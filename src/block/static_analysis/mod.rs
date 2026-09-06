//! `koxi block static` — the host-side static domain (v1 `static/`):
//! tree-sitter LOC + AST unsafe-surface metrics over the pinned
//! kernel tree, and commit mining over the locked linux-meta mirror.
//! No VM, no artifacts — the identity is the source pins, the
//! classify-rules asset, and the analysis scope, so results are
//! reproducible offline (v1 mined a moving GitHub HEAD with a
//! floating date window). The C driver is phase-1 screening; the
//! Rust driver (plus its declared abstraction layer, counted
//! separately so unsafe cannot hide one layer down) runs under the
//! named campaign.

pub mod ast;
pub mod commits;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{error, info, warn};

use crate::block::cli::Opts;
use crate::block::results::{self, Campaign, Identity, Manifest, SourceIds, StaticKnobs};
use crate::config::{anchored, Driver, Project, Role};
use crate::fetch::{self, Ctx};
use crate::lock::{Lock, LockedSource, LOCK_PATH};
use crate::virt::runner;
use crate::{assets, kernel};

/// Bumped when the AST queries or LOC/mining logic change, so stale
/// analyses never hash-match the new recipe.
const AST_RECIPE: u32 = 1;

pub fn static_phase(opts: &Opts, logs: &Path) -> ExitCode {
    match drive(opts, logs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("koxi block static: {err}");
            ExitCode::FAILURE
        }
    }
}

fn drive(opts: &Opts, logs: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let project = Project::locate()?;
    let home = fetch::koxi_home()?;
    let lock_path = project.root.join(LOCK_PATH);
    let mut lock = Lock::load(&lock_path)?.unwrap_or_default();

    // Sources first (fetch/verify through the shared machinery); the
    // lock is saved even on failure so resolved pins stick.
    let fetched = {
        let mut ctx = Ctx {
            config: &project.config,
            root: &project.root,
            home: &home,
            lock: &mut lock,
            logs,
            assume_yes: opts.yes,
        };
        kernel::setup::setup(&mut ctx)
            .and_then(|ktree| Ok((ktree, kernel::setup::history(&mut ctx)?)))
    };
    let classify = assets::load_locked(
        &project.root,
        &project.config,
        "static/classify.toml",
        &mut lock,
    );
    if let Err(err) = lock.save(&lock_path) {
        warn!("could not save {}: {err}", lock_path.display());
    }
    let (ktree, mirror) = fetched?;
    let classify = classify?;
    let rules = commits::Rules::parse(&classify.contents)?;

    let Some(LockedSource::Tarball {
        sha256: linux_sha, ..
    }) = lock.sources.get("linux")
    else {
        return Err("linux source is not locked — run `koxi block setup` first".into());
    };
    let Some(LockedSource::GitMeta {
        commit: meta_commit,
        ..
    }) = lock.sources.get("linux-meta")
    else {
        return Err("linux-meta mirror is not locked — run `koxi block setup` first".into());
    };
    let source = SourceIds {
        linux: linux_sha.clone(),
        meta_commit: meta_commit.clone(),
        classify: classify.sha256.clone(),
    };
    let since = project.config.block.static_.since.clone();

    let results_root = anchored(&project.root, &opts.output);
    let host = runner::hostname();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let campaign = opts.campaign.clone().unwrap_or_else(|| now.to_string());

    let pairs = super::driver_pairs(&project.config, &opts.only);
    if pairs.is_empty() {
        return Err("no matching driver pairs in the [block.drivers] registry".into());
    }

    let analyzer = ast::Analyzer::new()?;
    let identity = |name: &str, driver: &Driver| Identity {
        domain: "static".to_owned(),
        driver: name.to_owned(),
        spec: runner::driver_spec(name, driver),
        prep: driver.prep.clone().unwrap_or_default(),
        host: host.clone(),
        accel: None,
        smp: None,
        memory: None,
        artifacts: None,
        source: Some(source.clone()),
        fio: None,
        fuzz: None,
        static_: Some(StaticKnobs {
            gitpath: driver.gitpath.display().to_string(),
            abstractions: driver
                .abstractions
                .iter()
                .map(|path| path.display().to_string())
                .collect(),
            since: since.clone().unwrap_or_default(),
            ast_recipe: AST_RECIPE,
        }),
    };

    let run = Run {
        ktree: &ktree,
        mirror: &mirror,
        rules: &rules,
        analyzer: &analyzer,
        since: since.as_deref(),
        meta_commit: meta_commit.clone(),
        validated_cwe: opts
            .validated_cwe
            .as_deref()
            .map(|path| anchored(&project.root, path)),
    };

    for (rs_name, rs_driver, c_name, c_driver) in pairs {
        // p1: the C baseline — static is phase-1 screening, so it
        // runs even under --p1.
        let c_identity = identity(c_name, c_driver);
        let c_hash = results::identity_hash(&c_identity)?;
        let p1_dir = results::p1_dir(&results_root, c_name, "static", &c_hash);
        if !(opts.force_p1 || opts.force_build) && Manifest::is_complete(&p1_dir) {
            info!(
                "p1 static cached for {c_name} at {} (--force-p1 re-runs)",
                p1_dir.display()
            );
        } else {
            info!("p1 static: {c_name} -> {}", p1_dir.display());
            let manifest = Manifest {
                complete: false,
                created: now,
                seed: now,
                koxi: env!("CARGO_PKG_VERSION").to_owned(),
                identity: c_identity,
                p2: None,
            };
            run.analyze(c_name, c_driver, &p1_dir, manifest)?;
        }

        if opts.p1 {
            info!("phase 1 only: skipping p2 static for {c_name}::{rs_name}");
            continue;
        }
        let p2_dir = results::p2_dir(&results_root, c_name, rs_name, &campaign, "static");
        let manifest = Manifest {
            complete: false,
            created: now,
            seed: now,
            koxi: env!("CARGO_PKG_VERSION").to_owned(),
            identity: identity(rs_name, rs_driver),
            p2: Some(Campaign {
                campaign: campaign.clone(),
                c_driver: c_name.clone(),
                rs_driver: rs_name.clone(),
                baseline: c_hash,
            }),
        };
        if !results::clear_for_campaign(&p2_dir, &manifest, opts.yes)? {
            info!("p2 static skipped for {c_name}::{rs_name}");
            continue;
        }
        info!("p2 static: {c_name}::{rs_name} -> {}", p2_dir.display());
        run.analyze(rs_name, rs_driver, &p2_dir, manifest)?;
    }
    Ok(())
}

struct Run<'a> {
    ktree: &'a Path,
    mirror: &'a Path,
    rules: &'a commits::Rules,
    analyzer: &'a ast::Analyzer,
    since: Option<&'a str>,
    meta_commit: String,
    validated_cwe: Option<PathBuf>,
}

impl Run<'_> {
    /// One driver's full static profile: AST metrics over its tree
    /// paths (+ abstraction layer for Rust) and classified history.
    fn analyze(
        &self,
        name: &str,
        driver: &Driver,
        outdir: &Path,
        mut manifest: Manifest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(outdir)?;
        manifest.save(outdir)?;

        let mut results = ast::Results::default();
        let src = self.ktree.join(&driver.gitpath);
        match driver.role {
            Role::C => {
                for file in source_files(&src, &["c", "h"])? {
                    self.analyzer.analyze_c_file(&file, name, &mut results)?;
                }
            }
            Role::Rs => {
                for file in source_files(&src, &["rs"])? {
                    self.analyzer
                        .analyze_rs_file(&file, name, "driver", &mut results)?;
                }
                let abstraction_name = format!("{name}_abstractions");
                for path in &driver.abstractions {
                    for file in source_files(&self.ktree.join(path), &["rs"])? {
                        self.analyzer.analyze_rs_file(
                            &file,
                            &abstraction_name,
                            "abstraction",
                            &mut results,
                        )?;
                    }
                }
            }
        }
        if results.densities.is_empty() {
            return Err(format!("no sources found under {}", src.display()).into());
        }
        write_ast_csvs(outdir, &results)?;

        let mut rows = commits::mine(
            self.mirror,
            &self.meta_commit,
            self.since,
            &driver.gitpath,
            name,
            self.rules,
        )?;
        if let Some(csv) = &self.validated_cwe {
            let contents = fs::read_to_string(csv)
                .map_err(|err| format!("reading --validated-cwe {}: {err}", csv.display()))?;
            commits::apply_validated(&mut rows, &contents);
        }
        fs::write(outdir.join("commits.csv"), commits::commits_csv(&rows))?;
        fs::write(
            outdir.join("commits_summary.csv"),
            commits::summary_csv(&rows),
        )?;

        let safety = rows.iter().filter(|row| row.safety_related).count();
        let functions = results.functions.len();
        let loc: usize = results.loc.iter().map(|entry| entry.code).sum();
        let implicit: usize = results
            .densities
            .iter()
            .map(|d| d.ptr_derefs + d.alloc_calls + d.free_calls + d.memop_calls + d.cast_exprs)
            .sum();
        let unsafe_sites = results.sites.len();
        info!(
            "{name}: {functions} functions, {loc} LoC, {implicit} implicit unsafe ops, \
             {unsafe_sites} unsafe sites, {}/{} safety-signal commits",
            safety,
            rows.len()
        );

        manifest.complete = true;
        manifest.save(outdir)?;
        info!("static complete for {name} at {}", outdir.display());
        Ok(())
    }
}

/// Files with the given extensions under `src`, recursively (a file
/// path passes through), sorted for determinism. v1 globbed one
/// level deep, which silently skipped rust/kernel/block/mq/*.rs —
/// the abstraction files that actually hold the unsafe surface.
fn source_files(src: &Path, extensions: &[&str]) -> Result<Vec<PathBuf>, std::io::Error> {
    if src.is_file() {
        return Ok(vec![src.to_owned()]);
    }
    let mut files = Vec::new();
    let mut pending = vec![src.to_owned()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| extensions.contains(&ext))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

fn write_ast_csvs(outdir: &Path, results: &ast::Results) -> Result<(), std::io::Error> {
    let quote = |field: &str| {
        if field.contains(',') || field.contains('"') || field.contains('\n') {
            format!("\"{}\"", field.replace('"', "\"\""))
        } else {
            field.to_owned()
        }
    };

    let mut functions =
        String::from("driver,file,function_name,start_line,end_line,line_count,complexity\n");
    for func in &results.functions {
        functions.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            quote(&func.driver),
            quote(&func.file),
            quote(&func.name),
            func.start_line,
            func.end_line,
            func.line_count,
            func.complexity
        ));
    }
    fs::write(outdir.join("functions.csv"), functions)?;

    let mut sites = String::from("source,file,line,end_line,node_type,contents_preview,purpose\n");
    for site in &results.sites {
        sites.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            site.source,
            quote(&site.file),
            site.line,
            site.end_line,
            site.node_type,
            quote(&site.preview),
            site.purpose
        ));
    }
    fs::write(outdir.join("unsafe_sites.csv"), sites)?;

    let mut densities = String::from(
        "driver,file,language,total_functions,unsafe_blocks,unsafe_fns,unsafe_impls,\
         ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\n",
    );
    for d in &results.densities {
        densities.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}\n",
            quote(&d.driver),
            quote(&d.file),
            d.language,
            d.total_functions,
            d.unsafe_blocks,
            d.unsafe_fns,
            d.unsafe_impls,
            d.ptr_derefs,
            d.alloc_calls,
            d.free_calls,
            d.memop_calls,
            d.cast_exprs
        ));
    }
    fs::write(outdir.join("unsafe_density.csv"), densities)?;

    let mut loc = String::from("driver,file,language,blank,comment,code\n");
    for entry in &results.loc {
        loc.push_str(&format!(
            "{},{},{},{},{},{}\n",
            quote(&entry.driver),
            quote(&entry.file),
            entry.language,
            entry.blank,
            entry.comment,
            entry.code
        ));
    }
    fs::write(outdir.join("loc.csv"), loc)?;
    Ok(())
}
