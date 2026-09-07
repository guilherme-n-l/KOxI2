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

use anyhow::{anyhow, bail};
use tracing::{info, warn};

use crate::block::cli::{RunOpts, StaticOpts};
use crate::block::results::{self, Campaign, Identity, Manifest, SourceIds, StaticKnobs};
use crate::block::DriverPair;
use crate::config::{anchored, Driver, Project, Role};
use crate::fetch::Ctx;
use crate::home::{self, CacheLock};
use crate::lock::{Lock, LockedSource, LOCK_PATH};
use crate::util;
use crate::virt::runner;
use crate::{assets, kernel};

/// Bumped when the AST queries or LOC/mining logic change, so stale
/// analyses never hash-match the new recipe.
const AST_RECIPE: u32 = 1;

pub(crate) fn drive(
    run: &RunOpts,
    opts: &StaticOpts,
    yes: bool,
    logs: &Path,
) -> anyhow::Result<()> {
    let project = Project::locate()?;
    let home = home::koxi_home()?;
    let lock_path = project.root.join(LOCK_PATH);
    let mut lock = Lock::load(&lock_path)?.unwrap_or_default();

    // Sources first (fetch/verify through the shared machinery); the
    // lock is saved even on failure so resolved pins stick.
    let fetched = {
        let _cache_lock = CacheLock::acquire(&home)?;
        let mut ctx = Ctx {
            config: &project.config,
            root: &project.root,
            home: &home,
            lock: &mut lock,
            logs,
            assume_yes: yes,
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
        bail!("linux source is not locked — run `koxi block setup` first");
    };
    let Some(LockedSource::GitMeta {
        commit: meta_commit,
        ..
    }) = lock.sources.get("linux-meta")
    else {
        bail!("linux-meta mirror is not locked — run `koxi block setup` first");
    };

    let pairs = super::driver_pairs(&project.config, &run.scope.only);
    if pairs.is_empty() {
        bail!("no matching driver pairs in the [block.drivers] registry");
    }

    let analyzer = ast::Analyzer::new()?;
    let analysis = Run {
        ktree: &ktree,
        mirror: &mirror,
        rules: &rules,
        analyzer: &analyzer,
        since: project.config.block.static_.since.clone(),
        meta_commit: meta_commit.clone(),
        host: runner::hostname(),
        source: SourceIds {
            linux: linux_sha.clone(),
            meta_commit: meta_commit.clone(),
            classify: classify.sha256.clone(),
        },
        validated_cwe: opts
            .validated_cwe
            .as_deref()
            .map(|path| anchored(&project.root, path)),
    };
    let now = util::unix_now();
    let plan = Plan {
        results_root: anchored(&project.root, &run.scope.output),
        campaign: run.campaign(now),
        now,
        p1: run.p1,
        force_p1: run.force_p1,
        yes,
    };

    for pair in pairs {
        analysis.pair(&plan, &pair)?;
    }
    Ok(())
}

/// Where this run writes and under what name.
struct Plan {
    results_root: PathBuf,
    campaign: String,
    now: u64,
    p1: bool,
    force_p1: bool,
    yes: bool,
}

struct Run<'a> {
    ktree: &'a Path,
    mirror: &'a Path,
    rules: &'a commits::Rules,
    analyzer: &'a ast::Analyzer,
    since: Option<String>,
    meta_commit: String,
    host: String,
    source: SourceIds,
    validated_cwe: Option<PathBuf>,
}

impl Run<'_> {
    /// The static domain has no VM and no artifacts: what makes two
    /// analyses comparable is the source pins, the classify rules,
    /// and the scope (driver paths + abstraction layer + window).
    fn identity(&self, name: &str, driver: &Driver) -> Identity {
        Identity {
            domain: "static".to_owned(),
            driver: name.to_owned(),
            spec: runner::driver_spec(name, driver),
            prep: driver.prep.clone().unwrap_or_default(),
            host: self.host.clone(),
            accel: None,
            smp: None,
            memory: None,
            artifacts: None,
            source: Some(self.source.clone()),
            fio: None,
            fuzz: None,
            static_: Some(StaticKnobs {
                gitpath: driver.gitpath.display().to_string(),
                abstractions: driver
                    .abstractions
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                since: self.since.clone().unwrap_or_default(),
                ast_recipe: AST_RECIPE,
            }),
        }
    }

    /// One pair: the C baseline (static is phase-1 screening, so it
    /// runs even under --p1) then the Rust driver under the campaign.
    fn pair(&self, plan: &Plan, pair: &DriverPair) -> anyhow::Result<()> {
        let manifest = |identity: Identity, p2: Option<Campaign>| Manifest {
            complete: false,
            created: plan.now,
            seed: plan.now,
            koxi: env!("CARGO_PKG_VERSION").to_owned(),
            identity,
            p2,
        };

        let c_identity = self.identity(pair.c_name, pair.c);
        let c_hash = results::identity_hash(&c_identity)?;
        let p1_dir = results::p1_dir(&plan.results_root, pair.c_name, "static", &c_hash);
        if !plan.force_p1 && Manifest::is_complete(&p1_dir) {
            info!(
                "p1 static cached for {} at {} (--force-p1 re-runs)",
                pair.c_name,
                p1_dir.display()
            );
        } else {
            info!("p1 static: {} -> {}", pair.c_name, p1_dir.display());
            self.analyze(pair.c_name, pair.c, &p1_dir, manifest(c_identity, None))?;
        }

        if plan.p1 {
            info!(
                "phase 1 only: skipping p2 static for {}::{}",
                pair.c_name, pair.rs_name
            );
            return Ok(());
        }
        let p2_dir = results::p2_dir(
            &plan.results_root,
            pair.c_name,
            pair.rs_name,
            &plan.campaign,
            "static",
        );
        let rs_manifest = manifest(
            self.identity(pair.rs_name, pair.rs),
            Some(Campaign {
                campaign: plan.campaign.clone(),
                c_driver: pair.c_name.to_owned(),
                rs_driver: pair.rs_name.to_owned(),
                baseline: c_hash,
            }),
        );
        if !results::clear_for_campaign(&p2_dir, &rs_manifest, plan.yes)? {
            info!("p2 static skipped for {}::{}", pair.c_name, pair.rs_name);
            return Ok(());
        }
        info!(
            "p2 static: {}::{} -> {}",
            pair.c_name,
            pair.rs_name,
            p2_dir.display()
        );
        self.analyze(pair.rs_name, pair.rs, &p2_dir, rs_manifest)
    }

    /// One driver's full static profile: AST metrics over its tree
    /// paths (+ abstraction layer for Rust) and classified history.
    fn analyze(
        &self,
        name: &str,
        driver: &Driver,
        outdir: &Path,
        mut manifest: Manifest,
    ) -> anyhow::Result<()> {
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
            bail!("no sources found under {}", src.display());
        }
        write_ast_csvs(outdir, &results)?;

        let mut rows = commits::mine(
            self.mirror,
            &self.meta_commit,
            self.since.as_deref(),
            &driver.gitpath,
            name,
            self.rules,
        )?;
        if let Some(csv) = &self.validated_cwe {
            let contents = fs::read_to_string(csv)
                .map_err(|err| anyhow!("reading --validated-cwe {}: {err}", csv.display()))?;
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
    // An explicitly registered file is analyzed whatever its
    // extension; a directory is walked for the ones that match.
    if src.is_file() {
        return Ok(vec![src.to_owned()]);
    }
    util::files_under(src, |path| {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext))
    })
}

fn write_ast_csvs(outdir: &Path, results: &ast::Results) -> Result<(), std::io::Error> {
    use std::fmt::Write as _;

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
        let _ = writeln!(
            functions,
            "{},{},{},{},{},{},{}",
            quote(&func.driver),
            quote(&func.file),
            quote(&func.name),
            func.start_line,
            func.end_line,
            func.line_count,
            func.complexity
        );
    }
    fs::write(outdir.join("functions.csv"), functions)?;

    let mut sites = String::from("source,file,line,end_line,node_type,contents_preview,purpose\n");
    for site in &results.sites {
        let _ = writeln!(
            sites,
            "{},{},{},{},{},{},{}",
            site.source,
            quote(&site.file),
            site.line,
            site.end_line,
            site.node_type,
            quote(&site.preview),
            site.purpose
        );
    }
    fs::write(outdir.join("unsafe_sites.csv"), sites)?;

    let mut densities = String::from(
        "driver,file,language,total_functions,unsafe_blocks,unsafe_fns,unsafe_impls,\
         ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\n",
    );
    for d in &results.densities {
        let _ = writeln!(
            densities,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
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
        );
    }
    fs::write(outdir.join("unsafe_density.csv"), densities)?;

    let mut loc = String::from("driver,file,language,blank,comment,code\n");
    for entry in &results.loc {
        let _ = writeln!(
            loc,
            "{},{},{},{},{},{}",
            quote(&entry.driver),
            quote(&entry.file),
            entry.language,
            entry.blank,
            entry.comment,
            entry.code
        );
    }
    fs::write(outdir.join("loc.csv"), loc)?;
    Ok(())
}
