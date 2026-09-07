//! `koxi block perf` — the fio benchmark matrix (v1 `perf/benchmark`
//! plus the run broker's p1/p2 orchestration), driven from the host
//! over the runner's ssh channel: one boot per driver, the shuffled
//! workload matrix inside, one annotated fio JSON per rep, results
//! returned over ssh (no 9p — the same transport works on bare
//! metal). Sequential by design: one VM, one fio at a time —
//! concurrent runs measure contention, not the driver (Mytkowicz et
//! al., ASPLOS 2009).

use std::fs;
use std::path::Path;

use anyhow::{anyhow, bail};
use tracing::{info, warn};

use crate::block::cli::{FioOpts, Profile, RunOpts};
use crate::block::results::{self, ArtifactShas, Campaign, FioKnobs, Identity, Manifest};
use crate::block::DriverPair;
use crate::cli::VmOpts;
use crate::config::{anchored, Driver, Project};
use crate::home;
use crate::host;
use crate::kernel::build::ARTIFACTS_DIR;
use crate::lock::{Lock, LOCK_PATH};
use crate::scratch::Scratch;
use crate::util;
use crate::virt::runner::{self, Vm};

pub(crate) fn drive(
    run: &RunOpts,
    profile: Profile,
    vm: &VmOpts,
    fio: &FioOpts,
    yes: bool,
    logs: &Path,
) -> anyhow::Result<()> {
    if run.p1 {
        info!("phase 1 only: perf is a phase-2 gate; skipping");
        return Ok(());
    }

    let project = Project::locate()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    let kernel = anchored(&project.root, &vm.kernel);
    let initrd = anchored(&project.root, &vm.guest.initrd);
    for input in [&kernel, &initrd] {
        if !input.is_file() {
            bail!("{} missing — run `koxi block setup` first", input.display());
        }
    }
    let lock = Lock::load(&project.root.join(LOCK_PATH))?
        .ok_or_else(|| anyhow!("no koxi.lock — run `koxi block setup` first"))?;
    let kconfig_sha = lock.artifacts.get("config").cloned().ok_or_else(|| {
        anyhow!("effective kernel config not locked — run `koxi block setup` first")
    })?;

    // One guest at a time: perf is sequential by design.
    super::check_host(profile, &vm.guest.memory, vm.guest.smp, 1)?;

    let knobs = FioKnobs {
        bs: fio.bs.clone(),
        rw: fio.rw.clone(),
        qd: fio.qd.clone(),
        size: fio.sz.clone(),
        reps: fio.reps,
        runtime: fio.runtime,
        engine: fio.engine.clone(),
    };
    if knobs.bs.is_empty() || knobs.rw.is_empty() || knobs.qd.is_empty() || knobs.size.is_empty() {
        bail!("empty fio matrix (check --fio-bs/--fio-rw/--fio-qd/--fio-sz)");
    }
    let pairs = super::driver_pairs(&project.config, &run.scope.only);
    if pairs.is_empty() {
        bail!("no matching driver pairs in the [block.drivers] registry");
    }

    let now = util::unix_now();
    let plan = Plan {
        results_root: anchored(&project.root, &run.scope.output),
        campaign: run.campaign(now),
        now,
        seed: fio.seed.unwrap_or(now),
        force_p1: run.force_p1,
        yes,
    };
    let ids = Ids {
        host: runner::hostname(),
        accel: host::accel(),
        kernel_sha: util::sha256_file(&kernel)?,
        initrd_sha: util::sha256_file(&initrd)?,
        kconfig_sha,
        module_dir: &artifacts,
        smp: vm.guest.smp,
        memory: &vm.guest.memory,
        fio: knobs,
    };
    let ctx = MatrixCtx {
        project: &project,
        vm,
        logs,
        kernel: &kernel,
        initrd: &initrd,
        module_dir: &artifacts,
    };

    for pair in pairs {
        measure_pair(&ctx, &ids, &plan, &pair)?;
    }
    Ok(())
}

/// What makes this run's numbers comparable: the substrate tags and
/// the artifact hashes every driver of the run shares.
struct Ids<'a> {
    host: String,
    accel: &'static str,
    kernel_sha: String,
    initrd_sha: String,
    kconfig_sha: String,
    module_dir: &'a Path,
    smp: u32,
    memory: &'a str,
    fio: FioKnobs,
}

impl Ids<'_> {
    fn identity(&self, name: &str, driver: &Driver) -> anyhow::Result<Identity> {
        Ok(Identity {
            domain: "perf".to_owned(),
            driver: name.to_owned(),
            spec: runner::driver_spec(name, driver),
            prep: driver.prep.clone().unwrap_or_default(),
            host: self.host.clone(),
            accel: Some(self.accel.to_owned()),
            smp: Some(self.smp),
            memory: Some(self.memory.to_owned()),
            artifacts: Some(ArtifactShas {
                kernel: self.kernel_sha.clone(),
                initrd: self.initrd_sha.clone(),
                module: util::sha256_file(&self.module_dir.join(&driver.ko))?,
                kconfig: self.kconfig_sha.clone(),
                syzkaller: None,
                syz_template: None,
            }),
            source: None,
            fio: Some(self.fio.clone()),
            fuzz: None,
            static_: None,
        })
    }
}

/// Where this run writes and under what name.
struct Plan {
    results_root: std::path::PathBuf,
    campaign: String,
    now: u64,
    seed: u64,
    force_p1: bool,
    yes: bool,
}

/// One pair: the cached C baseline, then the Rust driver under the
/// named campaign, its baseline recorded by hash (no symlinks —
/// results must survive rsync).
fn measure_pair(ctx: &MatrixCtx, ids: &Ids, plan: &Plan, pair: &DriverPair) -> anyhow::Result<()> {
    let manifest = |identity: Identity, p2: Option<Campaign>| Manifest {
        complete: false,
        created: plan.now,
        seed: plan.seed,
        koxi: env!("CARGO_PKG_VERSION").to_owned(),
        identity,
        p2,
    };

    let c_identity = ids.identity(pair.c_name, pair.c)?;
    let c_hash = results::identity_hash(&c_identity)?;
    let p1_dir = results::p1_dir(&plan.results_root, pair.c_name, "perf", &c_hash);
    if !plan.force_p1 && Manifest::is_complete(&p1_dir) {
        info!(
            "p1 perf cached for {} at {} (--force-p1 re-runs)",
            pair.c_name,
            p1_dir.display()
        );
    } else {
        info!("p1 perf: {} -> {}", pair.c_name, p1_dir.display());
        run_matrix(
            ctx,
            pair.c_name,
            pair.c,
            &p1_dir,
            manifest(c_identity, None),
        )?;
    }

    let p2_dir = results::p2_dir(
        &plan.results_root,
        pair.c_name,
        pair.rs_name,
        &plan.campaign,
        "perf",
    );
    let rs_manifest = manifest(
        ids.identity(pair.rs_name, pair.rs)?,
        Some(Campaign {
            campaign: plan.campaign.clone(),
            c_driver: pair.c_name.to_owned(),
            rs_driver: pair.rs_name.to_owned(),
            baseline: c_hash,
        }),
    );
    if !results::clear_for_campaign(&p2_dir, &rs_manifest, plan.yes)? {
        info!("p2 perf skipped for {}::{}", pair.c_name, pair.rs_name);
        return Ok(());
    }
    info!(
        "p2 perf: {}::{} -> {}",
        pair.c_name,
        pair.rs_name,
        p2_dir.display()
    );
    run_matrix(ctx, pair.rs_name, pair.rs, &p2_dir, rs_manifest)
}

struct MatrixCtx<'a> {
    project: &'a Project,
    vm: &'a VmOpts,
    logs: &'a Path,
    kernel: &'a Path,
    initrd: &'a Path,
    module_dir: &'a Path,
}

/// One driver's full matrix in one boot: resume-aware at rep
/// granularity, shuffled by the manifest's seed, every rep annotated
/// and written host-side, dmesg harvested at the end.
fn run_matrix(
    ctx: &MatrixCtx,
    name: &str,
    driver: &Driver,
    outdir: &Path,
    manifest: Manifest,
) -> anyhow::Result<()> {
    // An unfinished root resumes under its recorded seed so the
    // shuffled order stays the order that actually ran.
    let mut manifest = match Manifest::load(outdir)? {
        Some(existing) if existing.identity == manifest.identity => existing,
        _ => {
            manifest.save(outdir)?;
            manifest
        }
    };
    let seed = manifest.seed;
    let fio = manifest
        .identity
        .fio
        .clone()
        .ok_or_else(|| anyhow!("perf manifest lacks its [identity.fio] table"))?;
    let reps = fio.reps;
    let runtime = fio.runtime;

    let order = shuffled(matrix(&fio), seed);
    info!("workload seed: {seed} ({} workloads)", order.len());

    let rep_path = |workload: &Workload, rep: u32| {
        outdir
            .join(workload.dir_name())
            .join(format!("fio_{rep}.json"))
    };
    let missing = |workload: &Workload| (1..=reps).any(|rep| !rep_path(workload, rep).is_file());
    if !order.iter().any(missing) {
        info!("all reps present for {name}; marking complete");
        manifest.complete = true;
        manifest.save(outdir)?;
        return Ok(());
    }

    let scratch = Scratch::new(&home::koxi_home()?, "perf-")?;
    let run_initrd = runner::driver_initrd(
        scratch.path(),
        ctx.initrd,
        name,
        driver,
        ctx.module_dir,
        ctx.project,
        ctx.logs,
    )?;

    let mut vm = Vm::launch(
        &runner::Options {
            kernel: ctx.kernel.to_owned(),
            initrd: run_initrd,
            memory: ctx.vm.guest.memory.clone(),
            smp: ctx.vm.guest.smp,
            port: ctx.vm.port,
            key: ctx.project.root.join(ARTIFACTS_DIR).join("keys/id_ed25519"),
            append: String::new(),
        },
        ctx.logs,
    )?;
    vm.wait_ready(ctx.vm.vm_timeout)?;
    let device = driver.device.display().to_string();
    let check = vm.exec(&format!("test -e {device}"))?;
    if !check.status.success() {
        bail!("driver {name} setup ran but {device} is absent");
    }

    let mut failures = 0u32;
    for (index, workload) in order.iter().enumerate() {
        let config_dir = outdir.join(workload.dir_name());
        fs::create_dir_all(&config_dir)?;
        for rep in 1..=reps {
            let out = rep_path(workload, rep);
            if out.is_file() {
                continue;
            }
            let output = vm.exec(&workload.fio_command(&device, runtime, &fio.engine))?;
            let annotated = if output.status.success() {
                annotate(&output.stdout, rep == 1, index + 1, seed, name, rep)
            } else {
                Err(format!("fio exited with {}", output.status))
            };
            match annotated {
                Ok(json) => {
                    fs::write(&out, json)?;
                    info!("done: {name} {} rep={rep}", workload.label());
                }
                Err(err) => {
                    failures += 1;
                    let log = config_dir.join(format!("fio_{rep}.err.log"));
                    fs::write(
                        &log,
                        format!(
                            "{err}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        ),
                    )?;
                    warn!(
                        "failed: {name} {} rep={rep} ({err}; see {})",
                        workload.label(),
                        log.display()
                    );
                }
            }
        }
    }

    // The guest kernel log rides home before teardown; the host-side
    // console log (vm-console.log) already covers crashes.
    let dmesg = vm.exec("dmesg")?;
    fs::write(outdir.join("kernel.log"), &dmesg.stdout)?;
    vm.shutdown();

    if failures > 0 {
        bail!("{failures} fio runs failed for {name}; rerunning resumes the missing reps");
    }
    manifest.complete = true;
    manifest.save(outdir)?;
    info!("perf complete for {name} at {}", outdir.display());
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
struct Workload {
    bs: String,
    rw: String,
    qd: u32,
    size: String,
}

impl Workload {
    fn dir_name(&self) -> String {
        format!("{}_{}_{}_{}", self.bs, self.rw, self.qd, self.size)
    }

    fn label(&self) -> String {
        format!("{} {} qd={} sz={}", self.bs, self.rw, self.qd, self.size)
    }

    /// v1 perf/vm_init fio invocation plus an explicit ioengine —
    /// v1's implicit psync silently capped iodepth at 1.
    fn fio_command(&self, device: &str, runtime: u64, engine: &str) -> String {
        format!(
            "fio --name=bench --filename={device} --ioengine={engine} --bs={bs} \
             --iodepth={qd} --rw={rw} --size={size} --direct=1 --runtime={runtime} \
             --time_based --group_reporting=1 --output-format=json --allow_file_create=0",
            device = runner::shell_quote(device),
            engine = runner::shell_quote(engine),
            bs = runner::shell_quote(&self.bs),
            qd = self.qd,
            rw = runner::shell_quote(&self.rw),
            size = runner::shell_quote(&self.size),
        )
    }
}

/// The full nested matrix in declaration order (bs × rw × qd × size).
fn matrix(fio: &FioKnobs) -> Vec<Workload> {
    let mut workloads = Vec::new();
    for bs in &fio.bs {
        for rw in &fio.rw {
            for qd in &fio.qd {
                for size in &fio.size {
                    workloads.push(Workload {
                        bs: bs.clone(),
                        rw: rw.clone(),
                        qd: *qd,
                        size: size.clone(),
                    });
                }
            }
        }
    }
    workloads
}

/// Deterministic Fisher-Yates over a splitmix64 stream — the v1
/// `shuf --random-source=seed` role, reproducible from the manifest.
fn shuffled<T>(mut items: Vec<T>, seed: u64) -> Vec<T> {
    let mut state = seed;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    for i in (1..items.len()).rev() {
        let j = (next() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
    items
}

/// Inject run metadata into the fio JSON (v1 sed-appended
/// "nullb_metadata"; this is the structured version). fio prefixes
/// advisory notes to stdout (e.g. "queue depth will be capped at 1"
/// for sync engines) — they are preserved as evidence in the
/// metadata rather than breaking the parse.
fn annotate(
    stdout: &[u8],
    warmup: bool,
    run_order: usize,
    seed: u64,
    driver: &str,
    rep: u32,
) -> Result<String, String> {
    let text = String::from_utf8_lossy(stdout);
    let start = text
        .find('{')
        .ok_or_else(|| format!("fio produced no JSON: {}", text.trim()))?;
    let notes: Vec<String> = text[..start]
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    for note in &notes {
        warn!("fio: {note}");
    }
    let mut value: serde_json::Value = serde_json::from_str(&text[start..])
        .map_err(|err| format!("fio output is not JSON: {err}"))?;
    let object = value
        .as_object_mut()
        .ok_or("fio output is not a JSON object")?;
    object.insert(
        "koxi_metadata".to_owned(),
        serde_json::json!({
            "warmup": warmup,
            "run_order": run_order,
            "workload_seed": seed.to_string(),
            "driver": driver,
            "rep": rep,
            "fio_notes": notes,
        }),
    );
    serde_json::to_string_pretty(&value).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn knobs() -> FioKnobs {
        FioKnobs {
            bs: vec!["4k".to_owned(), "64k".to_owned()],
            rw: vec!["randread".to_owned()],
            qd: vec![1, 32],
            size: vec!["512M".to_owned()],
            reps: 3,
            runtime: 5,
            engine: "io_uring".to_owned(),
        }
    }

    #[test]
    fn matrix_covers_the_cross_product() {
        let workloads = matrix(&knobs());
        assert_eq!(workloads.len(), 4);
        assert_eq!(workloads[0].dir_name(), "4k_randread_1_512M");
        assert_eq!(workloads[3].dir_name(), "64k_randread_32_512M");
    }

    #[test]
    fn shuffle_is_deterministic_per_seed() {
        let base = matrix(&knobs());
        let a = shuffled(base.clone(), 7);
        let b = shuffled(base.clone(), 7);
        assert_eq!(a, b, "same seed, same order");
        let c = shuffled(base.clone(), 8);
        assert!(
            a != c || base.len() < 2,
            "different seed shuffles differently"
        );
        let mut sorted_a: Vec<String> = a.iter().map(Workload::dir_name).collect();
        sorted_a.sort();
        let mut sorted_base: Vec<String> = base.iter().map(Workload::dir_name).collect();
        sorted_base.sort();
        assert_eq!(sorted_a, sorted_base, "shuffle is a permutation");
    }

    #[test]
    fn annotate_injects_metadata() {
        let json = annotate(
            br#"{"fio version": "fio-3.41", "jobs": []}"#,
            true,
            2,
            42,
            "rnull",
            1,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let meta = &value["koxi_metadata"];
        assert_eq!(meta["warmup"], true);
        assert_eq!(meta["run_order"], 2);
        assert_eq!(meta["workload_seed"], "42");
        assert_eq!(meta["driver"], "rnull");
        assert_eq!(meta["rep"], 1);
        assert_eq!(value["fio version"], "fio-3.41");

        assert!(annotate(b"not json", false, 1, 1, "x", 2).is_err());
    }

    #[test]
    fn annotate_preserves_fio_notes_before_the_json() {
        let stdout = b"note: both iodepth >= 1 and synchronous I/O engine are selected, \
                       queue depth will be capped at 1\n{\"jobs\": []}";
        let json = annotate(stdout, false, 1, 7, "null_blk", 2).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let notes = value["koxi_metadata"]["fio_notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].as_str().unwrap().contains("capped at 1"));
    }

    #[test]
    fn fio_command_matches_v1_flags() {
        let workload = Workload {
            bs: "4k".to_owned(),
            rw: "randread".to_owned(),
            qd: 1,
            size: "512M".to_owned(),
        };
        let command = workload.fio_command("/dev/nullb0", 30, "io_uring");
        for flag in [
            "--name=bench",
            "--filename=/dev/nullb0",
            "--ioengine=io_uring",
            "--bs=4k",
            "--iodepth=1",
            "--rw=randread",
            "--size=512M",
            "--direct=1",
            "--runtime=30",
            "--time_based",
            "--group_reporting=1",
            "--output-format=json",
            "--allow_file_create=0",
        ] {
            assert!(command.contains(flag), "missing {flag} in {command}");
        }
    }
}
