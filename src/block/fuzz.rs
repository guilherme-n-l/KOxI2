//! `koxi block fuzz` — syzkaller campaigns (v1 `fuzz/fuzz`): per
//! driver, N sequential campaigns of H hours, each one syz-manager
//! run driving FUZZ_PARALLEL qemu VMs that boot the fuzz-flavor
//! kernel with the driver riding the overlay initrd (no 9p). The C
//! baseline is phase-1 screening — content-addressed and cached like
//! perf — and the Rust driver runs under the named campaign.
//!
//! The syz-manager config is a structured JSON merge, not a text
//! template: the `syzkaller/<driver>.cfg` (or generic) asset holds
//! user-tunable knobs, and koxi overlays the machine-owned fields
//! (paths, VM geometry, accel-aware qemu args) as real JSON values —
//! valid output by construction, and any syz-manager field is
//! user-overridable. Crash classification belongs to the stats
//! layer; this phase collects.

use std::fs::{self, File, OpenOptions};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use tracing::{info, warn};

use crate::assets;
use crate::block::cli::{FuzzOpts, Profile, RunOpts};
use crate::block::results::{self, ArtifactShas, Campaign, FuzzKnobs, Identity, Manifest};
use crate::block::Subject;
use crate::cli::GuestOpts;
use crate::config::{anchored, Driver, Project};
use crate::home;
use crate::host;
use crate::kernel::build::{Flavor, ARTIFACTS_DIR, BZIMAGE};
use crate::lock::{Lock, LOCK_PATH};
use crate::scratch::Scratch;
use crate::util;
use crate::virt::runner;

pub(crate) fn drive(
    run: &RunOpts,
    profile: Profile,
    guest: &GuestOpts,
    opts: &FuzzOpts,
    yes: bool,
    logs: &Path,
) -> anyhow::Result<()> {
    let project = Project::locate()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    let fuzz_dir = Flavor::Fuzz.dir(&artifacts);
    let kernel = fuzz_dir.join(BZIMAGE);
    let base_initrd = anchored(&project.root, &guest.initrd);
    let syz_root = opts.syz_root.as_deref().map_or_else(
        || artifacts.join("syzkaller"),
        |path| anchored(&project.root, path),
    );
    let syz_manager = opts.syz_manager.as_deref().map_or_else(
        || syz_root.join("bin/syz-manager"),
        |path| anchored(&project.root, path),
    );
    let ssh_key = artifacts.join("keys/id_ed25519");
    for input in [&kernel, &base_initrd, &syz_manager, &ssh_key] {
        if !input.is_file() {
            bail!("{} missing — run `koxi block setup` first", input.display());
        }
    }
    let vmlinux = fuzz_dir.join("vmlinux");
    if !vmlinux.is_file() {
        bail!(
            "{} missing — vmlinux must be in [build].extra-artifacts; re-run `koxi block setup`",
            vmlinux.display()
        );
    }
    let lock = Lock::load(&project.root.join(LOCK_PATH))?
        .ok_or_else(|| anyhow!("no koxi.lock — run `koxi block setup` first"))?;
    let kconfig_sha =
        lock.artifacts.get("fuzz/config").cloned().ok_or_else(|| {
            anyhow!("fuzz kernel config not locked — run `koxi block setup` first")
        })?;

    // syz-manager drives --fuzz-parallel guests at once, all of them
    // this size.
    super::check_host(profile, &guest.memory, guest.smp, opts.parallel)?;

    let knobs = FuzzKnobs {
        campaigns: opts.campaigns,
        hours: opts.hours,
        parallel: opts.parallel,
    };
    if knobs.campaigns == 0 || knobs.hours <= 0.0 || knobs.parallel == 0 {
        bail!("empty fuzz plan (check --fuzz-campaigns/--fuzz-hours/--fuzz-parallel)");
    }
    let subjects = super::subjects(&project.config, &run.scope.only);
    if subjects.is_empty() {
        bail!("no matching C drivers in the [block.drivers] registry");
    }

    let accel = host::accel();
    let ids = Ids {
        host: runner::hostname(),
        accel,
        kernel_sha: util::sha256_file(&kernel)?,
        initrd_sha: util::sha256_file(&base_initrd)?,
        syz_sha: util::sha256_file(&syz_manager)?,
        kconfig_sha,
        fuzz_dir: &fuzz_dir,
        smp: guest.smp,
        memory: &guest.memory,
        knobs: &knobs,
    };
    let shared = SharedCfg {
        project: &project,
        guest,
        logs,
        kernel: &kernel,
        base_initrd: &base_initrd,
        fuzz_dir: &fuzz_dir,
        syz_root: &syz_root,
        syz_manager: &syz_manager,
        syz_cfg: opts.syz_cfg.as_deref(),
        syz_http_port: opts.syz_http_port,
        ssh_key: &ssh_key,
        qemu_args: if accel == "kvm" { "-enable-kvm" } else { "" },
        knobs: &knobs,
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

    for subject in subjects {
        fuzz_subject(&shared, &ids, &plan, &subject)?;
    }
    Ok(())
}

/// What makes this run's campaigns comparable: substrate tags plus
/// the artifact hashes every driver of the run shares.
struct Ids<'a> {
    host: String,
    accel: &'static str,
    kernel_sha: String,
    initrd_sha: String,
    syz_sha: String,
    kconfig_sha: String,
    fuzz_dir: &'a Path,
    smp: u32,
    memory: &'a str,
    knobs: &'a FuzzKnobs,
}

impl Ids<'_> {
    fn identity(&self, name: &str, driver: &Driver, base: &BaseCfg) -> anyhow::Result<Identity> {
        Ok(Identity {
            domain: "fuzz".to_owned(),
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
                module: util::sha256_file(&self.fuzz_dir.join(&driver.ko))?,
                kconfig: self.kconfig_sha.clone(),
                syzkaller: Some(self.syz_sha.clone()),
                syz_template: Some(base.sha256.clone()),
            }),
            source: None,
            fio: None,
            fuzz: Some(self.knobs.clone()),
            static_: None,
        })
    }
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

/// One pair: the C baseline (fuzz is a phase-1 screening domain, so
/// it runs even under --p1) then the Rust driver under the campaign.
/// One subject's campaigns: the C baseline always, since phase 1
/// stands alone, and the Rust counterpart only when one is
/// registered and this is not a `--p1` run.
fn fuzz_subject(
    shared: &SharedCfg,
    ids: &Ids,
    plan: &Plan,
    subject: &Subject,
) -> anyhow::Result<()> {
    let manifest = |identity: Identity, p2: Option<Campaign>| Manifest {
        complete: false,
        created: plan.now,
        seed: plan.now,
        koxi: env!("CARGO_PKG_VERSION").to_owned(),
        identity,
        p2,
    };

    let c_cfg = base_cfg(shared, subject.c_name)?;
    let c_identity = ids.identity(subject.c_name, subject.c, &c_cfg)?;
    let c_hash = results::identity_hash(&c_identity)?;
    let p1_dir = results::p1_dir(&plan.results_root, subject.c_name, "fuzz", &c_hash);
    if !plan.force_p1 && Manifest::is_complete(&p1_dir) {
        info!(
            "p1 fuzz cached for {} at {} (--force-p1 re-runs)",
            subject.c_name,
            p1_dir.display()
        );
    } else {
        info!("p1 fuzz: {} -> {}", subject.c_name, p1_dir.display());
        run_campaigns(
            shared,
            subject.c_name,
            subject.c,
            &p1_dir,
            manifest(c_identity, None),
            &c_cfg,
        )?;
    }

    let Some(pair) = subject.pair() else {
        info!(
            "{} has no registered Rust counterpart; stopping at phase 1",
            subject.c_name
        );
        return Ok(());
    };
    if plan.p1 {
        info!(
            "phase 1 only: skipping p2 fuzz for {}::{}",
            pair.c_name, pair.rs_name
        );
        return Ok(());
    }
    let rs_cfg = base_cfg(shared, pair.rs_name)?;
    let p2_dir = results::p2_dir(
        &plan.results_root,
        pair.c_name,
        pair.rs_name,
        &plan.campaign,
        "fuzz",
    );
    let rs_manifest = manifest(
        ids.identity(pair.rs_name, pair.rs, &rs_cfg)?,
        Some(Campaign {
            campaign: plan.campaign.clone(),
            c_driver: pair.c_name.to_owned(),
            rs_driver: pair.rs_name.to_owned(),
            baseline: c_hash,
        }),
    );
    if !results::clear_for_campaign(&p2_dir, &rs_manifest, plan.yes)? {
        info!("p2 fuzz skipped for {}::{}", pair.c_name, pair.rs_name);
        return Ok(());
    }
    info!(
        "p2 fuzz: {}::{} -> {}",
        pair.c_name,
        pair.rs_name,
        p2_dir.display()
    );
    run_campaigns(shared, pair.rs_name, pair.rs, &p2_dir, rs_manifest, &rs_cfg)
}

/// The user-tunable base config: --syz-cfg wins, then the per-driver
/// asset (`syzkaller/<driver>.cfg`), then the generic one.
struct BaseCfg {
    contents: String,
    sha256: String,
}

fn base_cfg(shared: &SharedCfg, driver: &str) -> anyhow::Result<BaseCfg> {
    let contents = if let Some(path) = shared.syz_cfg {
        let path = anchored(&shared.project.root, path);
        fs::read_to_string(&path)
            .map_err(|err| anyhow!("reading --syz-cfg {}: {err}", path.display()))?
    } else {
        let custom = format!("syzkaller/{driver}.cfg");
        let project = shared.project;
        match assets::load(&project.root, &project.config, &custom) {
            Ok(contents) => {
                info!("using custom syzkaller config asset {custom}");
                contents.into_owned()
            }
            Err(assets::Error::Unknown(_)) => {
                assets::load(&project.root, &project.config, "syzkaller/generic.cfg")?.into_owned()
            }
            Err(err) => return Err(err.into()),
        }
    };
    let sha256 = util::sha256_bytes(contents.as_bytes());
    Ok(BaseCfg { contents, sha256 })
}

struct SharedCfg<'a> {
    project: &'a Project,
    guest: &'a GuestOpts,
    logs: &'a Path,
    kernel: &'a Path,
    base_initrd: &'a Path,
    fuzz_dir: &'a Path,
    syz_root: &'a Path,
    syz_manager: &'a Path,
    syz_cfg: Option<&'a Path>,
    syz_http_port: u16,
    ssh_key: &'a Path,
    qemu_args: &'a str,
    knobs: &'a FuzzKnobs,
}

/// Written when a campaign stops (v1 `.campaign_done`), holding the
/// seconds syz-manager actually ran. Its absence means the process
/// died mid-campaign, which is what separates "found nothing" from
/// "we do not know"; its contents are the exposure the crash rate is
/// divided by, which is not the budget whenever a campaign ends
/// early. v1 markers were empty, so a missing number falls back to
/// the manifest's nominal hours.
pub const CAMPAIGN_DONE: &str = ".campaign_done";

/// One driver's campaigns: the overlay initrd is staged once and
/// lives for the whole run; campaigns resume via per-campaign
/// markers (v1 .campaign_done).
fn run_campaigns(
    shared: &SharedCfg,
    name: &str,
    driver: &Driver,
    outdir: &Path,
    manifest: Manifest,
    base: &BaseCfg,
) -> anyhow::Result<()> {
    let mut manifest = match Manifest::load(outdir)? {
        Some(existing) if existing.identity == manifest.identity => existing,
        _ => {
            manifest.save(outdir)?;
            manifest
        }
    };

    let scratch = Scratch::new(&home::koxi_home()?, "fuzz-")?;
    let run_initrd = runner::driver_initrd(
        scratch.path(),
        shared.base_initrd,
        name,
        driver,
        shared.fuzz_dir,
        shared.project,
        shared.logs,
    )?;

    let mem = mem_mb(&shared.guest.memory)?;
    info!(
        "fuzzing {name}: {} campaigns x {}h, {} VMs each",
        shared.knobs.campaigns, shared.knobs.hours, shared.knobs.parallel
    );
    for index in 1..=shared.knobs.campaigns {
        let workdir = outdir.join("campaigns").join(format!("campaign_{index}"));
        let machine = |image: &Path, workdir: &Path| {
            serde_json::json!({
                "name": format!("{name}-security-benchmark"),
                "syzkaller": shared.syz_root.display().to_string(),
                "kernel_obj": shared.fuzz_dir.display().to_string(),
                "image": image.display().to_string(),
                "http": format!("127.0.0.1:{}", shared.syz_http_port),
                "workdir": workdir.display().to_string(),
                "type": "qemu",
                "vm": {
                    "count": shared.knobs.parallel,
                    "kernel": shared.kernel.display().to_string(),
                    "initrd": run_initrd.display().to_string(),
                    "cpu": shared.guest.smp,
                    "mem": mem,
                    "qemu_args": shared.qemu_args,
                },
                "sshkey": shared.ssh_key.display().to_string(),
            })
        };
        run_campaign(
            index,
            &workdir,
            scratch.path(),
            shared,
            &base.contents,
            machine,
        )?;
    }

    manifest.complete = true;
    manifest.save(outdir)?;
    info!("fuzz complete for {name} at {}", outdir.display());
    Ok(())
}

/// One syz-manager run under a wall-clock limit (timeout is the
/// expected outcome; early success and failure are both recorded and
/// the loop continues, v1-style).
fn run_campaign(
    index: u32,
    workdir: &Path,
    scratch: &Path,
    shared: &SharedCfg,
    base: &str,
    machine: impl Fn(&Path, &Path) -> serde_json::Value,
) -> anyhow::Result<()> {
    let done = workdir.join(CAMPAIGN_DONE);
    if done.is_file() {
        info!("campaign {index} already complete at {}", workdir.display());
        return Ok(());
    }
    if workdir.exists() {
        warn!("campaign {index}: wiping stale partial workdir");
        fs::remove_dir_all(workdir)?;
    }
    fs::create_dir_all(workdir)?;

    // Scratch disk syz-manager expects; sparse, recreated per
    // campaign, gone with the scratch dir.
    let image = scratch.join(format!("disk_{index}.img"));
    File::create(&image)?.set_len(128 * 1024 * 1024)?;

    let config = merged_config(base, machine(&image, workdir)).map_err(anyhow::Error::msg)?;
    let config_path = workdir.join("syz.cfg");
    fs::write(&config_path, config)?;

    let log_path = workdir.join("syz-manager.log");
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let seconds = (shared.knobs.hours * 3600.0).max(1.0) as u64;
    info!(
        "campaign {index}: {}h budget (log: {})",
        shared.knobs.hours,
        log_path.display()
    );
    let mut manager = Command::new(shared.syz_manager);
    manager
        .arg("-config")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .process_group(0);
    let mut child = manager.spawn()?;

    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    let exit = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        thread::sleep(Duration::from_secs(5));
    };
    match exit {
        None => {
            // The whole process group: syz-manager plus its qemus.
            let _ = Command::new("kill")
                .args(["-KILL", "--"])
                .arg(format!("-{}", child.id()))
                .status();
            let _ = child.wait();
            info!("campaign {index} reached its time limit");
        }
        Some(status) if status.success() => {
            info!("campaign {index} exited before the time limit");
        }
        Some(status) => {
            warn!("campaign {index} exited unexpectedly ({status}); continuing");
            fs::write(workdir.join(".failed_status"), format!("{status}\n"))?;
        }
    }
    let _ = fs::remove_file(&image);

    // The exposure this campaign actually bought. A manager that
    // exits early buys less than its budget, and dividing crashes by
    // the budget instead would understate the rate.
    let elapsed = started.elapsed().as_secs_f64();
    let crashes = crash_buckets(workdir);
    info!(
        "campaign {index}: {crashes} distinct crash buckets over {:.2}h",
        elapsed / 3600.0
    );
    fs::write(done, format!("{elapsed:.3}\n"))?;
    Ok(())
}

fn crash_buckets(workdir: &Path) -> usize {
    fs::read_dir(workdir.join("crashes")).map_or(0, |entries| {
        entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .count()
    })
}

/// Overlay the machine-owned fields onto the user's base config as
/// structured JSON — valid output by construction. Machine fields
/// win; the user is warned when one of theirs is displaced, and the
/// vm table is merged per-key so extra vm options survive.
fn merged_config(base: &str, machine: serde_json::Value) -> Result<String, String> {
    let mut config: serde_json::Value =
        serde_json::from_str(base).map_err(|err| format!("base syzkaller config: {err}"))?;
    let object = config
        .as_object_mut()
        .ok_or("base syzkaller config is not a JSON object")?;
    let serde_json::Value::Object(machine) = machine else {
        unreachable!("machine config is an object")
    };
    for (key, value) in machine {
        if key == "vm" {
            if let Some(user_vm) = object.get_mut("vm").and_then(|vm| vm.as_object_mut()) {
                let serde_json::Value::Object(vm) = value else {
                    unreachable!("vm config is an object")
                };
                for (vm_key, vm_value) in vm {
                    if user_vm.contains_key(&vm_key) {
                        warn!("syzkaller config: overriding machine-owned vm.{vm_key}");
                    }
                    user_vm.insert(vm_key, vm_value);
                }
            } else {
                object.insert(key, value);
            }
            continue;
        }
        if object.contains_key(&key) {
            warn!("syzkaller config: overriding machine-owned field {key}");
        }
        object.insert(key, value);
    }
    serde_json::to_string_pretty(&config).map_err(|err| err.to_string())
}

/// syz-manager's vm.mem is in MiB; the qemu-style spelling is
/// parsed once, by the same code the host-fitness gate uses.
fn mem_mb(memory: &str) -> anyhow::Result<u64> {
    host::parse_memory(memory)
        .map(|bytes| bytes >> 20)
        .ok_or_else(|| anyhow!("cannot parse --memory {memory} as a size"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_sizes_parse_to_mb() {
        assert_eq!(mem_mb("4G").unwrap(), 4096);
        assert_eq!(mem_mb("512M").unwrap(), 512);
        assert_eq!(mem_mb("2048").unwrap(), 2048);
        assert!(mem_mb("lots").is_err());
    }

    #[test]
    fn machine_fields_overlay_the_base_config() {
        let base = r#"{"procs": 16, "sandbox": "none", "workdir": "/user/tried", "vm": {"snapshot": false, "mem": 1}}"#;
        let machine = serde_json::json!({
            "workdir": "/machine/workdir",
            "type": "qemu",
            "vm": {"mem": 4096, "count": 4},
        });
        let merged: serde_json::Value =
            serde_json::from_str(&merged_config(base, machine).unwrap()).unwrap();
        assert_eq!(merged["procs"], 16, "user knob survives");
        assert_eq!(merged["workdir"], "/machine/workdir", "machine field wins");
        assert_eq!(merged["type"], "qemu");
        assert_eq!(merged["vm"]["snapshot"], false, "extra vm option survives");
        assert_eq!(merged["vm"]["mem"], 4096, "machine vm field wins");
        assert_eq!(merged["vm"]["count"], 4);

        assert!(merged_config("not json", serde_json::json!({})).is_err());
    }

    #[test]
    fn embedded_base_config_merges_cleanly() {
        let base = crate::assets::ASSETS
            .iter()
            .find(|asset| asset.name == "syzkaller/generic.cfg")
            .expect("generic syzkaller config is embedded");
        let machine = serde_json::json!({
            "name": "x", "syzkaller": "/s", "kernel_obj": "/k", "image": "/i",
            "http": "127.0.0.1:0", "workdir": "/w", "type": "qemu",
            "vm": {"count": 1, "kernel": "/b", "initrd": "/r", "cpu": 4, "mem": 4096, "qemu_args": ""},
            "sshkey": "/key",
        });
        let merged: serde_json::Value =
            serde_json::from_str(&merged_config(base.contents, machine).unwrap()).unwrap();
        for key in [
            "name",
            "syzkaller",
            "kernel_obj",
            "image",
            "http",
            "workdir",
            "sshkey",
        ] {
            assert!(merged.get(key).is_some(), "missing {key}");
        }
        assert_eq!(merged["cover"], true, "asset knob preserved");
        assert_eq!(merged["vm"]["count"], 1);
    }
}
