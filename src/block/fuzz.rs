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
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::{error, info, warn};

use crate::block::cli::Opts;
use crate::block::results::{self, ArtifactShas, Campaign, FuzzKnobs, Identity, Manifest};
use crate::config::{anchored, Driver, Project};
use crate::kernel::build::{Flavor, ARTIFACTS_DIR, BZIMAGE};
use crate::lock::{Lock, LOCK_PATH};
use crate::virt::runner;
use crate::{assets, fetch};

pub fn fuzz(opts: &Opts, logs: &Path) -> ExitCode {
    match drive(opts, logs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("koxi block fuzz: {err}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn drive(opts: &Opts, logs: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let project = Project::locate()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    let fuzz_dir = Flavor::Fuzz.dir(&artifacts);
    let kernel = fuzz_dir.join(BZIMAGE);
    let base_initrd = anchored(&project.root, &opts.initrd);
    let syz_root = opts
        .syz_root
        .as_deref()
        .map(|path| anchored(&project.root, path))
        .unwrap_or_else(|| artifacts.join("syzkaller"));
    let syz_manager = opts
        .syz_manager
        .as_deref()
        .map(|path| anchored(&project.root, path))
        .unwrap_or_else(|| syz_root.join("bin/syz-manager"));
    let ssh_key = artifacts.join("keys/id_ed25519");
    for input in [&kernel, &base_initrd, &syz_manager, &ssh_key] {
        if !input.is_file() {
            return Err(
                format!("{} missing — run `koxi block setup` first", input.display()).into(),
            );
        }
    }
    let vmlinux = fuzz_dir.join("vmlinux");
    if !vmlinux.is_file() {
        return Err(format!(
            "{} missing — vmlinux must be in [build].extra-artifacts; re-run `koxi block setup`",
            vmlinux.display()
        )
        .into());
    }
    let lock = Lock::load(&project.root.join(LOCK_PATH))?
        .ok_or("no koxi.lock — run `koxi block setup` first")?;
    let kconfig_sha = lock
        .artifacts
        .get("fuzz/config")
        .cloned()
        .ok_or("fuzz kernel config not locked — run `koxi block setup` first")?;

    let results_root = anchored(&project.root, &opts.output);
    let host = runner::hostname();
    let accel = runner::accel();
    if accel == "tcg" {
        warn!("no KVM on this host — TCG fuzzing is smoke-only and finds very little");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let campaign = opts.campaign.clone().unwrap_or_else(|| now.to_string());

    let kernel_sha = fetch::sha256(&kernel, logs)?;
    let initrd_sha = fetch::sha256(&base_initrd, logs)?;
    let syz_sha = fetch::sha256(&syz_manager, logs)?;
    let knobs = FuzzKnobs {
        campaigns: opts.fuzz_campaigns,
        hours: opts.fuzz_hours,
        parallel: opts.fuzz_parallel,
    };
    if knobs.campaigns == 0 || knobs.hours <= 0.0 || knobs.parallel == 0 {
        return Err("empty fuzz plan (check --fuzz-campaigns/--fuzz-hours/--fuzz-parallel)".into());
    }

    let pairs = super::driver_pairs(&project.config, &opts.only);
    if pairs.is_empty() {
        return Err("no matching driver pairs in the [block.drivers] registry".into());
    }

    for (rs_name, rs_driver, c_name, c_driver) in pairs {
        let identity = |name: &str,
                        driver: &Driver,
                        base_cfg: &BaseCfg|
         -> Result<Identity, Box<dyn std::error::Error>> {
            Ok(Identity {
                domain: "fuzz".to_owned(),
                driver: name.to_owned(),
                spec: runner::driver_spec(name, driver),
                prep: driver.prep.clone().unwrap_or_default(),
                host: host.clone(),
                accel: Some(accel.to_owned()),
                smp: Some(opts.smp),
                memory: Some(opts.memory.clone()),
                artifacts: Some(ArtifactShas {
                    kernel: kernel_sha.clone(),
                    initrd: initrd_sha.clone(),
                    module: fetch::sha256(&fuzz_dir.join(&driver.ko), logs)?,
                    kconfig: kconfig_sha.clone(),
                    syzkaller: Some(syz_sha.clone()),
                    syz_template: Some(base_cfg.sha256.clone()),
                }),
                source: None,
                fio: None,
                fuzz: Some(knobs.clone()),
                static_: None,
            })
        };
        let shared = SharedCfg {
            project: &project,
            opts,
            logs,
            kernel: &kernel,
            base_initrd: &base_initrd,
            fuzz_dir: &fuzz_dir,
            syz_root: &syz_root,
            syz_manager: &syz_manager,
            ssh_key: &ssh_key,
            qemu_args: if accel == "kvm" { "-enable-kvm" } else { "" },
            knobs: &knobs,
        };

        // p1: the C baseline — fuzz is a phase-1 screening domain, so
        // it runs even under --p1 (unlike perf).
        let c_cfg = base_cfg(&project, opts, c_name)?;
        let c_identity = identity(c_name, c_driver, &c_cfg)?;
        let c_hash = results::identity_hash(&c_identity)?;
        let p1_dir = results::p1_dir(&results_root, c_name, "fuzz", &c_hash);
        if !(opts.force_p1 || opts.force_build) && Manifest::is_complete(&p1_dir) {
            info!(
                "p1 fuzz cached for {c_name} at {} (--force-p1 re-runs)",
                p1_dir.display()
            );
        } else {
            info!("p1 fuzz: {c_name} -> {}", p1_dir.display());
            let manifest = Manifest {
                complete: false,
                created: now,
                seed: now,
                koxi: env!("CARGO_PKG_VERSION").to_owned(),
                identity: c_identity,
                p2: None,
            };
            run_campaigns(&shared, c_name, c_driver, &p1_dir, manifest, &c_cfg)?;
        }

        if opts.p1 {
            info!("phase 1 only: skipping p2 fuzz for {c_name}::{rs_name}");
            continue;
        }
        let rs_cfg = base_cfg(&project, opts, rs_name)?;
        let rs_identity = identity(rs_name, rs_driver, &rs_cfg)?;
        let p2_dir = results::p2_dir(&results_root, c_name, rs_name, &campaign, "fuzz");
        let manifest = Manifest {
            complete: false,
            created: now,
            seed: now,
            koxi: env!("CARGO_PKG_VERSION").to_owned(),
            identity: rs_identity,
            p2: Some(Campaign {
                campaign: campaign.clone(),
                c_driver: c_name.clone(),
                rs_driver: rs_name.clone(),
                baseline: c_hash,
            }),
        };
        if !results::clear_for_campaign(&p2_dir, &manifest, opts.yes)? {
            info!("p2 fuzz skipped for {c_name}::{rs_name}");
            continue;
        }
        info!("p2 fuzz: {c_name}::{rs_name} -> {}", p2_dir.display());
        run_campaigns(&shared, rs_name, rs_driver, &p2_dir, manifest, &rs_cfg)?;
    }
    Ok(())
}

/// The user-tunable base config: --syz-cfg wins, then the per-driver
/// asset (`syzkaller/<driver>.cfg`), then the generic one.
struct BaseCfg {
    contents: String,
    sha256: String,
}

fn base_cfg(
    project: &Project,
    opts: &Opts,
    driver: &str,
) -> Result<BaseCfg, Box<dyn std::error::Error>> {
    let contents = match &opts.syz_cfg {
        Some(path) => {
            let path = anchored(&project.root, path);
            fs::read_to_string(&path)
                .map_err(|err| format!("reading --syz-cfg {}: {err}", path.display()))?
        }
        None => {
            let custom = format!("syzkaller/{driver}.cfg");
            match assets::load(&project.root, &project.config, &custom) {
                Ok(contents) => {
                    info!("using custom syzkaller config asset {custom}");
                    contents.into_owned()
                }
                Err(assets::Error::Unknown(_)) => {
                    assets::load(&project.root, &project.config, "syzkaller/generic.cfg")?
                        .into_owned()
                }
                Err(err) => return Err(err.into()),
            }
        }
    };
    let sha256 = assets::sha256_text(&contents)?;
    Ok(BaseCfg { contents, sha256 })
}

struct SharedCfg<'a> {
    project: &'a Project,
    opts: &'a Opts,
    logs: &'a Path,
    kernel: &'a Path,
    base_initrd: &'a Path,
    fuzz_dir: &'a Path,
    syz_root: &'a Path,
    syz_manager: &'a Path,
    ssh_key: &'a Path,
    qemu_args: &'a str,
    knobs: &'a FuzzKnobs,
}

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
) -> Result<(), Box<dyn std::error::Error>> {
    let mut manifest = match Manifest::load(outdir)? {
        Some(existing) if existing.identity == manifest.identity => existing,
        _ => {
            manifest.save(outdir)?;
            manifest
        }
    };

    let tmp_root = fetch::koxi_home()?.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix("fuzz-")
        .tempdir_in(&tmp_root)?;
    let run_initrd = runner::driver_initrd(
        scratch.path(),
        shared.base_initrd,
        name,
        driver,
        shared.fuzz_dir,
        shared.project,
        shared.logs,
    )?;

    let mem = mem_mb(&shared.opts.memory)?;
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
                "http": format!("127.0.0.1:{}", shared.opts.syz_http_port),
                "workdir": workdir.display().to_string(),
                "type": "qemu",
                "vm": {
                    "count": shared.knobs.parallel,
                    "kernel": shared.kernel.display().to_string(),
                    "initrd": run_initrd.display().to_string(),
                    "cpu": shared.opts.smp,
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
) -> Result<(), Box<dyn std::error::Error>> {
    let done = workdir.join(".campaign_done");
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

    let config = merged_config(base, machine(&image, workdir))?;
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

    let deadline = Instant::now() + Duration::from_secs(seconds);
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

    let crashes = crash_buckets(workdir);
    info!("campaign {index}: {crashes} distinct crash buckets");
    fs::write(done, "")?;
    Ok(())
}

fn crash_buckets(workdir: &Path) -> usize {
    fs::read_dir(workdir.join("crashes"))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_dir())
                .count()
        })
        .unwrap_or(0)
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
    let machine = match machine {
        serde_json::Value::Object(map) => map,
        _ => unreachable!("machine config is an object"),
    };
    for (key, value) in machine {
        if key == "vm" {
            if let Some(user_vm) = object.get_mut("vm").and_then(|vm| vm.as_object_mut()) {
                let vm = match value {
                    serde_json::Value::Object(map) => map,
                    _ => unreachable!("vm config is an object"),
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

/// "4G" -> 4096, "512M" -> 512, bare numbers are MB (syz-manager's
/// vm.mem unit).
fn mem_mb(memory: &str) -> Result<u64, String> {
    let trimmed = memory.trim();
    let (digits, unit) = match trimmed.chars().last() {
        Some('G') | Some('g') => (&trimmed[..trimmed.len() - 1], 1024),
        Some('M') | Some('m') => (&trimmed[..trimmed.len() - 1], 1),
        _ => (trimmed, 1),
    };
    digits
        .parse::<u64>()
        .map(|value| value * unit)
        .map_err(|_| format!("cannot parse --memory {memory} as a size"))
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
