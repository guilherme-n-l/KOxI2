//! `koxi block vm` — boot the built kernel + initramfs with an
//! optional registry driver loaded at init, then run a command or an
//! interactive shell in the guest. The dev-loop face of
//! `virt::runner`, and the end-to-end smoke for the overlay-initrd
//! driver transport the perf and fuzz phases reuse.

use std::fs;
use std::io::IsTerminal;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::ArgMatches;
use tracing::{error, info};

use crate::block::cli::Opts;
use crate::config::{Driver, Project, Role};
use crate::kernel::build::{Flavor, ARTIFACTS_DIR, BZIMAGE};
use crate::virt::runner;
use crate::{assets, fetch};

pub fn vm(opts: &Opts, sub: &ArgMatches, logs: &Path) -> ExitCode {
    match run(opts, sub, logs) {
        Ok(code) => code,
        Err(err) => {
            error!("koxi block vm: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(opts: &Opts, sub: &ArgMatches, logs: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let command: Vec<&String> = sub
        .get_many::<String>("cmd")
        .into_iter()
        .flatten()
        .collect();
    if command.is_empty() && !std::io::stdin().is_terminal() {
        return Err("no command given and stdin is not a terminal".into());
    }

    let project = Project::locate()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    // --fuzz flips the kernel default and the module source to the
    // fuzz flavor's namespace; an explicit --kernel still wins.
    let flavor = if sub.get_flag("fuzz") {
        Flavor::Fuzz
    } else {
        Flavor::Clean
    };
    let kernel = if flavor == Flavor::Fuzz
        && sub.value_source("kernel") == Some(clap::parser::ValueSource::DefaultValue)
    {
        flavor.dir(&artifacts).join(BZIMAGE)
    } else {
        anchored(&project.root, &opts.kernel)
    };
    let module_dir = flavor.dir(&artifacts);
    let base_initrd = anchored(&project.root, &opts.initrd);

    let driver = match sub.get_one::<String>("driver") {
        Some(name) => {
            let driver =
                project.config.block.drivers.get(name).ok_or_else(|| {
                    format!("driver {name} is not in the [block.drivers] registry")
                })?;
            Some((name.as_str(), driver))
        }
        None => None,
    };

    // Per-run scratch for the overlay and the concatenated initrd;
    // qemu is torn down before this drops.
    let tmp_root = fetch::koxi_home()?.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix("vm-")
        .tempdir_in(&tmp_root)?;

    let initrd = match driver {
        Some((name, driver)) => {
            let staging = scratch.path().join("overlay");
            stage_overlay(&staging, name, driver, &module_dir, &project)?;
            let initrd = scratch.path().join("initrd.cpio.gz");
            runner::overlay_initrd(&base_initrd, &staging, &initrd, logs)?;
            initrd
        }
        None => base_initrd,
    };

    let mut vm = runner::Vm::launch(
        &runner::Options {
            kernel,
            initrd,
            memory: opts.memory.clone(),
            smp: opts.smp,
            port: opts.port,
            key: artifacts.join("keys/id_ed25519"),
            append: String::new(),
        },
        logs,
    )?;
    vm.wait_ready(opts.vm_timeout)?;
    info!("guest is up (root@localhost:{})", opts.port);

    if let Some((name, driver)) = driver {
        // Init powers off on setup failure, so a reachable guest means
        // the script ran; the device node is the observable contract.
        let check = vm.exec(&format!("test -e {}", driver.device.display()))?;
        if !check.status.success() {
            return Err(format!(
                "driver {name} setup ran but {} is absent",
                driver.device.display()
            )
            .into());
        }
        info!("driver {name} is up ({} present)", driver.device.display());
    }

    let status = if command.is_empty() {
        vm.shell()?
    } else {
        let joined = command
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ");
        vm.run(&joined)?
    };
    vm.shutdown();
    Ok(match status.code() {
        Some(code) => ExitCode::from(code.clamp(0, 255) as u8),
        None => ExitCode::FAILURE,
    })
}

/// Resolve the CLI's relative default artifact paths under the
/// project root; explicit absolute paths pass through.
fn anchored(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    }
}

/// Stage the per-run `/koxi` overlay tree: the driver module (from
/// the requested flavor's artifact dir), the vm-driver-setup asset,
/// and the generated spec/prep contract.
fn stage_overlay(
    staging: &Path,
    name: &str,
    driver: &Driver,
    module_dir: &Path,
    project: &Project,
) -> Result<(), Box<dyn std::error::Error>> {
    let ko = module_dir.join(&driver.ko);
    if !ko.is_file() {
        return Err(format!("{} missing — run `koxi block setup` first", ko.display()).into());
    }
    for dir in ["koxi/modules", "koxi/scripts", "koxi/driver_setup"] {
        fs::create_dir_all(staging.join(dir))?;
    }
    fs::copy(&ko, staging.join("koxi/modules").join(&driver.ko))?;
    let script = assets::load(&project.root, &project.config, "virt/vm-driver-setup")?;
    let script_path = staging.join("koxi/scripts/vm_driver_setup");
    fs::write(&script_path, script.as_bytes())?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;
    fs::write(
        staging.join("koxi/driver_setup/spec"),
        driver_spec(name, driver) + "\n",
    )?;
    if let Some(prep) = &driver.prep {
        fs::write(staging.join("koxi/driver_setup/prep"), format!("{prep}\n"))?;
    }
    Ok(())
}

/// v1 spec line: role:name:ko:device:insmod_params:configfs_dir:configfs_params.
fn driver_spec(name: &str, driver: &Driver) -> String {
    let role = match driver.role {
        Role::C => "c",
        Role::Rs => "rs",
    };
    format!(
        "{role}:{name}:{ko}:{device}:{insmod}:{configfs}:{configfs_params}",
        ko = driver.ko,
        device = driver.device.display(),
        insmod = driver.insmod.as_deref().unwrap_or(""),
        configfs = driver.configfs.as_deref().unwrap_or(""),
        configfs_params = driver.configfs_params.as_deref().unwrap_or(""),
    )
}

/// Single-quote a word for the guest's /bin/sh unless it is plainly
/// safe (v1 used printf %q).
fn shell_quote(word: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn spec_matches_v1_shape() {
        let config = Config::parse(include_str!("../../koxi.toml")).unwrap();
        let driver = &config.block.drivers["null_blk"];
        let spec = driver_spec("null_blk", driver);
        let fields: Vec<&str> = spec.split(':').collect();
        assert_eq!(fields.len(), 7, "spec is 7 colon-separated fields: {spec}");
        assert_eq!(fields[0], "c");
        assert_eq!(fields[1], "null_blk");
        assert_eq!(fields[2], driver.ko);
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote("uname"), "uname");
        assert_eq!(shell_quote("-r"), "-r");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r#"'it'\''s'"#);
        assert_eq!(shell_quote(""), "''");
    }
}
