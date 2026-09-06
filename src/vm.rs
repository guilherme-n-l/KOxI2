//! `koxi vm` — boot the built kernel + initramfs in qemu with an
//! optional registry driver loaded at init, then run a command or an
//! interactive shell in the guest. The qemu sibling of `koxi metal`:
//! the dev-loop face of `virt::runner`, and the end-to-end smoke for
//! the overlay-initrd driver transport the perf and fuzz phases
//! reuse.

use std::fs;
use std::io::IsTerminal;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::FalseyValueParser;
use clap::parser::ValueSource;
use clap::{value_parser, Arg, ArgAction, ArgMatches};
use tracing::{error, info};

use crate::config::{Driver, Project, Role};
use crate::kernel::build::{Flavor, ARTIFACTS_DIR, BZIMAGE};
use crate::virt::runner;
use crate::{assets, fetch, logging};

pub fn command() -> clap::Command {
    clap::Command::new("vm")
        .about("Boot the test VM and run a command or interactive shell")
        .arg(
            Arg::new("driver")
                .long("driver")
                .value_name("name")
                .help("Registry driver to load at boot (module rides an overlay initrd)"),
        )
        .arg(
            Arg::new("fuzz")
                .long("fuzz")
                .action(ArgAction::SetTrue)
                .help("Boot the fuzz flavor (instrumented kernel + modules from artifacts/fuzz)"),
        )
        .arg(
            Arg::new("kernel")
                .long("kernel")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .env("KERNEL")
                .default_value("artifacts/bzImage")
                .help("Kernel bzImage (default resolved under the project root)"),
        )
        .arg(
            Arg::new("initrd")
                .long("initrd")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .env("INITRD")
                .default_value("artifacts/initramfs.cpio.gz")
                .help("Initrd"),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .value_name("port")
                .value_parser(value_parser!(u16))
                .env("FWDPORT")
                .default_value("5555")
                .help("SSH forward port"),
        )
        .arg(
            Arg::new("smp")
                .long("smp")
                .value_name("n")
                .value_parser(value_parser!(u32))
                .env("SMP")
                .default_value("4")
                .help("vCPUs"),
        )
        .arg(
            Arg::new("memory")
                .long("memory")
                .value_name("size")
                .env("MEMORY")
                .default_value("4G")
                .help("RAM"),
        )
        .arg(
            Arg::new("vm-timeout")
                .long("vm-timeout")
                .value_name("s")
                .value_parser(value_parser!(u64))
                .env("VM_TIMEOUT")
                .default_value("120")
                .help("VM ready timeout in seconds"),
        )
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue)
                .value_parser(FalseyValueParser::new())
                .env("VERBOSE")
                .help("Verbose output (V=1)"),
        )
        .arg(
            Arg::new("cmd")
                .num_args(0..)
                .allow_hyphen_values(true)
                .trailing_var_arg(true)
                .help("Command to run in the guest (default: interactive shell)"),
        )
}

pub fn run(matches: &ArgMatches) -> ExitCode {
    let logs = logging::run_log_dir();
    logging::init(
        matches.get_flag("verbose"),
        false,
        Some(&logs.join("run.log")),
    );
    match drive(matches, &logs) {
        Ok(code) => code,
        Err(err) => {
            error!("koxi vm: {err}");
            ExitCode::FAILURE
        }
    }
}

fn drive(matches: &ArgMatches, logs: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let command: Vec<&String> = matches
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
    let flavor = if matches.get_flag("fuzz") {
        Flavor::Fuzz
    } else {
        Flavor::Clean
    };
    let cli_kernel = matches.get_one::<PathBuf>("kernel").expect("defaulted");
    let kernel = if flavor == Flavor::Fuzz
        && matches.value_source("kernel") == Some(ValueSource::DefaultValue)
    {
        flavor.dir(&artifacts).join(BZIMAGE)
    } else {
        anchored(&project.root, cli_kernel)
    };
    let module_dir = flavor.dir(&artifacts);
    let base_initrd = anchored(
        &project.root,
        matches.get_one::<PathBuf>("initrd").expect("defaulted"),
    );

    let driver = match matches.get_one::<String>("driver") {
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
            memory: matches
                .get_one::<String>("memory")
                .cloned()
                .expect("defaulted"),
            smp: *matches.get_one::<u32>("smp").expect("defaulted"),
            port: *matches.get_one::<u16>("port").expect("defaulted"),
            key: artifacts.join("keys/id_ed25519"),
            append: String::new(),
        },
        logs,
    )?;
    vm.wait_ready(*matches.get_one::<u64>("vm-timeout").expect("defaulted"))?;
    info!(
        "guest is up (root@localhost:{})",
        matches.get_one::<u16>("port").expect("defaulted")
    );

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
    fn takes_driver_flavor_and_trailing_command() {
        let matches =
            command().get_matches_from(["vm", "--fuzz", "--driver", "rnull", "uname", "-r"]);
        assert!(matches.get_flag("fuzz"));
        assert_eq!(
            matches.get_one::<String>("driver").map(String::as_str),
            Some("rnull")
        );
        let cmd: Vec<&String> = matches.get_many::<String>("cmd").unwrap().collect();
        assert_eq!(cmd, ["uname", "-r"]);
    }

    #[test]
    fn spec_matches_v1_shape() {
        let config = Config::parse(include_str!("../koxi.toml")).unwrap();
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
