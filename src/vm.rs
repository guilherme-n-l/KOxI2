//! `koxi vm` — boot the built kernel + initramfs in qemu with an
//! optional registry driver loaded at init, then run a command or an
//! interactive shell in the guest. The qemu sibling of `koxi metal`:
//! the dev-loop face of `virt::runner`, and the end-to-end smoke for
//! the overlay-initrd driver transport the perf and fuzz phases
//! reuse.

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::builder::FalseyValueParser;
use clap::parser::ValueSource;
use clap::{value_parser, Arg, ArgAction, ArgMatches};
use tracing::{error, info};

use crate::config::{anchored, Project};
use crate::kernel::build::{Flavor, ARTIFACTS_DIR, BZIMAGE};
use crate::virt::runner;
use crate::{fetch, logging};

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
        Some((name, driver)) => runner::driver_initrd(
            scratch.path(),
            &base_initrd,
            name,
            driver,
            &module_dir,
            &project,
            logs,
        )?,
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
            .map(|word| runner::shell_quote(word))
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
