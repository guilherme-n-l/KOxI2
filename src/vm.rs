//! `koxi vm` — boot the built kernel + initramfs in qemu with an
//! optional registry driver loaded at init, then run a command or an
//! interactive shell in the guest. The qemu sibling of `koxi metal`:
//! the dev-loop face of `virt::runner`, and the end-to-end smoke for
//! the overlay-initrd driver transport the perf and fuzz phases
//! reuse.

use std::io::IsTerminal;
use std::process::ExitCode;

use anyhow::{anyhow, bail};
use clap::{Arg, ArgAction, ArgMatches};
use tracing::info;

use crate::cli::VmOpts;
use crate::config::{anchored, Project};
use crate::home;
use crate::kernel::build::{Flavor, ARTIFACTS_DIR, BZIMAGE};
use crate::scratch::Scratch;
use crate::virt::runner;

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
        // The same geometry the perf phase boots, so a `koxi vm`
        // reproduction of a benchmark run is the same guest.
        .args(VmOpts::args())
        .arg(
            Arg::new("cmd")
                .num_args(0..)
                .allow_hyphen_values(true)
                .trailing_var_arg(true)
                .help("Command to run in the guest (default: interactive shell)"),
        )
}

pub fn run(matches: &ArgMatches, logs: &std::path::Path) -> anyhow::Result<ExitCode> {
    let command: Vec<&String> = matches
        .get_many::<String>("cmd")
        .into_iter()
        .flatten()
        .collect();
    if command.is_empty() && !std::io::stdin().is_terminal() {
        bail!("no command given and stdin is not a terminal");
    }
    let opts = VmOpts::from_matches(matches)?;

    let project = Project::locate()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    // --fuzz flips the kernel default and the module source to the
    // fuzz flavor's namespace; an explicit --kernel (or KERNEL) wins.
    let flavor = if matches.get_flag("fuzz") {
        Flavor::Fuzz
    } else {
        Flavor::Clean
    };
    let kernel = if flavor == Flavor::Fuzz && VmOpts::kernel_defaulted(matches) {
        flavor.dir(&artifacts).join(BZIMAGE)
    } else {
        anchored(&project.root, &opts.kernel)
    };
    let module_dir = flavor.dir(&artifacts);
    let base_initrd = anchored(&project.root, &opts.guest.initrd);

    let driver = match matches.get_one::<String>("driver") {
        Some(name) => {
            let driver =
                project.config.block.drivers.get(name).ok_or_else(|| {
                    anyhow!("driver {name} is not in the [block.drivers] registry")
                })?;
            Some((name.as_str(), driver))
        }
        None => None,
    };

    // Per-run scratch for the overlay and the concatenated initrd;
    // qemu is torn down before this drops.
    let scratch = Scratch::new(&home::koxi_home()?, "vm-")?;

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
            memory: opts.guest.memory.clone(),
            smp: opts.guest.smp,
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
            bail!(
                "driver {name} setup ran but {} is absent",
                driver.device.display()
            );
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
