//! `koxi metal` — the bare-metal connection layer: push the built
//! artifacts to a target's resident OS over ssh, kexec into the test
//! kernel, wait for its dropbear, and reset back. Perf runners build
//! on this. The target needs kexec-tools, passwordless sudo for
//! kexec, Secure Boot/lockdown off, and wired Ethernet; the test
//! kernel is reached with the project's client key at `guest-addr`
//! (defaulting to the host — same MAC usually keeps the same DHCP
//! lease).
//!
//! Interactive by design: ssh/scp/kexec output streams to the
//! console rather than task logs.

use std::io::IsTerminal;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

use clap::{Arg, ArgAction, ArgMatches};

use crate::config::{BaremetalConfig, Project};
use crate::kernel::build::{ARTIFACTS_DIR, BZIMAGE};
use crate::virt::initramfs::INITRAMFS;

const REMOTE_DIR: &str = "/tmp/koxi-metal";

pub fn command() -> clap::Command {
    clap::Command::new("metal")
        .about("Bare-metal target control (kexec)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            clap::Command::new("boot")
                .about("Push artifacts and kexec the target into the test kernel")
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Skip the confirmation prompt"),
                ),
        )
        .subcommand(
            clap::Command::new("reset").about("Reboot the target back into its resident OS"),
        )
}

pub fn run(matches: &ArgMatches) -> ExitCode {
    let result = match matches.subcommand() {
        Some(("boot", sub)) => boot(sub.get_flag("yes")),
        Some(("reset", _)) => reset(),
        _ => unreachable!("subcommand is required"),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("koxi metal: {err}");
            ExitCode::FAILURE
        }
    }
}

fn target() -> Result<(Project, BaremetalConfig), String> {
    let project = Project::locate().map_err(|err| err.to_string())?;
    let baremetal = project
        .config
        .baremetal
        .clone()
        .ok_or("koxi.toml has no [baremetal] table (host = \"user@target\")")?;
    Ok((project, baremetal))
}

fn guest_addr(config: &BaremetalConfig) -> String {
    config.guest_addr.clone().unwrap_or_else(|| {
        config
            .host
            .rsplit('@')
            .next()
            .unwrap_or(&config.host)
            .to_owned()
    })
}

fn boot(yes: bool) -> Result<(), String> {
    let (project, config) = target()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    let bzimage = artifacts.join(BZIMAGE);
    let initramfs = artifacts.join(INITRAMFS);
    for path in [&bzimage, &initramfs] {
        if !path.is_file() {
            return Err(format!(
                "{} missing — run `koxi block setup` first",
                path.display()
            ));
        }
    }

    if !yes {
        if !std::io::stdin().is_terminal() {
            return Err(format!(
                "kexec will replace the OS on {} until reset; rerun with --yes",
                config.host
            ));
        }
        eprint!(
            "kexec will replace the running OS on {} until reset. Continue? [y/N] ",
            config.host
        );
        use std::io::Write;
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|err| err.to_string())?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            return Err("aborted".to_owned());
        }
    }

    println!("pushing artifacts to {}", config.host);
    host_ssh(&config, &["mkdir", "-p", REMOTE_DIR])?;
    let status = Command::new("scp")
        .arg("-q")
        .arg(&bzimage)
        .arg(&initramfs)
        .arg(format!("{}:{REMOTE_DIR}/", config.host))
        .status()
        .map_err(|err| format!("running scp: {err}"))?;
    if !status.success() {
        return Err(format!("scp to {} failed: {status}", config.host));
    }

    let net = config.net.clone().unwrap_or_else(|| "dhcp".to_owned());
    let append = format!(
        "console=tty0 console=ttyS0,115200 koxi.net={net}{}{}",
        if config.append.is_some() { " " } else { "" },
        config.append.as_deref().unwrap_or("")
    );
    println!("loading test kernel (append: {append})");
    host_ssh(
        &config,
        &[
            "sudo",
            "-n",
            "kexec",
            "-l",
            &format!("{REMOTE_DIR}/{BZIMAGE}"),
            &format!("--initrd={REMOTE_DIR}/{INITRAMFS}"),
            &format!("--append={append}"),
        ],
    )
    .map_err(|err| format!("{err} (kexec-tools installed? passwordless sudo? lockdown off?)"))?;

    println!("executing kexec — the ssh connection will drop");
    // The machine warm-boots mid-command; any exit is fine.
    let _ = Command::new("ssh")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("-o")
        .arg("ServerAliveInterval=2")
        .arg("-o")
        .arg("ServerAliveCountMax=2")
        .arg(&config.host)
        .args(["sudo", "-n", "kexec", "-e"])
        .status();

    let guest = guest_addr(&config);
    let key = artifacts.join("keys/id_ed25519");
    println!("waiting for the test kernel's dropbear at {guest}");
    for attempt in 1..=36 {
        thread::sleep(Duration::from_secs(5));
        if let Ok(output) = guest_ssh(&key, &guest, "uname -r && fio --version") {
            println!("test kernel is up (attempt {attempt}):\n{output}");
            println!("run `koxi metal reset` to return {} to its OS", config.host);
            return Ok(());
        }
    }
    Err(format!(
        "test kernel did not answer at {guest} within 3 minutes; check the console \
         (wrong NIC driver in the kernel config, or koxi.net mismatch?)"
    ))
}

fn reset() -> Result<(), String> {
    let (project, config) = target()?;
    let guest = guest_addr(&config);
    let key = project.root.join(ARTIFACTS_DIR).join("keys/id_ed25519");

    println!("rebooting the test kernel at {guest}");
    // reboot -f severs the connection; any exit is fine.
    let _ = guest_ssh(&key, &guest, "reboot -f");

    println!("waiting for the resident OS on {}", config.host);
    for _ in 1..=60 {
        thread::sleep(Duration::from_secs(5));
        if host_ssh(&config, &["true"]).is_ok() {
            println!("{} is back on its resident OS", config.host);
            return Ok(());
        }
    }
    Err(format!(
        "{} did not come back within 5 minutes; it may need a manual power cycle",
        config.host
    ))
}

fn host_ssh(config: &BaremetalConfig, args: &[&str]) -> Result<(), String> {
    let status = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg(&config.host)
        .args(args)
        .status()
        .map_err(|err| format!("running ssh: {err}"))?;
    if !status.success() {
        return Err(format!(
            "ssh {} {} failed: {status}",
            config.host,
            args.join(" ")
        ));
    }
    Ok(())
}

fn guest_ssh(key: &Path, guest: &str, command: &str) -> Result<String, String> {
    let output = Command::new("ssh")
        .arg("-i")
        .arg(key)
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=3")
        .arg(format!("root@{guest}"))
        .arg(command)
        .output()
        .map_err(|err| format!("running ssh: {err}"))?;
    if !output.status.success() {
        return Err(format!("guest ssh failed: {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
