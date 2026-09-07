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

use std::path::Path;
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use clap::ArgMatches;

use crate::cli::Globals;
use crate::config::{BaremetalConfig, Project};
use crate::kernel::build::{ARTIFACTS_DIR, BZIMAGE};
use crate::util::confirm;
use crate::virt::initramfs::INITRAMFS;
use crate::virt::runner;

const REMOTE_DIR: &str = "/tmp/koxi-metal";

pub fn command() -> clap::Command {
    clap::Command::new("metal")
        .about("Bare-metal target control (kexec)")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(clap::Command::new("boot").about(
            "Push artifacts and kexec the target into the test kernel (asks first; --yes skips)",
        ))
        .subcommand(
            clap::Command::new("reset").about("Reboot the target back into its resident OS"),
        )
}

pub fn run(matches: &ArgMatches, globals: &Globals) -> anyhow::Result<ExitCode> {
    match matches.subcommand() {
        Some(("boot", _)) => boot(globals.yes)?,
        Some(("reset", _)) => reset()?,
        _ => unreachable!("subcommand is required"),
    }
    Ok(ExitCode::SUCCESS)
}

fn target() -> anyhow::Result<(Project, BaremetalConfig)> {
    let project = Project::locate()?;
    let baremetal = project
        .config
        .baremetal
        .clone()
        .context("koxi.toml has no [baremetal] table (host = \"user@target\")")?;
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

fn boot(yes: bool) -> anyhow::Result<()> {
    let (project, config) = target()?;
    let artifacts = project.root.join(ARTIFACTS_DIR);
    let bzimage = artifacts.join(BZIMAGE);
    let initramfs = artifacts.join(INITRAMFS);
    for path in [&bzimage, &initramfs] {
        ensure!(
            path.is_file(),
            "{} missing — run `koxi block setup` first",
            path.display()
        );
    }

    let prompt = format!(
        "kexec will replace the running OS on {} until reset. Continue?",
        config.host
    );
    ensure!(confirm(&prompt, yes)?, "aborted");

    println!("pushing artifacts to {}", config.host);
    host_ssh(&config, &["mkdir", "-p", REMOTE_DIR])?;
    let status = Command::new("scp")
        .arg("-q")
        .arg(&bzimage)
        .arg(&initramfs)
        .arg(format!("{}:{REMOTE_DIR}/", config.host))
        .status()
        .context("running scp")?;
    ensure!(status.success(), "scp to {} failed: {status}", config.host);

    let net = config.net.as_deref().unwrap_or("dhcp");
    let append = match &config.append {
        Some(extra) => format!("console=tty0 console=ttyS0,115200 koxi.net={net} {extra}"),
        None => format!("console=tty0 console=ttyS0,115200 koxi.net={net}"),
    };
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
    .context("kexec-tools installed? passwordless sudo? lockdown off?")?;

    println!("executing kexec — the ssh connection will drop");
    // The machine warm-boots mid-command; any exit is fine.
    let _ = Command::new("ssh")
        .args([
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ServerAliveInterval=2",
            "-o",
            "ServerAliveCountMax=2",
        ])
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
    bail!(
        "test kernel did not answer at {guest} within 3 minutes; check the console \
         (wrong NIC driver in the kernel config, or koxi.net mismatch?)"
    )
}

fn reset() -> anyhow::Result<()> {
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
    bail!(
        "{} did not come back within 5 minutes; it may need a manual power cycle",
        config.host
    )
}

/// Run `args` on the resident OS with the user's own ssh identity.
fn host_ssh(config: &BaremetalConfig, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("ssh")
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5"])
        .arg(&config.host)
        .args(args)
        .status()
        .context("running ssh")?;
    ensure!(
        status.success(),
        "ssh {} {} failed: {status}",
        config.host,
        args.join(" ")
    );
    Ok(())
}

/// Run `command` on the test kernel's dropbear, capturing stdout.
fn guest_ssh(key: &Path, guest: &str, command: &str) -> anyhow::Result<String> {
    let output = runner::ssh_command(key, true)
        .arg(format!("root@{guest}"))
        .arg(command)
        .output()
        .context("running ssh")?;
    ensure!(
        output.status.success(),
        "guest ssh failed: {}",
        output.status
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
