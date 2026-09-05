//! Boot the built kernel + initramfs in qemu and talk to the guest
//! over its forwarded dropbear — the runner the perf and fuzz phases
//! drive programmatically (v1 `vm_run`).
//!
//! Per-run payloads (driver module, setup script, spec) travel as a
//! second cpio archive concatenated onto the locked base initramfs:
//! the kernel unpacks initramfs archives back to back, so the base
//! image stays generic and byte-stable while each run overlays its
//! own `/koxi` tree. The same transport works for kexec bare metal,
//! where there is no 9p.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::cmd;

/// Launch parameters; `port` forwards to the guest's dropbear.
pub struct Options {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub memory: String,
    pub smp: u32,
    pub port: u16,
    /// ssh client key matching the image's baked authorized_keys.
    pub key: PathBuf,
    /// Extra kernel cmdline after `console=ttyS0 rdinit=/init`.
    pub append: String,
}

/// Pack the `staging` tree as a cpio archive and concatenate it onto
/// `base` at `out`. Entries land over the base rootfs at unpack time.
pub fn overlay_initrd(base: &Path, staging: &Path, out: &Path, logs: &Path) -> Result<(), Error> {
    let overlay = out.with_file_name("overlay.cpio.gz");
    let mut pack = Command::new("sh");
    pack.arg("-c").arg(format!(
        "cd '{root}' && find . | LC_ALL=C sort | \
         cpio -o -H newc --owner 0:0 | gzip -n > '{overlay}'",
        root = staging.display(),
        overlay = overlay.display()
    ));
    cmd::status(pack, "pack-overlay", logs)?;
    let mut dest = fs::File::create(out)?;
    for part in [base, overlay.as_path()] {
        io::copy(&mut fs::File::open(part)?, &mut dest)?;
    }
    Ok(())
}

/// A launched qemu guest; killed on drop (the guest is stateless).
pub struct Vm {
    child: Child,
    port: u16,
    key: PathBuf,
    console: PathBuf,
}

impl Vm {
    /// Spawn qemu with the serial console teed to `<logs>/vm-console.log`,
    /// KVM when /dev/kvm is usable (TCG fallback warns).
    pub fn launch(opts: &Options, logs: &Path) -> Result<Self, Error> {
        for input in [&opts.kernel, &opts.initrd, &opts.key] {
            if !input.is_file() {
                return Err(Error::MissingInput(input.clone()));
            }
        }
        fs::create_dir_all(logs)?;
        let console = logs.join("vm-console.log");
        let sink = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&console)?;

        let append = format!("console=ttyS0 rdinit=/init {}", opts.append);
        let mut qemu = Command::new("qemu-system-x86_64");
        qemu.arg("-kernel")
            .arg(&opts.kernel)
            .arg("-initrd")
            .arg(&opts.initrd)
            .arg("-m")
            .arg(&opts.memory)
            .arg("-smp")
            .arg(opts.smp.to_string())
            .arg("-append")
            .arg(append.trim())
            .arg("-nographic")
            .arg("-no-reboot")
            .arg("-netdev")
            .arg(format!("user,id=net0,hostfwd=tcp::{}-:22", opts.port))
            .arg("-device")
            .arg("e1000,netdev=net0");
        if kvm_available() {
            qemu.arg("-enable-kvm").arg("-cpu").arg("host");
        } else {
            warn!("/dev/kvm unavailable — booting under TCG (slow)");
        }
        qemu.stdin(Stdio::null())
            .stdout(Stdio::from(sink.try_clone()?))
            .stderr(Stdio::from(sink));
        debug!("running {qemu:?} (console: {})", console.display());
        info!(
            "launching qemu (mem {}, smp {}, ssh port {})",
            opts.memory, opts.smp, opts.port
        );
        let child = qemu.spawn().map_err(Error::Spawn)?;
        Ok(Self {
            child,
            port: opts.port,
            key: opts.key.clone(),
            console,
        })
    }

    /// Poll the guest's dropbear until it answers, qemu exits, or the
    /// timeout passes.
    pub fn wait_ready(&mut self, timeout: u64) -> Result<(), Error> {
        info!("waiting for the guest's dropbear on port {}", self.port);
        let deadline = Instant::now() + Duration::from_secs(timeout);
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Err(Error::Died {
                    status,
                    console: self.console.clone(),
                });
            }
            if matches!(self.exec("true"), Ok(output) if output.status.success()) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    secs: timeout,
                    console: self.console.clone(),
                });
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    /// Run a command in the guest, capturing its output.
    pub fn exec(&self, command: &str) -> Result<Output, Error> {
        let mut ssh = self.ssh(true);
        ssh.arg(command).stdin(Stdio::null());
        ssh.output().map_err(Error::Ssh)
    }

    /// Run a command in the guest with inherited stdio.
    pub fn run(&self, command: &str) -> Result<ExitStatus, Error> {
        let mut ssh = self.ssh(true);
        ssh.arg(command);
        ssh.status().map_err(Error::Ssh)
    }

    /// Interactive guest shell on the caller's terminal.
    pub fn shell(&self) -> Result<ExitStatus, Error> {
        let mut ssh = self.ssh(false);
        ssh.arg("-t");
        ssh.status().map_err(Error::Ssh)
    }

    /// Kill the guest and reap qemu.
    pub fn shutdown(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn ssh(&self, batch: bool) -> Command {
        let mut ssh = Command::new("ssh");
        ssh.arg("-i")
            .arg(&self.key)
            .arg("-p")
            .arg(self.port.to_string())
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg("-o")
            .arg("UserKnownHostsFile=/dev/null")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg("-o")
            .arg("ConnectTimeout=3");
        if batch {
            ssh.arg("-o").arg("BatchMode=yes");
        }
        ssh.arg("root@localhost");
        ssh
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn kvm_available() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    MissingInput(PathBuf),
    Spawn(io::Error),
    Ssh(io::Error),
    Cmd(cmd::Error),
    Died {
        status: ExitStatus,
        console: PathBuf,
    },
    Timeout {
        secs: u64,
        console: PathBuf,
    },
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<cmd::Error> for Error {
    fn from(err: cmd::Error) -> Self {
        Error::Cmd(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "vm: {err}"),
            Error::MissingInput(path) => {
                write!(
                    f,
                    "{} missing — run `koxi block setup` first",
                    path.display()
                )
            }
            Error::Spawn(err) => write!(f, "launching qemu-system-x86_64: {err}"),
            Error::Ssh(err) => write!(f, "running ssh: {err}"),
            Error::Cmd(err) => write!(f, "{err}"),
            Error::Died { status, console } => {
                write!(
                    f,
                    "qemu exited early: {status} (console: {})",
                    console.display()
                )
            }
            Error::Timeout { secs, console } => {
                write!(
                    f,
                    "guest not reachable after {secs}s (console: {})",
                    console.display()
                )
            }
        }
    }
}

impl std::error::Error for Error {}
