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
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::assets;
use crate::cmd;
use crate::config::{Driver, Project, Role};

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

/// Stage the per-run `/koxi` overlay tree: the driver module (from
/// the requested flavor's artifact dir), the vm-driver-setup asset,
/// and the generated spec/prep contract.
pub fn stage_overlay(
    staging: &Path,
    name: &str,
    driver: &Driver,
    module_dir: &Path,
    project: &Project,
) -> Result<(), Error> {
    let ko = module_dir.join(&driver.ko);
    if !ko.is_file() {
        return Err(Error::MissingInput(ko));
    }
    for dir in ["koxi/modules", "koxi/scripts", "koxi/driver_setup"] {
        fs::create_dir_all(staging.join(dir))?;
    }
    fs::copy(&ko, staging.join("koxi/modules").join(&driver.ko))?;
    let script = assets::load(&project.root, &project.config, "virt/vm-driver-setup")
        .map_err(|err| Error::Overlay(err.to_string()))?;
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

/// Stage a driver overlay in `scratch` and concatenate it onto the
/// base initramfs; returns the per-run initrd path.
pub fn driver_initrd(
    scratch: &Path,
    base_initrd: &Path,
    name: &str,
    driver: &Driver,
    module_dir: &Path,
    project: &Project,
    logs: &Path,
) -> Result<PathBuf, Error> {
    let staging = scratch.join("overlay");
    stage_overlay(&staging, name, driver, module_dir, project)?;
    let initrd = scratch.join("initrd.cpio.gz");
    overlay_initrd(base_initrd, &staging, &initrd, logs)?;
    Ok(initrd)
}

/// v1 spec line: role:name:ko:device:insmod_params:configfs_dir:configfs_params.
pub fn driver_spec(name: &str, driver: &Driver) -> String {
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
pub fn shell_quote(word: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_./=:@,+".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The acceleration this host will boot with — part of a perf
/// result's identity (KVM and TCG numbers must never be pooled).
pub fn accel() -> &'static str {
    if kvm_available() {
        "kvm"
    } else {
        "tcg"
    }
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
    Overlay(String),
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
            Error::Overlay(err) => write!(f, "staging overlay: {err}"),
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
