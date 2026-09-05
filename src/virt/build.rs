//! Build the static BusyBox for the initramfs (v1
//! `kernel/busybox-*/build`): pristine tarball extract into tempdir
//! scratch, apply the `busybox/config` asset, `yes "" | make
//! oldconfig`, then a static musl build. The binary is harvested to
//! `artifacts/busybox` and sha-locked; the build is skipped when the
//! input fingerprint (recipe, tarball sha, config sha, musl-gcc
//! identity) is unchanged.

use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use tracing::{debug, info, warn};

use crate::fetch::{self, Ctx};
use crate::kernel::build::ARTIFACTS_DIR;
use crate::lock::LockedSource;
use crate::{assets, cmd};

/// Artifact and lock key.
pub const BUSYBOX: &str = "busybox";

/// Artifact name; the lock build key is "dropbear".
pub const DROPBEARMULTI: &str = "dropbearmulti";

/// koxi.toml sources key.
const SOURCE: &str = "busybox";

/// Bumped when the build steps themselves change.
const RECIPE: u32 = 1;

/// v1's configure flags, minus the libxcrypt plumbing (CPPFLAGS /
/// LDFLAGS / LIBS=-lutil and the cppflags-reorder patch): musl
/// provides crypt() and openpty() in libc, so none of it is needed.
const DROPBEAR_CONFIGURE: &[&str] = &[
    "--enable-static",
    "--enable-bundled-libtom",
    "--disable-zlib",
    "--disable-pam",
    "--disable-syslog",
    "--disable-shadow",
    "--disable-lastlog",
    "--disable-utmp",
    "--disable-utmpx",
    "--disable-wtmp",
    "--disable-wtmpx",
    "--disable-loginfunc",
    "--disable-pututline",
    "--disable-pututxline",
    "--enable-openpty",
    "--disable-harden",
];

/// Shared by the static-userland builds (busybox, dropbear, fio).
pub struct Options {
    pub force: bool,
}

/// Ensure the static busybox is built; returns `artifacts/busybox`.
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let logs = ctx.logs;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let artifact = artifacts.join(BUSYBOX);

    let config = assets::load_locked(ctx.root, ctx.config, "busybox/config", ctx.lock)?;
    let (tarball, stem) = fetch::tarball_path(SOURCE, ctx)?;
    let Some(LockedSource::Tarball {
        sha256: source_sha, ..
    }) = ctx.lock.sources.get(SOURCE)
    else {
        return Err(Error::NotFetched(SOURCE));
    };

    // The resolved compiler is part of the identity: on nix MUSL_GCC
    // is a store path, so a musl/gcc bump changes the fingerprint.
    let cc = musl_cc();
    let toolchain = format!("{cc}:{}", probe_version(&cc));
    let expected = format!("r{RECIPE}:{source_sha}:{}:{toolchain}", config.sha256);

    if artifact.is_file() && !opts.force && ctx.lock.builds.get(SOURCE) == Some(&expected) {
        debug!("busybox cached at {}", artifact.display());
        return Ok(artifact);
    }

    let tmp_root = ctx.home.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix(&format!("{stem}-"))
        .tempdir_in(&tmp_root)?;
    let tree = scratch.path().join(&stem);

    let result = (|| -> Result<(), Error> {
        info!("extracting pristine {stem} for build");
        let mut tar = Command::new("tar");
        tar.arg("-xf").arg(&tarball).arg("-C").arg(scratch.path());
        cmd::status(tar, "tar-build", logs)?;
        if !tree.is_dir() {
            return Err(Error::UnexpectedLayout(tree.clone()));
        }

        fs::write(tree.join(".config"), config.contents.as_bytes())?;

        // v1: `yes "" | make oldconfig` — accept defaults for any
        // symbol the asset does not pin.
        info!("configuring busybox (oldconfig)");
        let mut oldconfig = Command::new("sh");
        oldconfig
            .arg("-c")
            .arg(format!("yes '' | make -C '{}' oldconfig", tree.display()));
        cmd::status(oldconfig, "make-busybox-oldconfig", logs)?;

        let jobs = thread::available_parallelism().map_or(1, |n| n.get());
        info!(
            "building busybox with {jobs} jobs (log: {})",
            logs.join("make-busybox.log").display()
        );
        let mut make = Command::new("make");
        make.arg("-C")
            .arg(&tree)
            .arg(format!("CC={cc}"))
            // v1 parity: lets musl-gcc find kernel headers on
            // FHS hosts; harmless where /usr/include is absent.
            .arg("CFLAGS=-idirafter /usr/include")
            // The nix cc-wrapper injects hardening flags (fortify,
            // -Werror=format-security) that busybox's old printf
            // patterns fail; inert outside nix.
            .env("NIX_HARDENING_ENABLE", "")
            .arg("-j")
            .arg(jobs.to_string());
        cmd::status(make, "make-busybox", logs)?;

        let built = tree.join("busybox");
        if !built.is_file() {
            return Err(Error::MissingBinary(built));
        }
        fs::create_dir_all(&artifacts)?;
        fs::copy(&built, &artifact)?;
        ctx.lock
            .artifacts
            .insert(BUSYBOX.to_owned(), fetch::sha256(&artifact, logs)?);

        let used = assets::load_locked(ctx.root, ctx.config, "busybox/config", ctx.lock)?;
        let source_sha = match ctx.lock.sources.get(SOURCE) {
            Some(LockedSource::Tarball { sha256, .. }) => sha256.clone(),
            _ => return Err(Error::NotFetched(SOURCE)),
        };
        ctx.lock.builds.insert(
            SOURCE.to_owned(),
            format!("r{RECIPE}:{source_sha}:{}:{toolchain}", used.sha256),
        );
        Ok(())
    })();

    if let Err(err) = result {
        let kept = scratch.keep();
        warn!("build scratch kept for debugging at {}", kept.display());
        return Err(err);
    }

    info!("busybox at {}", artifact.display());
    Ok(artifact)
}

/// Ensure the static dropbear multibinary is built; returns
/// `artifacts/dropbearmulti`.
pub fn build_dropbear(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let logs = ctx.logs;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let artifact = artifacts.join(DROPBEARMULTI);

    let (tarball, stem) = fetch::tarball_path("dropbear", ctx)?;
    let Some(LockedSource::Tarball {
        sha256: source_sha, ..
    }) = ctx.lock.sources.get("dropbear")
    else {
        return Err(Error::NotFetched("dropbear"));
    };
    let cc = musl_cc();
    let toolchain = format!("{cc}:{}", probe_version(&cc));
    // No config asset: the configure flags are part of the recipe.
    let expected = format!("r{RECIPE}:{source_sha}:{toolchain}");

    if artifact.is_file() && !opts.force && ctx.lock.builds.get("dropbear") == Some(&expected) {
        debug!("dropbear cached at {}", artifact.display());
        return Ok(artifact);
    }

    let tmp_root = ctx.home.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix(&format!("{stem}-"))
        .tempdir_in(&tmp_root)?;
    let tree = scratch.path().join(&stem);

    let result = (|| -> Result<(), Error> {
        info!("extracting pristine {stem} for build");
        let mut tar = Command::new("tar");
        tar.arg("-xf").arg(&tarball).arg("-C").arg(scratch.path());
        cmd::status(tar, "tar-build", logs)?;
        if !tree.is_dir() {
            return Err(Error::UnexpectedLayout(tree.clone()));
        }

        info!("configuring dropbear");
        let mut configure = Command::new("./configure");
        configure
            .current_dir(&tree)
            .args(DROPBEAR_CONFIGURE)
            .env("CC", &cc)
            .env("NIX_HARDENING_ENABLE", "");
        cmd::status(configure, "dropbear-configure", logs)?;

        let jobs = thread::available_parallelism().map_or(1, |n| n.get());
        info!(
            "building dropbear with {jobs} jobs (log: {})",
            logs.join("make-dropbear.log").display()
        );
        let mut make = Command::new("make");
        make.arg("-C")
            .arg(&tree)
            .arg("PROGRAMS=dropbear dropbearkey scp")
            .arg("MULTI=1")
            .arg("STATIC=1")
            .env("NIX_HARDENING_ENABLE", "")
            .arg("-j")
            .arg(jobs.to_string());
        cmd::status(make, "make-dropbear", logs)?;

        let built = tree.join("dropbearmulti");
        if !built.is_file() {
            return Err(Error::MissingBinary(built));
        }
        fs::create_dir_all(&artifacts)?;
        fs::copy(&built, &artifact)?;
        ctx.lock
            .artifacts
            .insert(DROPBEARMULTI.to_owned(), fetch::sha256(&artifact, logs)?);
        ctx.lock
            .builds
            .insert("dropbear".to_owned(), expected.clone());
        Ok(())
    })();

    if let Err(err) = result {
        let kept = scratch.keep();
        warn!("build scratch kept for debugging at {}", kept.display());
        return Err(err);
    }

    info!("dropbear at {}", artifact.display());
    Ok(artifact)
}

/// The static-userland compiler: `$MUSL_GCC` (set by the flake to an
/// absolute store path) or `musl-gcc` from PATH.
pub fn musl_cc() -> String {
    std::env::var("MUSL_GCC").unwrap_or_else(|_| "musl-gcc".to_owned())
}

pub fn probe_version(cc: &str) -> String {
    let output = Command::new(cc).arg("--version").output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned(),
        _ => "unknown".to_owned(),
    }
}

#[derive(Debug)]
pub enum Error {
    NotLinux,
    NotFetched(&'static str),
    MissingPrereq(String),
    UnexpectedLayout(PathBuf),
    MissingBinary(PathBuf),
    Io(std::io::Error),
    Asset(assets::Error),
    Fetch(fetch::Error),
    Cmd(cmd::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<assets::Error> for Error {
    fn from(err: assets::Error) -> Self {
        Error::Asset(err)
    }
}

impl From<fetch::Error> for Error {
    fn from(err: fetch::Error) -> Self {
        Error::Fetch(err)
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
            Error::NotLinux => write!(f, "this build step requires a Linux host"),
            Error::NotFetched(name) => {
                write!(
                    f,
                    "the {name} source is not locked yet (fetch step missing)"
                )
            }
            Error::MissingPrereq(what) => {
                write!(
                    f,
                    "prerequisite artifact {what} missing (run earlier build steps)"
                )
            }
            Error::UnexpectedLayout(tree) => write!(
                f,
                "extracting the tarball did not produce {}",
                tree.display()
            ),
            Error::MissingBinary(path) => {
                write!(f, "build finished without producing {}", path.display())
            }
            Error::Io(err) => write!(f, "{err}"),
            Error::Asset(err) => write!(f, "{err}"),
            Error::Fetch(err) => write!(f, "{err}"),
            Error::Cmd(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {}
