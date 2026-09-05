//! Build the kernel image (v1 `kernel/linux-*/build`).
//!
//! For determinism every build starts from a pristine tree: the
//! verified tarball is re-extracted into a mktemp-style scratch dir
//! under `tmp/` in the koxi home, the `linux/config` asset is
//! applied, and only then does make run. Scratch auto-deletes after
//! a successful build and is kept on failure for debugging (it lives
//! under the home rather than the system /tmp, which is often
//! RAM-backed tmpfs — too small for a kernel tree). A build is
//! skipped when the artifact exists and the lock's input fingerprint
//! (recipe version, tarball sha, config sha, toolchain identity) is
//! unchanged.

use std::fmt;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use tracing::{debug, info, warn};

use crate::assets;
use crate::cmd;
use crate::fetch::{self, Ctx};
use crate::lock::LockedSource;

/// Project-relative directory for build outputs. Artifacts are
/// project-scoped (unlike sources) because they derive from
/// project-editable inputs like the kconfig asset.
pub const ARTIFACTS_DIR: &str = "artifacts";

/// The built kernel image.
pub const BZIMAGE: &str = "bzImage";

/// koxi.toml sources key for the kernel.
const SOURCE: &str = "linux";

/// Supported build targets, in kbuild vocabulary: target name to
/// (make ARCH value, image path inside the tree).
fn kbuild_arch(target: &str) -> Option<(&'static str, &'static str)> {
    match target {
        "x86_64" => Some(("x86_64", "arch/x86/boot/bzImage")),
        _ => None,
    }
}

/// Bumped when the build steps themselves change, so artifacts built
/// by an older recipe never fingerprint-match the new one.
const RECIPE: u32 = 1;

pub struct Options {
    pub force: bool,
    pub menuconfig: bool,
    pub skip_build: bool,
    /// C compiler passed to make as CC= (kbuild ignores the CC env
    /// var, so it must be an explicit make variable).
    pub cc: String,
    /// Build target arch in kbuild vocabulary (see [`kbuild_arch`]).
    pub target: String,
}

/// Ensure the kernel image is built; returns its path
/// (`out/bzImage`).
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let (arch, image_path) =
        kbuild_arch(&opts.target).ok_or_else(|| Error::UnsupportedTarget(opts.target.clone()))?;
    let build_key = format!("linux-{}", opts.target);

    let logs = ctx.logs;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let artifact = artifacts.join(BZIMAGE);

    let kconfig = assets::load_locked(ctx.root, ctx.config, "linux/config", ctx.lock)?;
    let (tarball, stem) = fetch::tarball_path(SOURCE, ctx)?;
    let Some(LockedSource::Tarball {
        sha256: source_sha, ..
    }) = ctx.lock.sources.get(SOURCE)
    else {
        return Err(Error::NotFetched);
    };
    let toolchain = toolchain_id(&opts.cc, logs);
    let expected = fingerprint(source_sha, &kconfig.sha256, &toolchain);

    if artifact.is_file()
        && !opts.force
        && !opts.menuconfig
        && ctx.lock.builds.get(&build_key) == Some(&expected)
    {
        debug!("kernel image cached at {}", artifact.display());
        return Ok(artifact);
    }

    // Pristine tree in a mktemp-style scratch dir: unique per build,
    // auto-deleted on success, kept on failure for debugging. Never
    // build in the shared source extraction.
    let tmp_root = ctx.home.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix(&format!("{stem}-"))
        .tempdir_in(&tmp_root)?;
    let tree = scratch.path().join(&stem);

    let result = (|| -> Result<(), Error> {
        info!("extracting pristine {} for build", stem);
        let mut tar = Command::new("tar");
        tar.arg("-xf").arg(&tarball).arg("-C").arg(scratch.path());
        cmd::status(tar, "tar-build", logs)?;
        if !tree.is_dir() {
            return Err(Error::UnexpectedLayout(tree.clone()));
        }

        fs::write(tree.join(".config"), kconfig.contents.as_bytes())?;

        if opts.menuconfig {
            menuconfig(&tree, arch, &opts.cc)?;
        }

        info!("configuring kernel (olddefconfig)");
        cmd::status(
            make(&tree, arch, &opts.cc, &["olddefconfig"]),
            "make-olddefconfig",
            logs,
        )?;

        if opts.menuconfig {
            // Persist the tuned config as the project override so
            // future runs use it (v1 copied it back into the repo).
            let dest = assets::default_override_path(ctx.root, "linux/config");
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(tree.join(".config"), &dest)?;
            info!("persisted menuconfig result to {}", dest.display());
        }

        if opts.skip_build {
            warn!("kernel build skipped (--skip-build); image may be stale or missing");
            return Ok(());
        }

        let jobs = thread::available_parallelism().map_or(1, |n| n.get());
        info!(
            "building kernel with {jobs} jobs (log: {})",
            logs.join("make-kernel.log").display()
        );
        cmd::status(
            make(&tree, arch, &opts.cc, &["-j", &jobs.to_string()]),
            "make-kernel",
            logs,
        )?;

        let bzimage = tree.join(image_path);
        if !bzimage.is_file() {
            return Err(Error::MissingImage(bzimage));
        }
        fs::create_dir_all(&artifacts)?;
        fs::copy(&bzimage, &artifact)?;

        // Re-hash the config actually used (menuconfig may have
        // changed it) so the recorded fingerprint matches the image.
        let built_with = assets::load_locked(ctx.root, ctx.config, "linux/config", ctx.lock)?;
        let source_sha = match ctx.lock.sources.get(SOURCE) {
            Some(LockedSource::Tarball { sha256, .. }) => sha256.clone(),
            _ => return Err(Error::NotFetched),
        };
        ctx.lock.builds.insert(
            build_key,
            fingerprint(&source_sha, &built_with.sha256, &toolchain),
        );
        Ok(())
    })();

    if let Err(err) = result {
        let kept = scratch.keep();
        warn!("build scratch kept for debugging at {}", kept.display());
        return Err(err);
    }

    info!("kernel image at {}", artifact.display());
    Ok(artifact)
}

/// Everything that determines the image bytes: recipe version,
/// source, config, and the toolchain that compiles it.
fn fingerprint(source_sha: &str, config_sha: &str, toolchain: &str) -> String {
    format!("r{RECIPE}:{source_sha}:{config_sha}:{toolchain}")
}

/// Compiler identity (the configured CC + rustc when present); a
/// toolchain bump must rebuild even with identical source and config.
fn toolchain_id(cc: &str, logs: &Path) -> String {
    let probe = |program: &str, label: &'static str| {
        let mut cmd = Command::new(program);
        cmd.arg("--version");
        crate::cmd::stdout(cmd, label, logs)
            .map(|out| out.lines().next().unwrap_or_default().to_owned())
            .unwrap_or_else(|_| "none".to_owned())
    };
    format!(
        "{}|{}",
        probe(cc, "cc-version"),
        probe("rustc", "rustc-version")
    )
}

fn make(tree: &Path, arch: &str, cc: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new("make");
    cmd.arg("-C")
        .arg(tree)
        .arg(format!("ARCH={arch}"))
        .arg(format!("CC={cc}"))
        .args(args);
    cmd
}

/// Interactive `make menuconfig`, inheriting the terminal.
fn menuconfig(tree: &Path, arch: &str, cc: &str) -> Result<(), Error> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::MenuconfigNeedsTty);
    }
    info!("running menuconfig");
    let status = make(tree, arch, cc, &["menuconfig"])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(Error::Io)?;
    if !status.success() {
        return Err(Error::Menuconfig(status));
    }
    Ok(())
}

#[derive(Debug)]
pub enum Error {
    NotLinux,
    NotFetched,
    UnsupportedTarget(String),
    UnexpectedLayout(PathBuf),
    MissingImage(PathBuf),
    MenuconfigNeedsTty,
    Menuconfig(std::process::ExitStatus),
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
            Error::NotLinux => write!(f, "the kernel build requires a Linux host"),
            Error::UnsupportedTarget(target) => {
                write!(f, "unsupported build target {target} (supported: x86_64)")
            }
            Error::NotFetched => {
                write!(f, "the linux source is not locked yet (fetch step missing)")
            }
            Error::UnexpectedLayout(tree) => write!(
                f,
                "extracting the kernel tarball did not produce {}",
                tree.display()
            ),
            Error::MissingImage(path) => {
                write!(
                    f,
                    "kernel build finished without producing {}",
                    path.display()
                )
            }
            Error::MenuconfigNeedsTty => {
                write!(f, "--menuconfig needs an interactive terminal")
            }
            Error::Menuconfig(status) => write!(f, "menuconfig failed: {status}"),
            Error::Io(err) => write!(f, "{err}"),
            Error::Asset(err) => write!(f, "{err}"),
            Error::Fetch(err) => write!(f, "{err}"),
            Error::Cmd(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {}
