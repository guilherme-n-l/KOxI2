//! Build the static BusyBox for the initramfs (v1
//! `kernel/busybox-*/build`) and the static dropbear multibinary —
//! two instances of one shape shared with fio: pristine tarball
//! extract into scratch, an optional config asset at `.config`, the
//! recipe's own configure + make, then the binary at the tree root
//! harvested into `artifacts/` and sha-locked. A build is skipped
//! when the input fingerprint (recipe, tarball sha, config sha,
//! musl-gcc identity) is unchanged.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info};

use crate::fetch::{self, Ctx};
use crate::kernel::build::ARTIFACTS_DIR;
use crate::lock::LockedSource;
use crate::scratch::Scratch;
use crate::util;
use crate::{assets, cmd};

/// Artifact and lock key.
pub const BUSYBOX: &str = "busybox";

/// Artifact name; the lock build key is "dropbear".
pub const DROPBEARMULTI: &str = "dropbearmulti";

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

/// What varies between the static musl userland builds.
pub struct Recipe {
    /// koxi.toml sources key; also the lock build key and log label.
    pub source: &'static str,
    /// Artifact file name; also the lock artifact key.
    pub artifact: &'static str,
    /// Tree-relative path of the built binary.
    pub binary: &'static str,
    /// Config asset written to the tree's `.config` before
    /// `compile` runs; its sha joins the fingerprint.
    pub config: Option<&'static str>,
    /// The module's `RECIPE` constant, part of the fingerprint.
    pub version: u32,
}

/// Ensure the static busybox is built; returns `artifacts/busybox`.
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    const BUSYBOX_RECIPE: Recipe = Recipe {
        source: BUSYBOX,
        artifact: BUSYBOX,
        binary: "busybox",
        config: Some("busybox/config"),
        version: RECIPE,
    };
    let logs = ctx.logs;
    build_static(ctx, opts, &BUSYBOX_RECIPE, |tree, cc| {
        // v1: `yes "" | make oldconfig` — accept defaults for any
        // symbol the asset does not pin.
        info!("configuring busybox (oldconfig)");
        let mut oldconfig = Command::new("sh");
        oldconfig
            .arg("-c")
            .arg(format!("yes '' | make -C '{}' oldconfig", tree.display()));
        cmd::status(oldconfig, "make-busybox-oldconfig", logs)?;

        let jobs = util::jobs();
        info!(
            "building busybox with {jobs} jobs (log: {})",
            logs.join("make-busybox.log").display()
        );
        let mut make = Command::new("make");
        make.arg("-C")
            .arg(tree)
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
        Ok(cmd::status(make, "make-busybox", logs)?)
    })
}

/// Ensure the static dropbear multibinary is built; returns
/// `artifacts/dropbearmulti`.
pub fn build_dropbear(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    // No config asset: the configure flags are part of the recipe.
    const DROPBEAR_RECIPE: Recipe = Recipe {
        source: "dropbear",
        artifact: DROPBEARMULTI,
        binary: "dropbearmulti",
        config: None,
        version: RECIPE,
    };
    let logs = ctx.logs;
    build_static(ctx, opts, &DROPBEAR_RECIPE, |tree, cc| {
        info!("configuring dropbear");
        let mut configure = Command::new("./configure");
        configure
            .current_dir(tree)
            .args(DROPBEAR_CONFIGURE)
            .env("CC", cc)
            .env("NIX_HARDENING_ENABLE", "");
        cmd::status(configure, "dropbear-configure", logs)?;

        let jobs = util::jobs();
        info!(
            "building dropbear with {jobs} jobs (log: {})",
            logs.join("make-dropbear.log").display()
        );
        let mut make = Command::new("make");
        make.arg("-C")
            .arg(tree)
            .arg("PROGRAMS=dropbear dropbearkey scp")
            .arg("MULTI=1")
            .arg("STATIC=1")
            .env("NIX_HARDENING_ENABLE", "")
            .arg("-j")
            .arg(jobs.to_string());
        Ok(cmd::status(make, "make-dropbear", logs)?)
    })
}

/// The shared shape: fingerprint check, pristine extract into
/// scratch, config asset, the recipe's `compile(tree, cc)`, then
/// harvest and lock. Returns the artifact path.
pub fn build_static(
    ctx: &mut Ctx,
    opts: &Options,
    recipe: &Recipe,
    compile: impl FnOnce(&Path, &str) -> Result<(), Error>,
) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let logs = ctx.logs;
    let label = recipe.source;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let artifact = artifacts.join(recipe.artifact);

    let config = recipe
        .config
        .map(|name| assets::load_locked(ctx.root, ctx.config, name, ctx.lock))
        .transpose()?;
    let (tarball, stem) = fetch::tarball_path(recipe.source, ctx)?;
    let Some(LockedSource::Tarball {
        sha256: source_sha, ..
    }) = ctx.lock.sources.get(recipe.source)
    else {
        return Err(Error::NotFetched(recipe.source));
    };

    // The resolved compiler is part of the identity: on nix MUSL_GCC
    // is a store path, so a musl/gcc bump changes the fingerprint.
    let cc = musl_cc();
    let toolchain = format!("{cc}:{}", probe_version(&cc));
    let expected = match &config {
        Some(config) => format!(
            "r{}:{source_sha}:{}:{toolchain}",
            recipe.version, config.sha256
        ),
        None => format!("r{}:{source_sha}:{toolchain}", recipe.version),
    };

    if artifact.is_file() && !opts.force && ctx.lock.builds.get(label) == Some(&expected) {
        debug!("{label} cached at {}", artifact.display());
        return Ok(artifact);
    }

    Scratch::new(ctx.home, &format!("{stem}-"))?.run(|dir| {
        let tree = fetch::extract_pristine(&tarball, dir, &stem, logs)?;
        if let Some(config) = &config {
            fs::write(tree.join(".config"), config.contents.as_bytes())?;
        }
        compile(&tree, &cc)?;

        let built = tree.join(recipe.binary);
        if !built.is_file() {
            return Err(Error::MissingBinary(built));
        }
        fs::create_dir_all(&artifacts)?;
        fs::copy(&built, &artifact)?;
        ctx.lock
            .artifacts
            .insert(recipe.artifact.to_owned(), util::sha256_file(&artifact)?);
        ctx.lock.builds.insert(label.to_owned(), expected);
        Ok(())
    })?;

    info!("{label} at {}", artifact.display());
    Ok(artifact)
}

/// The static-userland compiler: `$MUSL_GCC` (set by the flake to an
/// absolute store path) or `musl-gcc` from PATH.
pub fn musl_cc() -> String {
    std::env::var("MUSL_GCC").unwrap_or_else(|_| "musl-gcc".to_owned())
}

/// First line of `<cc> --version` for fingerprints ("unknown" when
/// the compiler is missing).
pub fn probe_version(cc: &str) -> String {
    util::probe_version(cc, &["--version"], "unknown")
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("this build step requires a Linux host")]
    NotLinux,
    #[error("the {0} source is not locked yet (fetch step missing)")]
    NotFetched(&'static str),
    #[error("prerequisite artifact {0} missing (run earlier build steps)")]
    MissingPrereq(String),
    #[error("build finished without producing {}", .0.display())]
    MissingBinary(PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Asset(#[from] assets::Error),
    #[error(transparent)]
    Fetch(#[from] fetch::Error),
    #[error(transparent)]
    Cmd(#[from] cmd::Error),
}
