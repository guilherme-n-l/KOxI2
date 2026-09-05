//! fio — the block-class benchmark workload generator: source fetch
//! and the static musl build (v1 `perf/fio-*/build`).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use tracing::{debug, info, warn};

use crate::cmd;
use crate::fetch::{self, Ctx};
use crate::kernel::build::ARTIFACTS_DIR;
use crate::lock::LockedSource;
use crate::virt::build::{musl_cc, probe_version, Error, Options};

/// Artifact and lock key.
pub const FIO: &str = "fio";

const SOURCE: &str = "fio";

/// Bumped when the build steps themselves change.
const RECIPE: u32 = 1;

/// v1's configure flags. The forced linux/falloc.h include supplies
/// FALLOC_FL_ZERO_RANGE, which musl's fcntl.h omits by design; the
/// pinned -march keeps benchmark binaries comparable across hosts.
const CONFIGURE: &[&str] = &[
    "--build-static",
    "--disable-libnfs",
    "--disable-http",
    "--disable-rdma",
    "--disable-rados",
    "--disable-rbd",
    "--disable-gfapi",
    "--disable-lex",
    "--extra-cflags=-O2 -march=x86-64 -mtune=generic -include linux/falloc.h",
];

/// Ensure the fio source is present and verified; returns its path.
pub fn setup(ctx: &mut Ctx) -> Result<PathBuf, fetch::Error> {
    fetch::tarball(SOURCE, ctx)
}

/// Ensure the static fio is built; returns `artifacts/fio`.
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let logs = ctx.logs;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let artifact = artifacts.join(FIO);

    let (tarball, stem) = fetch::tarball_path(SOURCE, ctx)?;
    let Some(LockedSource::Tarball {
        sha256: source_sha, ..
    }) = ctx.lock.sources.get(SOURCE)
    else {
        return Err(Error::NotFetched(SOURCE));
    };
    let cc = musl_cc();
    let toolchain = format!("{cc}:{}", probe_version(&cc));
    // No config asset: the configure flags are part of the recipe.
    let expected = format!("r{RECIPE}:{source_sha}:{toolchain}");

    if artifact.is_file() && !opts.force && ctx.lock.builds.get(SOURCE) == Some(&expected) {
        debug!("fio cached at {}", artifact.display());
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

        info!("configuring fio");
        let mut configure = Command::new("./configure");
        configure
            .current_dir(&tree)
            .args(CONFIGURE)
            .env("CC", &cc)
            .env("NIX_HARDENING_ENABLE", "");
        cmd::status(configure, "fio-configure", logs)?;

        let jobs = thread::available_parallelism().map_or(1, |n| n.get());
        info!(
            "building fio with {jobs} jobs (log: {})",
            logs.join("make-fio.log").display()
        );
        let mut make = Command::new("make");
        make.arg("-C")
            .arg(&tree)
            .env("NIX_HARDENING_ENABLE", "")
            .arg("-j")
            .arg(jobs.to_string());
        cmd::status(make, "make-fio", logs)?;

        let built = tree.join("fio");
        if !built.is_file() {
            return Err(Error::MissingBinary(built));
        }
        let mut strip = Command::new("strip");
        strip.arg(&built);
        cmd::status(strip, "strip-fio", logs)?;

        fs::create_dir_all(&artifacts)?;
        fs::copy(&built, &artifact)?;
        ctx.lock
            .artifacts
            .insert(FIO.to_owned(), fetch::sha256(&artifact, logs)?);
        ctx.lock.builds.insert(SOURCE.to_owned(), expected.clone());
        Ok(())
    })();

    if let Err(err) = result {
        let kept = scratch.keep();
        warn!("build scratch kept for debugging at {}", kept.display());
        return Err(err);
    }

    info!("fio at {}", artifact.display());
    Ok(artifact)
}
