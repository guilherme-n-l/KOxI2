//! fio — the block-class benchmark workload generator: source fetch
//! and the static musl build (v1 `perf/fio-*/build`), one
//! [`build_static`] recipe.

use std::path::PathBuf;
use std::process::Command;

use tracing::info;

use crate::cmd;
use crate::fetch::{self, Ctx};
use crate::util;
use crate::virt::build::{build_static, Error, Options, Recipe};

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
    // No config asset: the configure flags are part of the recipe.
    const FIO_RECIPE: Recipe = Recipe {
        source: SOURCE,
        artifact: FIO,
        binary: "fio",
        config: None,
        version: RECIPE,
    };
    let logs = ctx.logs;
    build_static(ctx, opts, &FIO_RECIPE, |tree, cc| {
        info!("configuring fio");
        let mut configure = Command::new("./configure");
        configure
            .current_dir(tree)
            .args(CONFIGURE)
            .env("CC", cc)
            .env("NIX_HARDENING_ENABLE", "");
        cmd::status(configure, "fio-configure", logs)?;

        let jobs = util::jobs();
        info!(
            "building fio with {jobs} jobs (log: {})",
            logs.join("make-fio.log").display()
        );
        let mut make = Command::new("make");
        make.arg("-C")
            .arg(tree)
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
        Ok(cmd::status(strip, "strip-fio", logs)?)
    })
}
