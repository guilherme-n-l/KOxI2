//! Build syzkaller at the locked commit (v1 `fuzz/syzkaller/build`),
//! patch-free: the scp -O legacy-protocol fix is upstream
//! (google/syzkaller#7090) and gcc 15 builds the executor clean under
//! -Werror. Scratch is a shared local clone of the cache checkout at
//! the locked commit — the git analogue of the pristine tarball
//! extract. Go modules download on first build (content-pinned by the
//! commit's go.sum, cached in GOMODCACHE afterwards); `make generate`
//! + flatc only return if custom syscall descriptions land.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info};

use crate::cmd;
use crate::fetch::Ctx;
use crate::home::CACHE_DIR;
use crate::kernel::build::ARTIFACTS_DIR;
use crate::lock::LockedSource;
use crate::scratch::Scratch;
use crate::util;
use crate::virt::build::{probe_version, Error, Options};

const SOURCE: &str = "syzkaller";

/// Bumped when the build steps themselves change.
const RECIPE: u32 = 1;

/// bin/-relative outputs harvested into artifacts/syzkaller/bin/.
/// The layout is preserved because syz-manager resolves its helpers
/// relative to the configured syzkaller dir.
const BINARIES: &[&str] = &[
    "syz-manager",
    "syz-mutate",
    "syz-prog2c",
    "syz-repro",
    "syz-sysgen",
    "syz-upgrade",
    "linux_amd64/syz-execprog",
    "linux_amd64/syz-executor",
];

/// Ensure syzkaller is built at the locked commit; returns the
/// harvested root (`artifacts/syzkaller`), whose `bin/` layout is
/// what the manager config's "syzkaller" key points at.
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let logs = ctx.logs;
    let harvest_root = ctx.root.join(ARTIFACTS_DIR).join(SOURCE);

    let Some(LockedSource::Git { commit, .. }) = ctx.lock.sources.get(SOURCE) else {
        return Err(Error::NotFetched(SOURCE));
    };
    let commit = commit.clone();

    // The executor is C++ built by gcc; the rest is go.
    let toolchain = format!(
        "{}|{}",
        util::probe_version("go", &["version"], "unknown"),
        probe_version("gcc")
    );
    let expected = format!("r{RECIPE}:{commit}:{toolchain}");

    let all_harvested = || {
        BINARIES
            .iter()
            .all(|rel| harvest_root.join("bin").join(rel).is_file())
    };
    if !opts.force && ctx.lock.builds.get(SOURCE) == Some(&expected) && all_harvested() {
        debug!("syzkaller cached at {}", harvest_root.display());
        return Ok(harvest_root);
    }

    let cache_repo = ctx.home.join(CACHE_DIR).join(SOURCE);
    Scratch::new(ctx.home, "syzkaller-")?.run(|dir| {
        let repo = dir.join(SOURCE);
        clone_pristine(&cache_repo, &repo, &commit, logs)?;
        compile(&repo, logs)?;
        for rel in BINARIES {
            let built = repo.join("bin").join(rel);
            if !built.is_file() {
                return Err(Error::MissingBinary(built));
            }
            let dest = harvest_root.join("bin").join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&built, &dest)?;
            ctx.lock
                .artifacts
                .insert(format!("syzkaller/bin/{rel}"), util::sha256_file(&dest)?);
        }
        ctx.lock.builds.insert(SOURCE.to_owned(), expected);
        Ok(())
    })?;

    info!("syzkaller at {}", harvest_root.display());
    Ok(harvest_root)
}

/// A shared local clone of the cache checkout, detached at `commit`.
fn clone_pristine(cache_repo: &Path, repo: &Path, commit: &str, logs: &Path) -> Result<(), Error> {
    info!("cloning pristine syzkaller at {}", &commit[..12]);
    let mut clone = Command::new("git");
    clone
        .arg("clone")
        .arg("-q")
        .arg("--shared")
        .arg(cache_repo)
        .arg(repo);
    cmd::status(clone, "git-clone", logs)?;
    let mut checkout = Command::new("git");
    checkout
        .arg("-C")
        .arg(repo)
        .arg("checkout")
        .arg("-q")
        .arg("--detach")
        .arg(commit);
    Ok(cmd::status(checkout, "git-checkout", logs)?)
}

fn compile(repo: &Path, logs: &Path) -> Result<(), Error> {
    let jobs = util::jobs();
    info!(
        "building syzkaller with {jobs} jobs (log: {})",
        logs.join("make-syzkaller.log").display()
    );
    let mut make = Command::new("make");
    make.arg("-C")
        .arg(repo)
        .env("NIX_HARDENING_ENABLE", "")
        .arg("-j")
        .arg(jobs.to_string());
    // Static libc for the executor's -static probe, scoped to
    // this build only (globally it poisons host-tool links).
    if let Ok(dir) = std::env::var("GLIBC_STATIC_LIB") {
        let existing = std::env::var("NIX_LDFLAGS").unwrap_or_default();
        make.env("NIX_LDFLAGS", format!("{existing} -L{dir}"));
    }
    Ok(cmd::status(make, "make-syzkaller", logs)?)
}
