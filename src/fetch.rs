//! Shared acquisition of third-party sources declared in `koxi.toml`:
//! tarballs (sha256-verified against the project's `koxi.lock`) and
//! git checkouts (rev pin resolved to a locked commit). Artifacts are
//! cached globally under the koxi home (`$KOXI_HOME`, default
//! `~/.koxi`) and shared across projects, cargo-style; the config and
//! lock stay per-project. Shells out to wget, sha256sum, tar, and
//! git; subprocess output is teed to per-task files under `out/logs/`.

use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info, warn};

use crate::cmd;
use crate::config::{Config, Source};
use crate::lock::{Lock, LockedSource};

/// Reusable downloads under the koxi home (`--nocache` clears it):
/// tarballs, extracted source trees, git checkouts and mirrors.
pub const CACHE_DIR: &str = "cache";

/// Tools every fetch shells out to; `block test` preflights these.
pub const REQUIRED_TOOLS: &[&str] = &["wget", "sha256sum", "tar", "git"];

/// The global artifact home: `$KOXI_HOME`, defaulting to `~/.koxi`.
pub fn koxi_home() -> Result<PathBuf, Error> {
    if let Some(home) = std::env::var_os("KOXI_HOME") {
        return Ok(PathBuf::from(home));
    }
    std::env::var_os("HOME")
        .map(|home| Path::new(&home).join(".koxi"))
        .ok_or(Error::NoHome)
}

/// Everything a fetch needs besides the source name. The lock is
/// loaded and saved once per run by the driver, not per fetch.
pub struct Ctx<'a> {
    pub config: &'a Config,
    /// The project root (where koxi.toml lives): anchors asset
    /// overrides and the lock.
    pub root: &'a Path,
    /// The koxi home (see [`koxi_home`]): anchors the artifact cache.
    pub home: &'a Path,
    pub lock: &'a mut Lock,
    /// Per-run task log directory (`log/<project>/<run-id>`).
    pub logs: &'a Path,
    pub assume_yes: bool,
}

/// Ensure the tarball source `name` is downloaded, verified, and
/// extracted; returns the source tree (`cache/<name>-<version>`, which
/// must be the tarball's top-level directory).
pub fn tarball(name: &str, ctx: &mut Ctx) -> Result<PathBuf, Error> {
    let source = lookup(name, ctx.config)?;
    let Source::Tarball { version, url } = source else {
        return Err(Error::WrongKind {
            name: name.to_owned(),
            expected: "tarball (version + url)",
        });
    };

    let out = ctx.home.join(CACHE_DIR);
    let logs = ctx.logs;
    fs::create_dir_all(&out)?;

    let tarball = out.join(tarball_name(url)?);
    let stem = format!("{name}-{version}");
    let src_dir = out.join(&stem);
    let stamp = out.join(format!(".{stem}.extracted"));

    if tarball.exists() {
        let sha = sha256(&tarball, logs)?;
        if ctx.lock.satisfies(name, source) {
            match ctx.lock.sources.get(name) {
                Some(LockedSource::Tarball { sha256: locked, .. }) if *locked == sha => {
                    return ensure_extracted(name, &tarball, &out, &src_dir, &stamp, logs);
                }
                // Locked hash differs: stale or corrupt file, refetch.
                _ => {}
            }
        } else {
            // Shared-cache adoption: the file exists (fetched by some
            // other project) but this project's lock has no valid
            // entry yet — lock its hash instead of re-downloading.
            info!("{name}: adopting cached tarball {}", tarball.display());
            ctx.lock.sources.insert(
                name.to_owned(),
                LockedSource::Tarball {
                    version: version.clone(),
                    url: url.clone(),
                    sha256: sha,
                },
            );
            return ensure_extracted(name, &tarball, &out, &src_dir, &stamp, logs);
        }
    }

    download(url, &tarball, logs)?;
    let sha = sha256(&tarball, logs)?;
    match ctx.lock.sources.get(name) {
        Some(LockedSource::Tarball { sha256: locked, .. }) if ctx.lock.satisfies(name, source) => {
            if *locked != sha {
                return Err(Error::HashMismatch {
                    name: name.to_owned(),
                    expected: locked.clone(),
                    got: sha,
                });
            }
        }
        _ => {
            ctx.lock.sources.insert(
                name.to_owned(),
                LockedSource::Tarball {
                    version: version.clone(),
                    url: url.clone(),
                    sha256: sha,
                },
            );
        }
    }

    if src_dir.exists() && stamp.is_file() {
        let prompt = format!("{} already exists; replace it?", src_dir.display());
        if !confirm(&prompt, ctx.assume_yes)? {
            warn!(
                "keeping existing {}; it may not match the fetched tarball",
                src_dir.display()
            );
            return Ok(src_dir);
        }
    }
    reset_extraction(&src_dir, &stamp)?;
    extract_verified(name, &tarball, &out, &src_dir, &stamp, logs)
}

/// Ensure the git source `name` is cloned into `cache/<name>` and checked
/// out at the locked commit, resolving and locking the declared rev on
/// first use; returns the checkout path.
pub fn git(name: &str, ctx: &mut Ctx) -> Result<PathBuf, Error> {
    let source = lookup(name, ctx.config)?;
    let Source::Git { git: url, rev } = source else {
        return Err(Error::WrongKind {
            name: name.to_owned(),
            expected: "git (git + rev)",
        });
    };

    let out = ctx.home.join(CACHE_DIR);
    let logs = ctx.logs;
    fs::create_dir_all(&out)?;
    let repo = out.join(name);

    if repo.exists() && !repo.join(".git").is_dir() {
        warn!("removing incomplete checkout {}", repo.display());
        fs::remove_dir_all(&repo)?;
    }
    if !repo.exists() {
        info!("cloning {url}");
        let mut clone = Command::new("git");
        clone.arg("clone").arg(url).arg(&repo);
        cmd::status(clone, "git-clone", logs)?;
    }

    let locked_commit = match ctx.lock.sources.get(name) {
        Some(LockedSource::Git { commit, .. }) if ctx.lock.satisfies(name, source) => {
            Some(commit.clone())
        }
        _ => None,
    };
    let commit = match locked_commit {
        Some(commit) => commit,
        None => {
            let commit = resolve_commit(&repo, rev, logs)?;
            ctx.lock.sources.insert(
                name.to_owned(),
                LockedSource::Git {
                    git: url.clone(),
                    rev: rev.clone(),
                    commit: commit.clone(),
                },
            );
            commit
        }
    };

    if head_commit(&repo, logs)? != commit {
        checkout_commit(&repo, &commit, logs)?;
    }
    debug!("{name}: checked out {commit}");
    Ok(repo)
}

/// Ensure the git-meta source `name` — a bare, blob-filtered history
/// mirror for commit mining — exists in `cache/<name>.git` with the
/// locked commit available; returns the repo path. Never checked out.
pub fn git_meta(name: &str, ctx: &mut Ctx) -> Result<PathBuf, Error> {
    let source = lookup(name, ctx.config)?;
    let Source::GitMeta { git_meta: url, rev } = source else {
        return Err(Error::WrongKind {
            name: name.to_owned(),
            expected: "git-meta (git-meta + rev)",
        });
    };

    let out = ctx.home.join(CACHE_DIR);
    let logs = ctx.logs;
    fs::create_dir_all(&out)?;
    let repo = out.join(format!("{name}.git"));

    if repo.exists() && !repo.join("HEAD").is_file() {
        warn!("removing incomplete mirror {}", repo.display());
        fs::remove_dir_all(&repo)?;
    }
    if !repo.exists() {
        info!("cloning {url} (bare, history only)");
        let mut clone = Command::new("git");
        clone
            .arg("clone")
            .arg("--bare")
            .arg("--filter=blob:none")
            .arg(url)
            .arg(&repo);
        cmd::status(clone, "git-clone", logs)?;
    }

    let locked_commit = match ctx.lock.sources.get(name) {
        Some(LockedSource::GitMeta { commit, .. }) if ctx.lock.satisfies(name, source) => {
            Some(commit.clone())
        }
        _ => None,
    };
    let commit = match locked_commit {
        Some(commit) => {
            ensure_commit(&repo, &commit, logs)?;
            commit
        }
        None => {
            let commit = resolve_commit(&repo, rev, logs)?;
            ctx.lock.sources.insert(
                name.to_owned(),
                LockedSource::GitMeta {
                    git_meta: url.clone(),
                    rev: rev.clone(),
                    commit: commit.clone(),
                },
            );
            commit
        }
    };
    debug!("{name}: history mirror holds {commit}");
    Ok(repo)
}

/// Locate `tool` on PATH.
pub fn find_tool(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// The cached tarball location and `<name>-<version>` stem of a
/// tarball source — for build steps that re-extract pristine trees.
pub fn tarball_path(name: &str, ctx: &Ctx) -> Result<(PathBuf, String), Error> {
    let Source::Tarball { version, url } = lookup(name, ctx.config)? else {
        return Err(Error::WrongKind {
            name: name.to_owned(),
            expected: "tarball (version + url)",
        });
    };
    let out = ctx.home.join(CACHE_DIR);
    Ok((out.join(tarball_name(url)?), format!("{name}-{version}")))
}

fn lookup<'c>(name: &str, config: &'c Config) -> Result<&'c Source, Error> {
    config
        .sources
        .get(name)
        .ok_or_else(|| Error::NotConfigured(name.to_owned()))
}

/// Return the extracted tree for a verified tarball, redoing a
/// missing or unstamped (interrupted) extraction first.
fn ensure_extracted(
    name: &str,
    tarball: &Path,
    out: &Path,
    src_dir: &Path,
    stamp: &Path,
    logs: &Path,
) -> Result<PathBuf, Error> {
    if src_dir.is_dir() && stamp.is_file() {
        debug!("{name}: cached at {}", src_dir.display());
        return Ok(src_dir.to_owned());
    }
    info!("{name}: redoing missing or interrupted extraction");
    reset_extraction(src_dir, stamp)?;
    extract_verified(name, tarball, out, src_dir, stamp, logs)
}

fn tarball_name(url: &str) -> Result<&str, Error> {
    let name = url.rsplit('/').next().unwrap_or_default();
    if name.is_empty() {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    Ok(name)
}

/// Remove a stale or incomplete extraction (stamp first, so a crash
/// between the two removals still reads as incomplete).
fn reset_extraction(src_dir: &Path, stamp: &Path) -> Result<(), Error> {
    if stamp.exists() {
        fs::remove_file(stamp)?;
    }
    if src_dir.exists() {
        fs::remove_dir_all(src_dir)?;
    }
    Ok(())
}

/// Extract and require the expected top-level directory, then stamp
/// the extraction as complete so interrupted runs are re-done.
fn extract_verified(
    name: &str,
    tarball: &Path,
    out: &Path,
    src_dir: &Path,
    stamp: &Path,
    logs: &Path,
) -> Result<PathBuf, Error> {
    extract(tarball, out, logs)?;
    if !src_dir.is_dir() {
        return Err(Error::UnexpectedLayout {
            name: name.to_owned(),
            expected: src_dir.to_owned(),
        });
    }
    fs::write(stamp, b"")?;
    Ok(src_dir.to_owned())
}

fn download(url: &str, dest: &Path, logs: &Path) -> Result<(), Error> {
    info!("fetching {url}");
    let partial = PathBuf::from(format!("{}.part", dest.display()));
    let mut wget = Command::new("wget");
    wget.arg("-O").arg(&partial).arg(url);
    if let Err(err) = cmd::status(wget, "wget", logs) {
        let _ = fs::remove_file(&partial);
        return Err(err.into());
    }
    fs::rename(&partial, dest)?;
    Ok(())
}

/// sha256 of a file, via the same sha256sum used everywhere else.
pub fn sha256(path: &Path, logs: &Path) -> Result<String, Error> {
    let mut cmd = Command::new("sha256sum");
    cmd.arg(path);
    let stdout = cmd::stdout(cmd, "sha256sum", logs)?;
    stdout
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or(Error::Cmd(cmd::Error::Malformed("sha256sum")))
}

fn extract(tarball: &Path, out: &Path, logs: &Path) -> Result<(), Error> {
    info!("extracting {}", tarball.display());
    let mut tar = Command::new("tar");
    tar.arg("-xf").arg(tarball).arg("-C").arg(out);
    Ok(cmd::status(tar, "tar", logs)?)
}

fn git_in(repo: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);
    cmd
}

fn head_commit(repo: &Path, logs: &Path) -> Result<String, Error> {
    Ok(cmd::stdout(
        git_in(repo, &["rev-parse", "HEAD"]),
        "git-rev-parse",
        logs,
    )?)
}

/// Resolve a commit hash or tag to a full commit hash, fetching from
/// origin when the pin is not available locally.
fn resolve_commit(repo: &Path, rev: &str, logs: &Path) -> Result<String, Error> {
    let spec = format!("{rev}^{{commit}}");
    let rev_parse = |spec: &str| {
        cmd::stdout(
            git_in(repo, &["rev-parse", "--verify", spec]),
            "git-rev-parse",
            logs,
        )
    };
    if let Ok(commit) = rev_parse(&spec) {
        return Ok(commit);
    }
    let _ = cmd::status(git_in(repo, &["fetch", "origin", rev]), "git-fetch", logs);
    let _ = cmd::status(
        git_in(repo, &["fetch", "--tags", "origin"]),
        "git-fetch",
        logs,
    );
    Ok(rev_parse(&spec)?)
}

/// Require `commit` to be present locally, fetching it when missing.
fn ensure_commit(repo: &Path, commit: &str, logs: &Path) -> Result<(), Error> {
    let spec = format!("{commit}^{{commit}}");
    let verify = || {
        cmd::stdout(
            git_in(repo, &["rev-parse", "--verify", &spec]),
            "git-rev-parse",
            logs,
        )
    };
    if verify().is_ok() {
        return Ok(());
    }
    cmd::status(
        git_in(repo, &["fetch", "origin", commit]),
        "git-fetch",
        logs,
    )?;
    verify()?;
    Ok(())
}

fn checkout_commit(repo: &Path, commit: &str, logs: &Path) -> Result<(), Error> {
    let checkout = || {
        cmd::status(
            git_in(repo, &["checkout", "--detach", commit]),
            "git-checkout",
            logs,
        )
    };
    if checkout().is_ok() {
        return Ok(());
    }
    cmd::status(
        git_in(repo, &["fetch", "origin", commit]),
        "git-fetch",
        logs,
    )?;
    Ok(checkout()?)
}

fn confirm(prompt: &str, assume_yes: bool) -> Result<bool, Error> {
    if assume_yes {
        info!("{prompt} — assuming yes (--yes)");
        return Ok(true);
    }
    if !io::stdin().is_terminal() {
        return Err(Error::ConfirmationRequired(prompt.to_owned()));
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

#[derive(Debug)]
pub enum Error {
    NoHome,
    NotConfigured(String),
    WrongKind {
        name: String,
        expected: &'static str,
    },
    InvalidUrl(String),
    UnexpectedLayout {
        name: String,
        expected: PathBuf,
    },
    ConfirmationRequired(String),
    Io(std::io::Error),
    Cmd(cmd::Error),
    HashMismatch {
        name: String,
        expected: String,
        got: String,
    },
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
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
            Error::NoHome => write!(f, "cannot determine the koxi home: set KOXI_HOME or HOME"),
            Error::NotConfigured(name) => write!(f, "koxi.toml has no [sources.{name}]"),
            Error::WrongKind { name, expected } => {
                write!(f, "[sources.{name}] must be a {expected} source")
            }
            Error::InvalidUrl(url) => write!(f, "cannot derive a file name from url {url}"),
            Error::UnexpectedLayout { name, expected } => write!(
                f,
                "extracting {name} did not produce {}; the tarball's top-level \
                 directory does not match its version/url declaration",
                expected.display()
            ),
            Error::ConfirmationRequired(prompt) => write!(
                f,
                "{prompt} — confirmation needed but stdin is not a terminal; rerun with --yes"
            ),
            Error::Io(err) => write!(f, "{err}"),
            Error::Cmd(err) => write!(f, "{err}"),
            Error::HashMismatch {
                name,
                expected,
                got,
            } => write!(
                f,
                "{name} tarball sha256 {got} does not match locked {expected}; \
                 remove the {name} entry from koxi.lock to accept a new upstream tarball"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    struct Fixture {
        home: tempfile::TempDir,
        root: tempfile::TempDir,
        config: Config,
        lock: Lock,
    }

    /// A home whose cache holds a tiny thing-1.0.tar.gz whose top
    /// directory is `topdir`; the source URL points at a closed port
    /// so any download attempt fails fast and loudly.
    fn fixture(topdir: &str) -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let root = tempfile::tempdir().unwrap();
        let cache = home.path().join(CACHE_DIR);
        fs::create_dir_all(&cache).unwrap();

        let staging = tempfile::tempdir().unwrap();
        fs::create_dir_all(staging.path().join(topdir)).unwrap();
        fs::write(staging.path().join(topdir).join("file"), "hi").unwrap();
        let status = Command::new("tar")
            .arg("-czf")
            .arg(cache.join("thing-1.0.tar.gz"))
            .arg("-C")
            .arg(staging.path())
            .arg(topdir)
            .status()
            .unwrap();
        assert!(status.success());

        let config = Config::parse(
            "[sources.thing]\nversion = \"1.0\"\nurl = \"http://127.0.0.1:9/thing-1.0.tar.gz\"\n",
        )
        .unwrap();
        Fixture {
            home,
            root,
            config,
            lock: Lock::default(),
        }
    }

    fn run_tarball(fx: &mut Fixture) -> Result<PathBuf, Error> {
        let logs = fx.home.path().join("logs");
        let mut ctx = Ctx {
            config: &fx.config,
            root: fx.root.path(),
            home: fx.home.path(),
            lock: &mut fx.lock,
            logs: &logs,
            assume_yes: true,
        };
        tarball("thing", &mut ctx)
    }

    #[test]
    fn adopts_cached_tarball_then_serves_from_cache() {
        let mut fx = fixture("thing-1.0");
        let tree = run_tarball(&mut fx).unwrap();
        assert!(tree.join("file").is_file());
        assert!(
            fx.lock.sources.contains_key("thing"),
            "adoption locked the hash"
        );
        let stamp = fx.home.path().join(CACHE_DIR).join(".thing-1.0.extracted");
        assert!(stamp.is_file());

        // Fully cached: no re-extract (a marker in the tree survives).
        fs::write(tree.join("marker"), "x").unwrap();
        run_tarball(&mut fx).unwrap();
        assert!(tree.join("marker").is_file());
    }

    #[test]
    fn missing_stamp_forces_reextraction() {
        let mut fx = fixture("thing-1.0");
        let tree = run_tarball(&mut fx).unwrap();
        fs::write(tree.join("marker"), "x").unwrap();
        fs::remove_file(fx.home.path().join(CACHE_DIR).join(".thing-1.0.extracted")).unwrap();

        run_tarball(&mut fx).unwrap();
        assert!(
            !tree.join("marker").exists(),
            "interrupted extraction was redone"
        );
        assert!(tree.join("file").is_file());
    }

    #[test]
    fn mismatched_tarball_layout_errors() {
        let mut fx = fixture("wrong-1.0");
        assert!(matches!(
            run_tarball(&mut fx),
            Err(Error::UnexpectedLayout { .. })
        ));
    }

    #[test]
    fn corrupt_cache_attempts_refetch() {
        let mut fx = fixture("thing-1.0");
        run_tarball(&mut fx).unwrap();

        // Lock is valid but the file no longer matches it: koxi must
        // refetch, which fails against the closed port.
        let tarball_path = fx.home.path().join(CACHE_DIR).join("thing-1.0.tar.gz");
        let mut bytes = fs::read(&tarball_path).unwrap();
        bytes.push(0);
        fs::write(&tarball_path, bytes).unwrap();

        assert!(matches!(run_tarball(&mut fx), Err(Error::Cmd(_))));
    }

    #[test]
    fn tarball_name_is_last_url_segment() {
        assert_eq!(
            tarball_name("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.19.tar.xz").unwrap(),
            "linux-6.19.tar.xz"
        );
        assert!(tarball_name("https://example.com/dir/").is_err());
    }
}
