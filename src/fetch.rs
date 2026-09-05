//! Shared acquisition of third-party sources declared in `koxi.toml`:
//! tarballs (cached in `out/`, sha256-verified against `koxi.lock`) and
//! git checkouts (rev pin resolved to a locked commit). Shells out to
//! wget, sha256sum, tar, and git.

use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use crate::config::{Config, Source};
use crate::lock::{self, Lock, LockedSource};

/// Download/extract cache, as in v1 (`--nocache` clears it).
pub const OUT_DIR: &str = "out";

/// Ensure the tarball source `name` is downloaded, verified, and
/// extracted; returns the source tree (`out/<name>-<version>`, assumed
/// to be the tarball's top-level directory).
pub fn tarball(name: &str, config: &Config) -> Result<PathBuf, Error> {
    let source = lookup(name, config)?;
    let Source::Tarball { version, url } = source else {
        return Err(Error::WrongKind {
            name: name.to_owned(),
            expected: "tarball (version + url)",
        });
    };

    let out = Path::new(OUT_DIR);
    fs::create_dir_all(out).map_err(Error::Io)?;
    let tarball = out.join(tarball_name(url)?);
    let src_dir = out.join(format!("{name}-{version}"));

    let lock_path = Path::new(lock::LOCK_PATH);
    let mut lockfile = Lock::load(lock_path)
        .map_err(Error::Lock)?
        .unwrap_or_default();

    if tarball_cached(name, &tarball, &lockfile, source)? {
        if !src_dir.exists() {
            extract(&tarball, out)?;
        }
        return Ok(src_dir);
    }

    download(url, &tarball)?;
    let sha = sha256(&tarball)?;
    match lockfile.sources.get(name) {
        Some(LockedSource::Tarball { sha256: locked, .. }) if lockfile.satisfies(name, source) => {
            if *locked != sha {
                return Err(Error::HashMismatch {
                    name: name.to_owned(),
                    expected: locked.clone(),
                    got: sha,
                });
            }
        }
        _ => {
            lockfile.sources.insert(
                name.to_owned(),
                LockedSource::Tarball {
                    version: version.clone(),
                    url: url.clone(),
                    sha256: sha,
                },
            );
            lockfile.save(lock_path).map_err(Error::Lock)?;
        }
    }

    if src_dir.exists() {
        let prompt = format!("{} already exists; replace it?", src_dir.display());
        if !confirm(&prompt)? {
            eprintln!("keeping existing {}", src_dir.display());
            return Ok(src_dir);
        }
        fs::remove_dir_all(&src_dir).map_err(Error::Io)?;
    }
    extract(&tarball, out)?;
    Ok(src_dir)
}

/// Ensure the git source `name` is cloned into `out/<name>` and checked
/// out at the locked commit, resolving and locking the declared rev on
/// first use; returns the checkout path.
pub fn git(name: &str, config: &Config) -> Result<PathBuf, Error> {
    let source = lookup(name, config)?;
    let Source::Git { git: url, rev } = source else {
        return Err(Error::WrongKind {
            name: name.to_owned(),
            expected: "git (git + rev)",
        });
    };

    let out = Path::new(OUT_DIR);
    fs::create_dir_all(out).map_err(Error::Io)?;
    let repo = out.join(name);

    let lock_path = Path::new(lock::LOCK_PATH);
    let mut lockfile = Lock::load(lock_path)
        .map_err(Error::Lock)?
        .unwrap_or_default();

    if !repo.exists() {
        eprintln!("cloning {url}");
        let mut clone = Command::new("git");
        clone.arg("clone").arg(url).arg(&repo);
        command_status(clone, "git clone")?;
    }

    let locked_commit = match lockfile.sources.get(name) {
        Some(LockedSource::Git { commit, .. }) if lockfile.satisfies(name, source) => {
            Some(commit.clone())
        }
        _ => None,
    };

    let commit = match locked_commit {
        Some(commit) => commit,
        None => {
            let commit = resolve_commit(&repo, rev)?;
            lockfile.sources.insert(
                name.to_owned(),
                LockedSource::Git {
                    git: url.clone(),
                    rev: rev.clone(),
                    commit: commit.clone(),
                },
            );
            lockfile.save(lock_path).map_err(Error::Lock)?;
            commit
        }
    };

    if head_commit(&repo)? != commit {
        checkout_commit(&repo, &commit)?;
    }
    Ok(repo)
}

fn lookup<'c>(name: &str, config: &'c Config) -> Result<&'c Source, Error> {
    config
        .sources
        .get(name)
        .ok_or_else(|| Error::NotConfigured(name.to_owned()))
}

/// Cached means: tarball present, lock entry consistent with the config
/// declaration, and the file's sha256 matches the locked one.
fn tarball_cached(
    name: &str,
    tarball: &Path,
    lockfile: &Lock,
    source: &Source,
) -> Result<bool, Error> {
    if !tarball.exists() || !lockfile.satisfies(name, source) {
        return Ok(false);
    }
    let Some(LockedSource::Tarball { sha256: locked, .. }) = lockfile.sources.get(name) else {
        return Ok(false);
    };
    Ok(*locked == sha256(tarball)?)
}

fn tarball_name(url: &str) -> Result<&str, Error> {
    let name = url.rsplit('/').next().unwrap_or_default();
    if name.is_empty() {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    Ok(name)
}

fn download(url: &str, dest: &Path) -> Result<(), Error> {
    eprintln!("fetching {url}");
    let partial = PathBuf::from(format!("{}.part", dest.display()));
    let mut wget = Command::new("wget");
    wget.arg("-O").arg(&partial).arg(url);
    if let Err(err) = command_status(wget, "wget") {
        let _ = fs::remove_file(&partial);
        return Err(err);
    }
    fs::rename(&partial, dest).map_err(Error::Io)
}

fn sha256(path: &Path) -> Result<String, Error> {
    let mut cmd = Command::new("sha256sum");
    cmd.arg(path);
    let stdout = command_stdout(cmd, "sha256sum")?;
    stdout
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or(Error::MalformedOutput("sha256sum"))
}

fn extract(tarball: &Path, out: &Path) -> Result<(), Error> {
    eprintln!("extracting {}", tarball.display());
    let mut tar = Command::new("tar");
    tar.arg("-xf").arg(tarball).arg("-C").arg(out);
    command_status(tar, "tar")
}

fn git_in(repo: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(repo).args(args);
    cmd
}

fn head_commit(repo: &Path) -> Result<String, Error> {
    command_stdout(git_in(repo, &["rev-parse", "HEAD"]), "git rev-parse")
}

/// Resolve a commit hash or tag to a full commit hash, fetching from
/// origin when the pin is not available locally.
fn resolve_commit(repo: &Path, rev: &str) -> Result<String, Error> {
    let spec = format!("{rev}^{{commit}}");
    let rev_parse = |spec: &str| {
        command_stdout(
            git_in(repo, &["rev-parse", "--verify", spec]),
            "git rev-parse",
        )
    };
    if let Ok(commit) = rev_parse(&spec) {
        return Ok(commit);
    }
    let _ = command_status(git_in(repo, &["fetch", "origin", rev]), "git fetch");
    let _ = command_status(git_in(repo, &["fetch", "--tags", "origin"]), "git fetch");
    rev_parse(&spec)
}

fn checkout_commit(repo: &Path, commit: &str) -> Result<(), Error> {
    let checkout = |repo| {
        command_status(
            git_in(repo, &["checkout", "--detach", commit]),
            "git checkout",
        )
    };
    if checkout(repo).is_ok() {
        return Ok(());
    }
    command_status(git_in(repo, &["fetch", "origin", commit]), "git fetch")?;
    checkout(repo)
}

fn command_status(mut cmd: Command, label: &'static str) -> Result<(), Error> {
    let status = cmd.status().map_err(|err| Error::Spawn(label, err))?;
    if !status.success() {
        return Err(Error::CommandFailed(label, status));
    }
    Ok(())
}

fn command_stdout(mut cmd: Command, label: &'static str) -> Result<String, Error> {
    let output = cmd.output().map_err(|err| Error::Spawn(label, err))?;
    if !output.status.success() {
        return Err(Error::CommandFailed(label, output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() {
        return Err(Error::MalformedOutput(label));
    }
    Ok(stdout)
}

fn confirm(prompt: &str) -> Result<bool, Error> {
    if !io::stdin().is_terminal() {
        eprintln!("{prompt} — no terminal, keeping the existing directory");
        return Ok(false);
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush().map_err(Error::Io)?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).map_err(Error::Io)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

#[derive(Debug)]
pub enum Error {
    NotConfigured(String),
    WrongKind {
        name: String,
        expected: &'static str,
    },
    InvalidUrl(String),
    Io(std::io::Error),
    Lock(lock::Error),
    Spawn(&'static str, std::io::Error),
    CommandFailed(&'static str, ExitStatus),
    MalformedOutput(&'static str),
    HashMismatch {
        name: String,
        expected: String,
        got: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotConfigured(name) => write!(f, "koxi.toml has no [sources.{name}]"),
            Error::WrongKind { name, expected } => {
                write!(f, "[sources.{name}] must be a {expected} source")
            }
            Error::InvalidUrl(url) => write!(f, "cannot derive a file name from url {url}"),
            Error::Io(err) => write!(f, "{err}"),
            Error::Lock(err) => write!(f, "{err}"),
            Error::Spawn(label, err) => write!(f, "running {label}: {err}"),
            Error::CommandFailed(label, status) => write!(f, "{label} failed: {status}"),
            Error::MalformedOutput(label) => write!(f, "unexpected {label} output"),
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

    #[test]
    fn tarball_name_is_last_url_segment() {
        assert_eq!(
            tarball_name("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.19.tar.xz").unwrap(),
            "linux-6.19.tar.xz"
        );
        assert!(tarball_name("https://example.com/dir/").is_err());
    }
}
