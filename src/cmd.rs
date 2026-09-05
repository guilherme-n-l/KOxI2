//! Shared subprocess execution with output teed to per-task log
//! files under `<logs>/<label>.log` — the console stays quiet, the
//! logs keep everything.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use tracing::debug;

fn task_log(logs: &Path, label: &str) -> Result<(File, PathBuf), Error> {
    fs::create_dir_all(logs).map_err(Error::Log)?;
    let path = logs.join(format!("{label}.log"));
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(Error::Log)?;
    Ok((file, path))
}

/// Run to completion; stdout and stderr are appended to the task log.
pub fn status(mut cmd: Command, label: &'static str, logs: &Path) -> Result<(), Error> {
    let (file, log) = task_log(logs, label)?;
    cmd.stdout(Stdio::from(file.try_clone().map_err(Error::Log)?));
    cmd.stderr(Stdio::from(file));
    debug!("running {cmd:?} (log: {})", log.display());
    let status = cmd.status().map_err(|err| Error::Spawn(label, err))?;
    if !status.success() {
        return Err(Error::Failed { label, status, log });
    }
    Ok(())
}

/// Run capturing trimmed stdout; stderr is appended to the task log.
pub fn stdout(mut cmd: Command, label: &'static str, logs: &Path) -> Result<String, Error> {
    let (file, log) = task_log(logs, label)?;
    cmd.stderr(Stdio::from(file));
    debug!("running {cmd:?} (log: {})", log.display());
    let output = cmd.output().map_err(|err| Error::Spawn(label, err))?;
    if !output.status.success() {
        return Err(Error::Failed {
            label,
            status: output.status,
            log,
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() {
        return Err(Error::Malformed(label));
    }
    Ok(stdout)
}

#[derive(Debug)]
pub enum Error {
    Log(std::io::Error),
    Spawn(&'static str, std::io::Error),
    Failed {
        label: &'static str,
        status: ExitStatus,
        log: PathBuf,
    },
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Log(err) => write!(f, "opening task log: {err}"),
            Error::Spawn(label, err) => write!(f, "running {label}: {err}"),
            Error::Failed { label, status, log } => {
                write!(f, "{label} failed: {status} (see {})", log.display())
            }
            Error::Malformed(label) => write!(f, "unexpected {label} output"),
        }
    }
}

impl std::error::Error for Error {}
