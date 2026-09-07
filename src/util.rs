//! Small helpers that several modules used to hand-roll: time,
//! rounding, hashing, in-memory CSV rendering, filesystem walks,
//! tool probes, and the yes/no prompt.

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tracing::info;

/// Seconds since the Unix epoch (0 when the clock predates it).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Python-style rounding for JSON output shapes (half away from
/// zero). NaN passes through and serializes as null.
pub fn round(value: f64, decimals: i32) -> f64 {
    let factor = 10f64.powi(decimals);
    (value * factor).round() / factor
}

/// Build parallelism: every hardware thread, at least one.
pub fn jobs() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

/// Render a CSV in memory. Writing to a Vec cannot fail on io, so
/// the only error left is a programming one (ragged records).
pub fn csv_text(write: impl FnOnce(&mut csv::Writer<Vec<u8>>) -> csv::Result<()>) -> String {
    let mut out = csv::Writer::from_writer(Vec::new());
    write(&mut out).expect("in-memory csv writer only fails on ragged records");
    let bytes = out
        .into_inner()
        .expect("in-memory csv writer flushes without io");
    String::from_utf8(bytes).expect("csv of utf-8 fields is utf-8")
}

/// Lowercase hex sha256 of a file, streamed.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut fs::File::open(path)?, &mut hasher)?;
    Ok(hex(&hasher.finalize()))
}

/// Lowercase hex sha256 of an in-memory buffer.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// First line of `program args...` stdout, or `fallback` when the
/// program is missing or fails — toolchain identity for fingerprints.
pub fn probe_version(program: &str, args: &[&str], fallback: &str) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| fallback.to_owned())
}

/// Every regular file under `root` (a file path passes through),
/// recursively, sorted for determinism. `keep` filters by path.
pub fn files_under(root: &Path, keep: impl Fn(&Path) -> bool) -> io::Result<Vec<PathBuf>> {
    if root.is_file() {
        return Ok(if keep(root) {
            vec![root.to_owned()]
        } else {
            Vec::new()
        });
    }
    let mut files = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if keep(&path) {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[derive(Debug, thiserror::Error)]
pub enum ConfirmError {
    #[error("{0} — confirmation needed but stdin is not a terminal; rerun with --yes")]
    NotATerminal(String),
    #[error("reading confirmation: {0}")]
    Io(#[from] io::Error),
}

/// Yes/no prompt on stderr; `--yes` answers without asking, and a
/// non-interactive stdin is an error rather than a silent no.
pub fn confirm(prompt: &str, assume_yes: bool) -> Result<bool, ConfirmError> {
    if assume_yes {
        info!("{prompt} — assuming yes (--yes)");
        return Ok(true);
    }
    if !io::stdin().is_terminal() {
        return Err(ConfirmError::NotATerminal(prompt.to_owned()));
    }
    eprint!("{prompt} [y/N] ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abc");
        fs::write(&path, "abc").unwrap();
        assert_eq!(sha256_file(&path).unwrap(), sha256_bytes(b"abc"));
    }

    #[test]
    fn rounding_is_python_like() {
        assert_eq!(round(2.345, 2), 2.35);
        assert_eq!(round(-14.0, 2), -14.0);
        assert!(round(f64::NAN, 2).is_nan());
    }

    #[test]
    fn files_under_recurses_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("b/inner")).unwrap();
        fs::write(dir.path().join("b/inner/z.rs"), "").unwrap();
        fs::write(dir.path().join("a.c"), "").unwrap();
        fs::write(dir.path().join("b/y.rs"), "").unwrap();
        let with_extension = |ext: &'static str| {
            move |path: &Path| path.extension().is_some_and(|found| found == ext)
        };
        let rs = files_under(dir.path(), with_extension("rs")).unwrap();
        assert_eq!(
            rs,
            vec![dir.path().join("b/inner/z.rs"), dir.path().join("b/y.rs")]
        );
        assert_eq!(
            files_under(dir.path(), with_extension("c")).unwrap().len(),
            1
        );
        assert_eq!(
            files_under(&dir.path().join("a.c"), with_extension("c")).unwrap(),
            vec![dir.path().join("a.c")]
        );
        // Everything, unfiltered, is what the crash-bucket walk wants.
        assert_eq!(files_under(dir.path(), |_| true).unwrap().len(), 3);
    }
}
