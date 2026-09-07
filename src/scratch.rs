//! Per-run scratch directories under `$KOXI_HOME/tmp`: unique per
//! use, removed on success, kept on failure for debugging, and marked
//! live with an advisory lock so `koxi clean` can tell a running
//! build from an orphan left by a killed process. The lock dies with
//! the process (SIGKILL, power loss), so liveness never goes stale.
//! Scratch lives under the home rather than the system /tmp, which is
//! often RAM-backed tmpfs — too small for a kernel tree.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use tracing::warn;

use crate::home::TMP_DIR;

/// The liveness marker inside every scratch dir; its exclusive lock
/// is held for the scratch's whole lifetime.
pub const LIVE_MARKER: &str = ".koxi-live";

/// A live scratch directory. Dropping it removes the tree; `keep`
/// disarms that for post-mortems.
#[derive(Debug)]
pub struct Scratch {
    dir: Option<TempDir>,
    _live: File,
}

impl Scratch {
    /// Create `<home>/tmp/<prefix>XXXXXX` and mark it live.
    pub fn new(home: &Path, prefix: &str) -> io::Result<Self> {
        let root = home.join(TMP_DIR);
        fs::create_dir_all(&root)?;
        let dir = tempfile::Builder::new().prefix(prefix).tempdir_in(&root)?;
        let live = File::create(dir.path().join(LIVE_MARKER))?;
        live.lock()?;
        Ok(Self {
            dir: Some(dir),
            _live: live,
        })
    }

    pub fn path(&self) -> &Path {
        self.dir.as_ref().expect("scratch is alive").path()
    }

    /// Disarm removal so the tree survives for debugging; the
    /// liveness lock lapses with this process, after which `koxi
    /// clean` sweeps it like any other orphan.
    pub fn keep(mut self) -> PathBuf {
        let kept = self.dir.take().expect("scratch is alive").keep();
        warn!("scratch kept for debugging at {}", kept.display());
        kept
    }

    /// Run `body` against the scratch path; on error the tree is kept.
    pub fn run<T, E>(self, body: impl FnOnce(&Path) -> Result<T, E>) -> Result<T, E> {
        match body(self.path()) {
            Ok(value) => Ok(value),
            Err(err) => {
                self.keep();
                Err(err)
            }
        }
    }
}

/// Outcome of a sweep: what was removed and what was left alone
/// because a running koxi still holds it.
#[derive(Debug, Default)]
pub struct Sweep {
    pub removed: Vec<PathBuf>,
    pub live: Vec<PathBuf>,
}

/// Remove every scratch dir under `<home>/tmp` that no process holds
/// live. Safe to run alongside builds: theirs are skipped.
pub fn sweep(home: &Path) -> io::Result<Sweep> {
    let root = home.join(TMP_DIR);
    let mut sweep = Sweep::default();
    if !root.is_dir() {
        return Ok(sweep);
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&root)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<_>>()?;
    entries.sort();
    for path in entries {
        if is_live(&path)? {
            sweep.live.push(path);
            continue;
        }
        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        sweep.removed.push(path);
    }
    Ok(sweep)
}

/// Whether some process holds the scratch's liveness lock. Entries
/// without a marker (pre-marker koxi, stray files) count as dead.
fn is_live(dir: &Path) -> io::Result<bool> {
    let marker = dir.join(LIVE_MARKER);
    let file = match OpenOptions::new().read(true).write(true).open(&marker) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err),
    };
    match file.try_lock() {
        Ok(()) => {
            file.unlock()?;
            Ok(false)
        }
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(err)) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_removes_and_failure_keeps() {
        let home = tempfile::tempdir().unwrap();
        let scratch = Scratch::new(home.path(), "ok-").unwrap();
        let path = scratch.path().to_owned();
        assert!(path.join(LIVE_MARKER).is_file());
        let value: Result<u32, ()> = scratch.run(|dir| {
            assert_eq!(dir, path);
            Ok(7)
        });
        assert_eq!(value, Ok(7));
        assert!(!path.exists(), "success removes the scratch");

        let scratch = Scratch::new(home.path(), "bad-").unwrap();
        let path = scratch.path().to_owned();
        let failed: Result<(), &str> = scratch.run(|_| Err("boom"));
        assert_eq!(failed, Err("boom"));
        assert!(path.is_dir(), "failure keeps the scratch");
    }

    #[test]
    fn sweep_skips_live_scratch_and_removes_orphans() {
        let home = tempfile::tempdir().unwrap();
        let live = Scratch::new(home.path(), "live-").unwrap();
        let orphan = home.path().join(TMP_DIR).join("orphan-abc");
        fs::create_dir_all(&orphan).unwrap();
        fs::write(orphan.join(LIVE_MARKER), "").unwrap();
        let legacy = home.path().join(TMP_DIR).join("legacy-xyz");
        fs::create_dir_all(&legacy).unwrap();

        let result = sweep(home.path()).unwrap();
        assert_eq!(result.live, vec![live.path().to_owned()]);
        assert_eq!(result.removed.len(), 2);
        assert!(live.path().is_dir());
        assert!(!orphan.exists());
        assert!(!legacy.exists());

        // Dropping the scratch closes its liveness fd, but a
        // sibling thread forking a subprocess right then duplicates
        // every open fd (CLOEXEC only fires at exec), so the release
        // can land a hair after the close.
        drop(live);
        let swept = (0..100).any(|_| {
            if sweep(home.path()).unwrap().live.is_empty() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        });
        assert!(swept, "a dropped scratch stops counting as live");
    }
}
