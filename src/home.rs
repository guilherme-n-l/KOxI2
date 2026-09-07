//! The koxi home (`$KOXI_HOME`, default `~/.koxi`), shared across
//! projects cargo-style: its layout, the cross-process cache lock
//! that serializes fetches, extractions, and garbage collection, and
//! the collector itself.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

use tracing::info;

/// Reusable downloads: tarballs, extracted source trees, git
/// checkouts and history mirrors (`koxi clean --cache` collects).
pub const CACHE_DIR: &str = "cache";

/// Per-build scratch (see [`crate::scratch`]).
pub const TMP_DIR: &str = "tmp";

/// `log/<project>/<run-id>/` run logs.
pub const LOG_DIR: &str = "log";

/// Lock file inside the cache; never removed by the collector (the
/// lock is the inode, so unlinking it would let a second run in).
const CACHE_LOCK: &str = ".lock";

#[derive(Debug, thiserror::Error)]
#[error("cannot determine the koxi home: set KOXI_HOME or HOME")]
pub struct NoHome;

/// The global artifact home: `$KOXI_HOME`, defaulting to `~/.koxi`.
pub fn koxi_home() -> Result<PathBuf, NoHome> {
    if let Some(home) = std::env::var_os("KOXI_HOME") {
        return Ok(PathBuf::from(home));
    }
    std::env::var_os("HOME")
        .map(|home| Path::new(&home).join(".koxi"))
        .ok_or(NoHome)
}

/// Exclusive advisory lock over the cache, held by any run that
/// fetches, extracts, or collects. Released when dropped or when the
/// holder dies, so a killed run never wedges the cache.
#[derive(Debug)]
pub struct CacheLock {
    _file: File,
}

impl CacheLock {
    /// Take the lock, waiting (with a note on the console) when
    /// another koxi run holds it.
    pub fn acquire(home: &Path) -> io::Result<Self> {
        let cache = home.join(CACHE_DIR);
        fs::create_dir_all(&cache)?;
        let path = cache.join(CACHE_LOCK);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                info!(
                    "waiting for the cache lock at {} (another koxi run holds it)",
                    path.display()
                );
                file.lock()?;
            }
            Err(TryLockError::Error(err)) => return Err(err),
        }
        Ok(Self { _file: file })
    }
}

/// What the collector would do: cache entries (files or directories
/// directly under `cache/`) to remove versus the referenced ones.
#[derive(Debug, Default)]
pub struct GcPlan {
    pub remove: Vec<PathBuf>,
    pub keep: Vec<PathBuf>,
}

/// Plan a collection keeping only the entry names in `referenced`
/// (see `fetch::cache_entries`); the lock file is never a candidate.
/// Call with the [`CacheLock`] held.
pub fn gc_plan(home: &Path, referenced: &BTreeSet<String>) -> io::Result<GcPlan> {
    let cache = home.join(CACHE_DIR);
    let mut plan = GcPlan::default();
    if !cache.is_dir() {
        return Ok(plan);
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&cache)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<io::Result<_>>()?;
    entries.sort();
    for path in entries {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name == CACHE_LOCK {
            continue;
        }
        if referenced.contains(&name) {
            plan.keep.push(path);
        } else {
            plan.remove.push(path);
        }
    }
    Ok(plan)
}

/// Remove every entry the plan marks; returns the bytes freed.
pub fn gc_apply(plan: &GcPlan) -> io::Result<u64> {
    let mut freed = 0;
    for path in &plan.remove {
        freed += size_of(path);
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(freed)
}

/// Apparent size of a file or tree (best effort, for the report).
pub fn size_of(path: &Path) -> u64 {
    if path.is_dir() {
        fs::read_dir(path).map_or(0, |entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| size_of(&entry.path()))
                .sum()
        })
    } else {
        fs::symlink_metadata(path).map_or(0, |meta| meta.len())
    }
}

/// Human-readable byte count for reports.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_lock_excludes_a_second_holder() {
        let home = tempfile::tempdir().unwrap();
        let held = CacheLock::acquire(home.path()).unwrap();
        let path = home.path().join(CACHE_DIR).join(CACHE_LOCK);
        let probe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            matches!(probe.try_lock(), Err(TryLockError::WouldBlock)),
            "second holder must block while the lock is held"
        );
        drop(held);
        assert!(
            eventually(|| probe.try_lock().is_ok()),
            "the lock is released when its holder drops"
        );
    }

    /// Poll for a second: dropping a lock closes its fd, but a
    /// sibling thread that forks a subprocess right then duplicates
    /// every open fd (CLOEXEC only fires at exec), so the release can
    /// land a hair after the close.
    fn eventually(mut ready: impl FnMut() -> bool) -> bool {
        (0..100).any(|_| {
            if ready() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            false
        })
    }

    #[test]
    fn gc_keeps_referenced_entries_and_the_lock_file() {
        let home = tempfile::tempdir().unwrap();
        let _lock = CacheLock::acquire(home.path()).unwrap();
        let cache = home.path().join(CACHE_DIR);
        fs::write(cache.join("linux-6.19.tar.xz"), "x").unwrap();
        fs::create_dir_all(cache.join("linux-6.19")).unwrap();
        fs::write(cache.join(".linux-6.19.extracted"), "").unwrap();
        fs::write(cache.join("linux-6.18.tar.xz"), "old").unwrap();
        fs::create_dir_all(cache.join("syzkaller")).unwrap();

        let referenced: BTreeSet<String> =
            ["linux-6.19.tar.xz", "linux-6.19", ".linux-6.19.extracted"]
                .iter()
                .map(|name| (*name).to_owned())
                .collect();
        let plan = gc_plan(home.path(), &referenced).unwrap();
        let removed: Vec<String> = plan
            .remove
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(removed, vec!["linux-6.18.tar.xz", "syzkaller"]);
        assert_eq!(plan.keep.len(), 3);

        gc_apply(&plan).unwrap();
        assert!(cache.join(CACHE_LOCK).is_file(), "lock file survives");
        assert!(cache.join("linux-6.19.tar.xz").is_file());
        assert!(!cache.join("linux-6.18.tar.xz").exists());
        assert!(!cache.join("syzkaller").exists());
    }

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
