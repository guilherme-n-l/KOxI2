//! Acquire the kernel source tree declared in `koxi.toml` (see
//! `crate::fetch` for the cache/lock/extract mechanics).

use std::path::PathBuf;

use crate::fetch::{self, Ctx};

/// Ensure the kernel source is present and verified; returns its path.
pub fn setup(ctx: &mut Ctx) -> Result<PathBuf, fetch::Error> {
    fetch::tarball("linux", ctx)
}

/// Ensure the kernel history mirror (bare, metadata-only) is present
/// for commit mining; returns the repo path.
pub fn history(ctx: &mut Ctx) -> Result<PathBuf, fetch::Error> {
    fetch::git_meta("linux-meta", ctx)
}
