//! Acquire the fio source declared in `koxi.toml` — the block-class
//! benchmark workload generator.

use std::path::PathBuf;

use crate::fetch::{self, Ctx};

/// Ensure the fio source is present and verified; returns its path.
pub fn setup(ctx: &mut Ctx) -> Result<PathBuf, fetch::Error> {
    fetch::tarball("fio", ctx)
}
