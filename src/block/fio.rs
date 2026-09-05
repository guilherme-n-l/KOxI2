//! Acquire the fio source declared in `koxi.toml` — the block-class
//! benchmark workload generator.

use std::path::PathBuf;

use crate::config::Config;
use crate::fetch;

/// Ensure the fio source is present and verified; returns its path.
pub fn setup(config: &Config) -> Result<PathBuf, fetch::Error> {
    fetch::tarball("fio", config)
}
