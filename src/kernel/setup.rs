//! Acquire the kernel source tree declared in `koxi.toml` (see
//! `crate::fetch` for the cache/lock/extract mechanics).

use std::path::PathBuf;

use crate::config::Config;
use crate::fetch;

/// Ensure the kernel source is present and verified; returns its path.
pub fn setup(config: &Config) -> Result<PathBuf, fetch::Error> {
    fetch::tarball("linux", config)
}
