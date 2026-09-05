//! Acquire the VM userland sources declared in `koxi.toml`.

use std::path::PathBuf;

use crate::config::Config;
use crate::fetch;

/// Ensure the VM userland sources are present and verified; returns
/// the (busybox, dropbear) source trees.
pub fn setup(config: &Config) -> Result<(PathBuf, PathBuf), fetch::Error> {
    let busybox = fetch::tarball("busybox", config)?;
    let dropbear = fetch::tarball("dropbear", config)?;
    Ok((busybox, dropbear))
}
