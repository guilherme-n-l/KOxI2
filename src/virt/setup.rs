//! Acquire the VM userland sources declared in `koxi.toml`.

use std::path::PathBuf;

use crate::fetch::{self, Ctx};

/// Ensure the VM userland sources are present and verified; returns
/// the (busybox, dropbear) source trees.
pub fn setup(ctx: &mut Ctx) -> Result<(PathBuf, PathBuf), fetch::Error> {
    let busybox = fetch::tarball("busybox", ctx)?;
    let dropbear = fetch::tarball("dropbear", ctx)?;
    Ok((busybox, dropbear))
}
