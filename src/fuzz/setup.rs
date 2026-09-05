//! Acquire the syzkaller checkout declared in `koxi.toml`, pinned to
//! the locked commit.

use std::path::PathBuf;

use crate::fetch::{self, Ctx};

/// Ensure the syzkaller checkout is present at the locked commit;
/// returns its path.
pub fn setup(ctx: &mut Ctx) -> Result<PathBuf, fetch::Error> {
    fetch::git("syzkaller", ctx)
}
