//! Acquire the syzkaller checkout declared in `koxi.toml`, pinned to
//! the locked commit.

use std::path::PathBuf;

use crate::config::Config;
use crate::fetch;

/// Ensure the syzkaller checkout is present at the locked commit;
/// returns its path.
pub fn setup(config: &Config) -> Result<PathBuf, fetch::Error> {
    fetch::git("syzkaller", config)
}
