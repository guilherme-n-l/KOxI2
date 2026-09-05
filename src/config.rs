//! `koxi.toml` — user-edited harness configuration: shared third-party
//! component sources at the top level, class-specific configuration under
//! per-class tables (`[block]`, ...).

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Default config path, relative to the working directory.
pub const CONFIG_PATH: &str = "koxi.toml";

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub sources: BTreeMap<String, Source>,
    /// Build-input overrides: asset name → file path, relative to the
    /// project root. Undeclared assets use the embedded defaults.
    #[serde(default)]
    pub assets: BTreeMap<String, PathBuf>,
    /// Toolchain declaration (`[build]`).
    #[serde(default)]
    pub build: BuildConfig,
    /// Block-harness configuration (`[block]`).
    #[serde(default)]
    pub block: BlockConfig,
}

/// Project-declared toolchain for builds. The --cc flag (or CC env)
/// overrides `cc` for one-off runs.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// C compiler name or path (default: gcc).
    #[serde(default)]
    pub cc: Option<String>,
    /// Build target arch in kbuild vocabulary (default: x86_64).
    #[serde(default)]
    pub target: Option<String>,
    /// Extra kernel-tree files to harvest into artifacts/ after the
    /// build (paths relative to the tree root, e.g. vmlinux for
    /// syzkaller symbolization). Unlike registry modules these are
    /// explicit requests: a missing file fails the build.
    #[serde(rename = "extra-artifacts", default)]
    pub extra_artifacts: Vec<PathBuf>,
}

/// Everything block-specific: the driver registry (v1 `drivers.cfg`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockConfig {
    #[serde(default)]
    pub drivers: BTreeMap<String, Driver>,
}

/// Where a third-party component comes from.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum Source {
    Tarball {
        version: String,
        url: String,
    },
    Git {
        git: String,
        /// Required pin: a commit hash or tag. `setup` resolves it to an
        /// exact commit recorded in `koxi.lock`.
        rev: String,
    },
    /// History-only mirror: cloned bare with blobs filtered out and
    /// never checked out. For commit mining, not for building.
    GitMeta {
        #[serde(rename = "git-meta")]
        git_meta: String,
        /// Required pin, as in [`Source::Git`].
        rev: String,
    },
}

/// One driver registry entry (v1 `[drivers "<name>"]`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Driver {
    pub role: Role,
    pub ko: String,
    pub ko_dir: PathBuf,
    pub device: PathBuf,
    pub gitpath: PathBuf,
    #[serde(default)]
    pub insmod: Option<String>,
    #[serde(default)]
    pub prep: Option<String>,
    #[serde(default)]
    pub configfs: Option<String>,
    #[serde(default)]
    pub configfs_params: Option<String>,
    /// C driver this Rust driver replaces (v1 `[pairs]`).
    #[serde(default)]
    pub pair: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    C,
    Rs,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path).map_err(Error::Io)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text).map_err(Error::Parse)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Error> {
        for (name, driver) in &self.block.drivers {
            match (driver.role, &driver.pair) {
                (Role::C, Some(_)) => {
                    return Err(Error::Invalid(format!(
                        "driver {name}: only Rust drivers take a pair"
                    )));
                }
                (Role::Rs, Some(pair)) => match self.block.drivers.get(pair) {
                    None => {
                        return Err(Error::Invalid(format!(
                            "driver {name}: pair {pair} is not in the registry"
                        )));
                    }
                    Some(paired) if paired.role != Role::C => {
                        return Err(Error::Invalid(format!(
                            "driver {name}: pair {pair} is not a C driver"
                        )));
                    }
                    Some(_) => {}
                },
                _ => {}
            }
        }
        Ok(())
    }
}

/// A located project: the directory holding `koxi.toml`, which anchors
/// `koxi.lock` and the `out/` cache regardless of the working directory.
#[derive(Debug)]
pub struct Project {
    pub root: PathBuf,
    pub config: Config,
}

impl Project {
    /// Search for `koxi.toml` upward from the working directory,
    /// cargo-style. Artifacts do not live here — see
    /// `fetch::koxi_home` for the global cache.
    pub fn locate() -> Result<Self, Error> {
        let cwd = std::env::current_dir().map_err(Error::Io)?;
        for dir in cwd.ancestors() {
            if let Some(project) = Self::at(dir)? {
                return Ok(project);
            }
        }
        Err(Error::NoProject(cwd))
    }

    fn at(dir: &Path) -> Result<Option<Self>, Error> {
        let candidate = dir.join(CONFIG_PATH);
        if !candidate.is_file() {
            return Ok(None);
        }
        Ok(Some(Self {
            root: dir.to_owned(),
            config: Config::load(&candidate)?,
        }))
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(String),
    NoProject(PathBuf),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "reading config: {err}"),
            Error::Parse(err) => write!(f, "parsing config: {err}"),
            Error::Invalid(msg) => write!(f, "invalid config: {msg}"),
            Error::NoProject(cwd) => write!(
                f,
                "no {CONFIG_PATH} found (searched from {} upward)",
                cwd.display()
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_config_parses() {
        let config = Config::parse(include_str!("../koxi.toml")).unwrap();
        assert!(config.block.drivers.contains_key("null_blk"));
        assert_eq!(
            config.block.drivers["rnull"].pair.as_deref(),
            Some("null_blk")
        );
        assert!(config.sources.contains_key("linux"));
    }

    #[test]
    fn build_section_parses() {
        let config = Config::parse(
            r#"
            [sources]
            [build]
            cc = "clang"
            target = "x86_64"
            extra-artifacts = ["vmlinux", "System.map"]
            "#,
        )
        .unwrap();
        assert_eq!(config.build.cc.as_deref(), Some("clang"));
        assert_eq!(config.build.target.as_deref(), Some("x86_64"));
        assert_eq!(config.build.extra_artifacts.len(), 2);
        assert_eq!(Config::parse("[sources]").unwrap().build.cc, None);
    }

    #[test]
    fn git_meta_source_parses_and_requires_rev() {
        let config = Config::parse(
            r#"
            [sources.linux-meta]
            git-meta = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
            rev = "v6.19"
            "#,
        )
        .unwrap();
        assert!(matches!(
            config.sources["linux-meta"],
            Source::GitMeta { .. }
        ));
        assert!(Config::parse(
            r#"
            [sources.linux-meta]
            git-meta = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
            "#,
        )
        .is_err());
    }

    #[test]
    fn git_source_requires_rev() {
        let err = Config::parse(
            r#"
            [sources.syzkaller]
            git = "https://github.com/google/syzkaller.git"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
    }

    #[test]
    fn pair_must_reference_registered_c_driver() {
        let err = Config::parse(
            r#"
            [sources]
            [block.drivers.rnull]
            role = "rs"
            ko = "rnull_mod.ko"
            ko-dir = "drivers/block/rnull/"
            device = "/dev/rnullb0"
            gitpath = "drivers/block/rnull/"
            pair = "missing"
            "#,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }
}
