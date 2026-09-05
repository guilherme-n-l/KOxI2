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
    /// Block-harness configuration (`[block]`).
    #[serde(default)]
    pub block: BlockConfig,
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

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "reading config: {err}"),
            Error::Parse(err) => write!(f, "parsing config: {err}"),
            Error::Invalid(msg) => write!(f, "invalid config: {msg}"),
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
