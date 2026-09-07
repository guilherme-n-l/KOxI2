//! `koxi.toml` — user-edited harness configuration: shared third-party
//! component sources at the top level, class-specific configuration under
//! per-class tables (`[block]`, ...).

use std::collections::BTreeMap;
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
    /// Bare-metal target for kexec boots (`[baremetal]`).
    #[serde(default)]
    pub baremetal: Option<BaremetalConfig>,
    /// Block-harness configuration (`[block]`).
    #[serde(default)]
    pub block: BlockConfig,
}

/// A kexec-capable bare-metal target (see `koxi metal`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BaremetalConfig {
    /// ssh destination of the resident OS (user@host).
    pub host: String,
    /// koxi.net= value for the test kernel (default: dhcp).
    #[serde(default)]
    pub net: Option<String>,
    /// Where the test kernel's dropbear answers; defaults to the
    /// host part of `host` (same MAC usually keeps the same lease).
    #[serde(default)]
    pub guest_addr: Option<String>,
    /// Extra kernel cmdline appended after console/koxi.net.
    #[serde(default)]
    pub append: Option<String>,
}

/// Project-declared toolchain for builds. The --cc flag (or CC env)
/// overrides `cc` for one-off runs.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    /// Toolchain for the kernel build: gnu or llvm (default: gnu).
    #[serde(default)]
    pub toolchain: Option<Toolchain>,
    /// C compiler name or path, overriding the toolchain's default
    /// (gcc for gnu, clang for llvm).
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

/// Everything block-specific: the driver registry (v1 `drivers.cfg`)
/// and the static-analysis window.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockConfig {
    #[serde(default)]
    pub drivers: BTreeMap<String, Driver>,
    #[serde(default, rename = "static")]
    pub static_: StaticConfig,
}

/// `[block.static]` — commit-mining bounds. The since date is
/// absolute so the mined window is reproducible (v1 used a floating
/// "4 years ago" against GitHub's moving HEAD).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticConfig {
    #[serde(default)]
    pub since: Option<String>,
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
    /// Kernel-tree-relative paths of the shared abstraction layer
    /// this driver leans on (files or directories); the static phase
    /// counts their unsafe surface separately so a "0 unsafe" driver
    /// body cannot hide unsafe pushed one layer down.
    #[serde(default)]
    pub abstractions: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    C,
    Rs,
}

/// Which toolchain builds the kernel. `LLVM=1` is not a value of `cc`:
/// it swaps the assembler, the linker and the whole binutils set
/// together, so it is a selection of its own with `cc` left as the
/// narrow override *within* it (clang-21 instead of clang, say).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Toolchain {
    #[default]
    Gnu,
    Llvm,
}

impl Toolchain {
    /// The C compiler the toolchain implies when `cc` is not set.
    pub fn default_cc(self) -> &'static str {
        match self {
            Self::Gnu => "gcc",
            Self::Llvm => "clang",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Gnu => "gnu",
            Self::Llvm => "llvm",
        }
    }

    /// A compiler the *environment* names for this toolchain, used
    /// when nothing else does. It exists because the bare name on PATH
    /// is not always the right binary: the kernel's freestanding
    /// sub-builds (realmode, the EFI stub) rebuild KBUILD_CFLAGS from
    /// scratch, so no user-append variable reaches them, and a clang
    /// wrapper that injects `-nostdlibinc` therefore cannot compile
    /// them under `-Werror`. Only the target compiler is affected --
    /// HOSTCC still wants the wrapper, and `LLVM=1` picks that up from
    /// PATH on its own.
    pub fn env_cc(self) -> Option<String> {
        let key = match self {
            Self::Gnu => "KOXI_GNU_CC",
            Self::Llvm => "KOXI_LLVM_CC",
        };
        std::env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    /// The make variables that select it. `LLVM=1` is what kbuild
    /// documents (Documentation/kbuild/llvm.rst); there is no
    /// corresponding variable for the GNU chain, which is the default.
    pub fn make_vars(self) -> &'static [&'static str] {
        match self {
            Self::Gnu => &[],
            Self::Llvm => &["LLVM=1"],
        }
    }
}

/// The knob layer parses env values with `raw.parse::<T>()` and clap
/// resolves `value_parser!` through `FromStr` too, so a knob whose type
/// is not a std primitive has to provide this. Accepts the compiler
/// names as aliases because `--toolchain clang` is what a reader of
/// kbuild's llvm.rst will reach for.
impl std::str::FromStr for Toolchain {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim().to_ascii_lowercase().as_str() {
            "gnu" | "gcc" => Ok(Self::Gnu),
            "llvm" | "clang" => Ok(Self::Llvm),
            other => Err(format!("expected gnu or llvm, got {other:?}")),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let text = fs::read_to_string(path)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let config: Self = toml::from_str(text)?;
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

/// Resolve a CLI-relative default path under the project root;
/// explicit absolute paths pass through.
pub fn anchored(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
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
        let cwd = std::env::current_dir()?;
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
    #[error("no {config} found (searched from {} upward)", .0.display(), config = CONFIG_PATH)]
    NoProject(PathBuf),
}

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
    fn baremetal_section_parses() {
        let config = Config::parse(
            "[sources]\n[baremetal]\nhost = \"guilh@laptop.local\"\nnet = \"dhcp\"\n",
        )
        .unwrap();
        let baremetal = config.baremetal.unwrap();
        assert_eq!(baremetal.host, "guilh@laptop.local");
        assert_eq!(baremetal.net.as_deref(), Some("dhcp"));
        assert!(Config::parse("[sources]").unwrap().baremetal.is_none());
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
