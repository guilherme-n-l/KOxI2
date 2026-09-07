//! Build-input data files (kconfigs, patches, the VM init script).
//! Defaults are embedded in the binary at compile time so a bare koxi
//! binary is self-contained. Resolution order: a path declared in the
//! koxi.toml `[assets]` table (required to exist), then the
//! conventional override at `<project>/assets/<name>`, then the
//! embedded default. `koxi assets dump` materializes defaults into
//! the conventional location for editing.

use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::config::{Config, Project};
use crate::lock::Lock;
use crate::util;

pub struct Asset {
    pub name: &'static str,
    pub contents: &'static str,
}

/// Every embedded asset, addressed by its `assets/`-relative path.
pub const ASSETS: &[Asset] = &[
    Asset {
        name: "linux/config",
        contents: include_str!("../assets/linux/config"),
    },
    Asset {
        name: "linux/fuzz.config",
        contents: include_str!("../assets/linux/fuzz.config"),
    },
    Asset {
        name: "busybox/config",
        contents: include_str!("../assets/busybox/config"),
    },
    Asset {
        name: "syzkaller/generic.cfg",
        contents: include_str!("../assets/syzkaller/generic.cfg"),
    },
    Asset {
        name: "static/classify.toml",
        contents: include_str!("../assets/static/classify.toml"),
    },
    Asset {
        name: "virt/init",
        contents: include_str!("../assets/virt/init"),
    },
    Asset {
        name: "virt/udhcpc-script",
        contents: include_str!("../assets/virt/udhcpc-script"),
    },
    Asset {
        name: "virt/vm-driver-setup",
        contents: include_str!("../assets/virt/vm-driver-setup"),
    },
];

fn embedded(name: &str) -> Option<&'static Asset> {
    ASSETS.iter().find(|asset| asset.name == name)
}

/// Default override location: `<project>/assets/<name>`.
pub fn default_override_path(root: &Path, name: &str) -> PathBuf {
    root.join("assets").join(name)
}

/// Load an asset: the path declared in `koxi.toml` `[assets]` when
/// present (required to exist), else the conventional override at
/// `<project>/assets/<name>` when present, else the embedded default.
pub fn load(root: &Path, config: &Config, name: &str) -> Result<Cow<'static, str>, Error> {
    if let Some(declared) = config.assets.get(name) {
        let path = root.join(declared);
        return fs::read_to_string(&path)
            .map(Cow::Owned)
            .map_err(|err| Error::Override(path, err));
    }
    let conventional = default_override_path(root, name);
    if conventional.is_file() {
        return fs::read_to_string(&conventional)
            .map(Cow::Owned)
            .map_err(|err| Error::Override(conventional, err));
    }
    embedded(name)
        .map(|asset| Cow::Borrowed(asset.contents))
        .ok_or_else(|| Error::Unknown(name.to_owned()))
}

/// An asset loaded through the lock: its contents and content hash.
pub struct Loaded {
    pub contents: Cow<'static, str>,
    pub sha256: String,
}

/// Load an asset and record its sha256 in the lock (build steps
/// fingerprint on the hash, so a moved hash is staleness, not an
/// error).
pub fn load_locked(
    root: &Path,
    config: &Config,
    name: &str,
    lock: &mut Lock,
) -> Result<Loaded, Error> {
    let contents = load(root, config, name)?;
    let sha256 = util::sha256_bytes(contents.as_bytes());
    lock.assets.insert(name.to_owned(), sha256.clone());
    Ok(Loaded { contents, sha256 })
}

/// The `koxi assets` subcommand tree.
pub fn command() -> Command {
    Command::new("assets")
        .about("List and materialize embedded build-input defaults")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("list").about("List assets and where each resolves from"))
        .subcommand(
            Command::new("dump")
                .about("Write embedded defaults into <project>/assets for editing")
                .arg(
                    Arg::new("name")
                        .num_args(0..)
                        .help("Asset names (default: all)"),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Overwrite existing files"),
                ),
        )
}

pub fn run(matches: &ArgMatches) -> anyhow::Result<ExitCode> {
    match matches.subcommand() {
        Some(("list", _)) => list(),
        Some(("dump", sub)) => dump(sub)?,
        _ => unreachable!("subcommand is required"),
    }
    Ok(ExitCode::SUCCESS)
}

fn list() {
    let project = Project::locate().ok();
    for asset in ASSETS {
        let declared = project
            .as_ref()
            .and_then(|project| project.config.assets.get(asset.name));
        match (declared, &project) {
            (Some(path), _) => println!("declared  {} ({})", asset.name, path.display()),
            (None, Some(project)) if default_override_path(&project.root, asset.name).is_file() => {
                println!("override  {} (assets/{})", asset.name, asset.name);
            }
            _ => println!("embedded  {}", asset.name),
        }
    }
}

fn dump(matches: &ArgMatches) -> anyhow::Result<()> {
    let force = matches.get_flag("force");
    let root = Project::locate()?.root;

    let selected: Vec<&Asset> = match matches.get_many::<String>("name") {
        None => ASSETS.iter().collect(),
        Some(names) => names
            .map(|name| embedded(name).ok_or_else(|| Error::Unknown(name.clone())))
            .collect::<Result<_, _>>()?,
    };

    for asset in &selected {
        let path = default_override_path(&root, asset.name);
        anyhow::ensure!(
            force || !path.exists(),
            "{} exists (use --force to overwrite)",
            path.display()
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, asset.contents)?;
        println!("wrote {}", path.display());
    }

    println!("\nFiles under assets/ are picked up automatically; declare a");
    println!("custom path in the koxi.toml [assets] table to keep them elsewhere.");
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading declared asset override {path}: {err}", path = .0.display(), err = .1)]
    Override(PathBuf, std::io::Error),
    #[error("unknown asset {0}")]
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_assets_are_nonempty() {
        for asset in ASSETS {
            assert!(!asset.contents.is_empty(), "{} is empty", asset.name);
        }
        assert!(ASSETS.iter().any(|asset| asset.name == "linux/config"));
    }

    #[test]
    fn declared_override_wins_undeclared_uses_embedded() {
        let root = std::env::temp_dir().join(format!("koxi-assets-test-{}", std::process::id()));
        fs::create_dir_all(root.join("cfg")).unwrap();
        fs::write(root.join("cfg/custom.config"), "CONFIG_OVERRIDE=y\n").unwrap();

        let config = Config::parse(
            r#"
            [sources]
            [assets]
            "linux/config" = "cfg/custom.config"
            "#,
        )
        .unwrap();

        let overridden = load(&root, &config, "linux/config").unwrap();
        assert_eq!(overridden.as_ref(), "CONFIG_OVERRIDE=y\n");

        // Conventional override: assets/<name> under the project root,
        // no declaration needed.
        fs::create_dir_all(root.join("assets/virt")).unwrap();
        fs::write(root.join("assets/virt/init"), "#!/bin/sh\n").unwrap();
        let conventional = load(&root, &config, "virt/init").unwrap();
        assert_eq!(conventional.as_ref(), "#!/bin/sh\n");

        let fallback = load(&root, &config, "busybox/config").unwrap();
        assert!(!fallback.is_empty());

        let broken = Config::parse(
            r#"
            [sources]
            [assets]
            "virt/init" = "nope/missing"
            "#,
        )
        .unwrap();
        assert!(matches!(
            load(&root, &broken, "virt/init"),
            Err(Error::Override(..))
        ));

        assert!(load(&root, &config, "nope/nothing").is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_locked_records_the_hash() {
        let root = std::env::temp_dir().join(format!("koxi-assets-lock-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("init"), "one").unwrap();
        let config = Config::parse(
            r#"
            [sources]
            [assets]
            "virt/init" = "init"
            "#,
        )
        .unwrap();
        let mut lock = Lock::default();

        let first = load_locked(&root, &config, "virt/init", &mut lock).unwrap();
        assert_eq!(
            lock.assets["virt/init"], first.sha256,
            "first use is recorded"
        );
        let second = load_locked(&root, &config, "virt/init", &mut lock).unwrap();
        assert_eq!(first.sha256, second.sha256);

        fs::write(root.join("init"), "two").unwrap();
        let edited = load_locked(&root, &config, "virt/init", &mut lock).unwrap();
        assert_ne!(edited.sha256, first.sha256, "edited asset moves the hash");
        assert_eq!(lock.assets["virt/init"], edited.sha256);
        assert_eq!(edited.contents.as_ref(), "two");
        fs::remove_dir_all(&root).unwrap();
    }
}
