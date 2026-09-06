//! Build-input data files (kconfigs, patches, the VM init script).
//! Defaults are embedded in the binary at compile time so a bare koxi
//! binary is self-contained. Resolution order: a path declared in the
//! koxi.toml `[assets]` table (required to exist), then the
//! conventional override at `<project>/assets/<name>`, then the
//! embedded default. `koxi assets dump` materializes defaults into
//! the conventional location for editing.

use std::borrow::Cow;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode, Stdio};

use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::config::{Config, Project};
use crate::lock::Lock;

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
        name: "syzkaller/generic.cfg.in",
        contents: include_str!("../assets/syzkaller/generic.cfg.in"),
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

/// An asset loaded through the lock: its contents, content hash, and
/// whether it changed since the previous recorded use.
pub struct Loaded {
    pub contents: Cow<'static, str>,
    pub sha256: String,
    /// True on first use and whenever the hash moved.
    pub changed: bool,
}

/// Load an asset and record its sha256 in the lock.
pub fn load_locked(
    root: &Path,
    config: &Config,
    name: &str,
    lock: &mut Lock,
) -> Result<Loaded, Error> {
    let contents = load(root, config, name)?;
    let sha256 = sha256_text(&contents)?;
    let changed = lock.assets.get(name) != Some(&sha256);
    if changed {
        lock.assets.insert(name.to_owned(), sha256.clone());
    }
    Ok(Loaded {
        contents,
        sha256,
        changed,
    })
}

/// sha256 of a string via the host sha256sum (same tool the rest of
/// the pipeline trusts for artifact hashing).
pub fn sha256_text(text: &str) -> Result<String, Error> {
    let mut child = Process::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Error::Sha)?;
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(text.as_bytes())
        .map_err(Error::Sha)?;
    let output = child.wait_with_output().map_err(Error::Sha)?;
    if !output.status.success() {
        return Err(Error::ShaFailed(output.status));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or(Error::ShaFailed(output.status))
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

pub fn run(matches: &ArgMatches) -> ExitCode {
    match matches.subcommand() {
        Some(("list", _)) => list(),
        Some(("dump", sub)) => dump(sub),
        _ => unreachable!("subcommand is required"),
    }
}

fn list() -> ExitCode {
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
    ExitCode::SUCCESS
}

fn dump(matches: &ArgMatches) -> ExitCode {
    let force = matches.get_flag("force");
    let root = match Project::locate() {
        Ok(project) => project.root,
        Err(err) => return fail(err),
    };

    let selected: Vec<&Asset> = match matches.get_many::<String>("name") {
        None => ASSETS.iter().collect(),
        Some(names) => {
            let mut picked = Vec::new();
            for name in names {
                match embedded(name) {
                    Some(asset) => picked.push(asset),
                    None => return fail(Error::Unknown(name.clone())),
                }
            }
            picked
        }
    };

    for asset in &selected {
        let path = default_override_path(&root, asset.name);
        if path.exists() && !force {
            return fail(format!(
                "{} exists (use --force to overwrite)",
                path.display()
            ));
        }
        if let Some(parent) = path.parent() {
            if let Err(err) = fs::create_dir_all(parent) {
                return fail(err);
            }
        }
        if let Err(err) = fs::write(&path, asset.contents) {
            return fail(err);
        }
        println!("wrote {}", path.display());
    }

    println!("\nFiles under assets/ are picked up automatically; declare a");
    println!("custom path in the koxi.toml [assets] table to keep them elsewhere.");
    ExitCode::SUCCESS
}

fn fail(err: impl fmt::Display) -> ExitCode {
    eprintln!("koxi assets: {err}");
    ExitCode::FAILURE
}

#[derive(Debug)]
pub enum Error {
    Override(PathBuf, std::io::Error),
    Unknown(String),
    Sha(std::io::Error),
    ShaFailed(std::process::ExitStatus),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Override(path, err) => {
                write!(
                    f,
                    "reading declared asset override {}: {err}",
                    path.display()
                )
            }
            Error::Unknown(name) => write!(f, "unknown asset {name}"),
            Error::Sha(err) => write!(f, "running sha256sum: {err}"),
            Error::ShaFailed(status) => write!(f, "sha256sum failed: {status}"),
        }
    }
}

impl std::error::Error for Error {}

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
    fn load_locked_records_and_detects_changes() {
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
        assert!(first.changed, "first use counts as changed");
        let second = load_locked(&root, &config, "virt/init", &mut lock).unwrap();
        assert!(!second.changed, "unchanged asset is not stale");
        assert_eq!(first.sha256, second.sha256);

        fs::write(root.join("init"), "two").unwrap();
        let edited = load_locked(&root, &config, "virt/init", &mut lock).unwrap();
        assert!(edited.changed, "edited asset is stale");
        assert_eq!(edited.contents.as_ref(), "two");
        fs::remove_dir_all(&root).unwrap();
    }
}
