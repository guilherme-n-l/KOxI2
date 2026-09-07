//! `koxi init` and `koxi new` — starting a project.
//!
//! A KOxI project is a directory holding a `koxi.toml`; everything
//! else (the lock, the artifacts, the results) is generated. `init`
//! writes that file into a directory you already have, `new` makes
//! the directory first. `--nix` adds the flake that pins the runtime
//! shell, which is the only supported way to get every tool the
//! pipeline shells out to at the versions it was tested against.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context};
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

/// A file a fresh project starts with: where it lands, and what goes
/// in it.
struct Template {
    name: &'static str,
    contents: &'static str,
    /// Written only for `--nix`, which is opt-in because a project
    /// may already have its own flake or not use nix at all.
    nix_only: bool,
}

const TEMPLATES: &[Template] = &[
    Template {
        name: "koxi.toml",
        contents: include_str!("../templates/koxi.toml"),
        nix_only: false,
    },
    Template {
        name: ".gitignore",
        contents: include_str!("../templates/gitignore"),
        nix_only: false,
    },
    Template {
        name: "flake.nix",
        contents: include_str!("../templates/koxi/flake.nix"),
        nix_only: true,
    },
];

fn nix_arg() -> Arg {
    Arg::new("nix")
        .long("nix")
        .action(ArgAction::SetTrue)
        .help("Also write a flake pinning the koxi runtime shell")
}

fn force_arg() -> Arg {
    Arg::new("force")
        .long("force")
        .action(ArgAction::SetTrue)
        .help("Overwrite files that already exist")
}

pub fn init_command() -> Command {
    Command::new("init")
        .about("Write a starter koxi.toml into the current directory")
        .arg(nix_arg())
        .arg(force_arg())
}

pub fn new_command() -> Command {
    Command::new("new")
        .about("Create a project directory with a starter koxi.toml")
        .arg(
            Arg::new("path")
                .required(true)
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .help("Directory to create"),
        )
        .arg(nix_arg())
        .arg(force_arg())
}

pub fn init(matches: &ArgMatches) -> anyhow::Result<ExitCode> {
    scaffold(
        Path::new("."),
        matches.get_flag("nix"),
        matches.get_flag("force"),
    )?;
    Ok(ExitCode::SUCCESS)
}

pub fn new(matches: &ArgMatches) -> anyhow::Result<ExitCode> {
    let root = matches.get_one::<PathBuf>("path").expect("required");
    let force = matches.get_flag("force");
    // An existing empty directory is fine to fill; an existing
    // non-empty one is somebody's project, so say so rather than
    // scattering files through it.
    if root.exists() {
        let occupied = fs::read_dir(root)
            .with_context(|| format!("reading {}", root.display()))?
            .next()
            .is_some();
        if occupied && !force {
            bail!(
                "{} already exists and is not empty (use --force to write into it anyway)",
                root.display()
            );
        }
    }
    fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    scaffold(root, matches.get_flag("nix"), force)?;
    println!("\nnext: cd {}", root.display());
    Ok(ExitCode::SUCCESS)
}

/// Write the starting files into `root`, skipping any that exist
/// unless `force`.
fn scaffold(root: &Path, nix: bool, force: bool) -> anyhow::Result<()> {
    let mut wrote_flake = false;
    for template in TEMPLATES {
        if template.nix_only && !nix {
            continue;
        }
        let path = root.join(template.name);
        if path.exists() && !force {
            println!(
                "skipped {} (exists; use --force to overwrite)",
                template.name
            );
            continue;
        }
        fs::write(&path, template.contents)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("wrote {}", template.name);
        wrote_flake |= template.nix_only;
    }

    println!("\nedit koxi.toml to register the driver you care about, then:");
    if wrote_flake {
        println!("  nix develop    # koxi plus every tool the pipeline needs");
    } else {
        println!("  # `koxi init --nix` adds a flake pinning the runtime shell");
    }
    println!("  koxi block test");
    println!("  koxi block setup");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_starter_config_is_a_valid_config() {
        // The template is documentation that has to keep parsing:
        // a comment typo that breaks it would only surface for
        // whoever ran `koxi new` next.
        let config = crate::config::Config::parse(include_str!("../templates/koxi.toml"))
            .expect("starter koxi.toml parses");
        assert!(
            config.sources.contains_key("linux"),
            "a project needs its kernel source pinned to build anything"
        );
        let pair = &config.block.drivers["rnull"];
        assert_eq!(pair.pair.as_deref(), Some("null_blk"));
        assert!(
            !pair.abstractions.is_empty(),
            "the example shows how to declare an abstraction layer"
        );
    }

    #[test]
    fn init_writes_the_starter_files_and_nix_is_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        scaffold(dir.path(), false, false).unwrap();
        assert!(dir.path().join("koxi.toml").is_file());
        assert!(dir.path().join(".gitignore").is_file());
        assert!(!dir.path().join("flake.nix").exists(), "--nix is opt-in");

        scaffold(dir.path(), true, false).unwrap();
        assert!(dir.path().join("flake.nix").is_file());
    }

    #[test]
    fn an_existing_file_survives_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("koxi.toml");
        fs::write(&config, "# mine\n").unwrap();

        scaffold(dir.path(), false, false).unwrap();
        assert_eq!(fs::read_to_string(&config).unwrap(), "# mine\n");

        scaffold(dir.path(), false, true).unwrap();
        assert_ne!(fs::read_to_string(&config).unwrap(), "# mine\n");
    }
}
