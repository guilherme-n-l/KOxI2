//! `koxi nix` — nix integration helpers.
//!
//! `init` materializes the runtime flake template plus a starter
//! koxi.toml into the current directory: the offline equivalent of
//! `nix flake init -t github:guilherme-n-l/KOxI2#koxi`.

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};

const TEMPLATE_FILES: &[(&str, &str)] = &[
    ("flake.nix", include_str!("../templates/koxi/flake.nix")),
    ("koxi.toml", include_str!("../koxi.toml")),
];

pub fn command() -> Command {
    Command::new("nix")
        .about("Nix integration helpers")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("init")
                .about("Write the runtime flake and a starter koxi.toml here")
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
        Some(("init", sub)) => init(sub.get_flag("force")),
        _ => unreachable!("subcommand is required"),
    }
}

fn init(force: bool) -> ExitCode {
    for (name, contents) in TEMPLATE_FILES {
        let path = Path::new(name);
        if path.exists() && !force {
            println!("skipped {name} (exists; use --force to overwrite)");
            continue;
        }
        if let Err(err) = fs::write(path, contents) {
            eprintln!("koxi nix init: writing {name}: {err}");
            return ExitCode::FAILURE;
        }
        println!("wrote {name}");
    }
    println!("\nnext: nix develop    # then: koxi block test && koxi block setup");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_files_are_nonempty() {
        for (name, contents) in TEMPLATE_FILES {
            assert!(!contents.is_empty(), "{name} is empty");
        }
    }
}
