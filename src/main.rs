mod assets;
mod block;
mod clean;
mod cmd;
mod config;
mod fetch;
mod fuzz;
mod kernel;
mod lock;
mod logging;
mod nix;
mod virt;

use std::process::ExitCode;

use clap::Command;

fn command() -> Command {
    Command::new("koxi")
        .about("Kernel Oxidation Instrument")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(block::cli::command())
        .subcommand(assets::command())
        .subcommand(clean::command())
        .subcommand(nix::command())
}

fn main() -> ExitCode {
    let matches = command().get_matches();
    match matches.subcommand() {
        Some(("block", sub)) => block::run(sub),
        Some(("assets", sub)) => assets::run(sub),
        Some(("clean", _)) => clean::run(),
        Some(("nix", sub)) => nix::run(sub),
        _ => unreachable!("subcommand is required"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_is_well_formed() {
        super::command().debug_assert();
    }
}
