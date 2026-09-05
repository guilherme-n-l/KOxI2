mod block;
mod config;
mod lock;

use std::process::ExitCode;

use clap::Command;

fn command() -> Command {
    Command::new("koxi")
        .about("Kernel Oxidation Instrument")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(block::cli::command())
}

fn main() -> ExitCode {
    let matches = command().get_matches();
    match matches.subcommand() {
        Some(("block", sub)) => block::run(sub),
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
