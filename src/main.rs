mod assets;
mod block;
mod clean;
mod cli;
mod cmd;
mod config;
mod fetch;
mod fuzz;
mod home;
mod host;
mod kernel;
mod lock;
mod logging;
mod metal;
mod nix;
mod scratch;
mod stats;
mod util;
mod virt;
mod vm;

use std::path::Path;
use std::process::ExitCode;

use clap::{ArgMatches, Command};

fn command() -> Command {
    Command::new("koxi")
        .about("Kernel Oxidation Instrument")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .args(cli::logging_args())
        .arg(cli::yes_arg())
        .subcommand(block::cli::command())
        .subcommand(assets::command())
        .subcommand(clean::command())
        .subcommand(metal::command())
        .subcommand(nix::command())
        .subcommand(vm::command())
}

/// Subcommands that drive subprocesses keep a run log under the koxi
/// home; the housekeeping ones stay console-only.
fn keeps_run_log(name: &str) -> bool {
    matches!(name, "block" | "vm" | "metal")
}

fn main() -> ExitCode {
    let matches = command().get_matches();
    let (name, sub) = matches.subcommand().expect("subcommand is required");
    let globals = match cli::Globals::from_matches(&matches) {
        Ok(globals) => globals,
        Err(err) => {
            eprintln!("koxi: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Per-run log directory: log/<project-label>/<run-id> under the
    // koxi home; the default logfile lives inside it, while explicit
    // --logfile paths are honored as given.
    let logs = logging::run_log_dir();
    let logfile = if globals.nologfile || !keeps_run_log(name) {
        None
    } else {
        Some(
            globals
                .logfile
                .clone()
                .unwrap_or_else(|| logs.join("run.log")),
        )
    };
    logging::init(globals.verbose, globals.debug, logfile.as_deref());
    // Run header: lands in the run log (TRACE sink) without console
    // noise at the default level.
    tracing::debug!(
        "koxi {} | argv {:?} | cwd {} | logs {}",
        env!("CARGO_PKG_VERSION"),
        std::env::args().collect::<Vec<_>>(),
        std::env::current_dir().map_or_else(|_| "?".into(), |cwd| cwd.display().to_string()),
        logs.display()
    );

    let result = dispatch(name, sub, &globals, &logs);
    match result {
        Ok(code) => code,
        Err(err) => {
            // The failing verb, not just its tree: "koxi block perf".
            let verb = sub
                .subcommand_name()
                .map_or_else(|| name.to_owned(), |leaf| format!("{name} {leaf}"));
            tracing::error!("koxi {verb}: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(
    name: &str,
    sub: &ArgMatches,
    globals: &cli::Globals,
    logs: &Path,
) -> anyhow::Result<ExitCode> {
    match name {
        "block" => block::run(sub, globals, logs),
        "assets" => assets::run(sub),
        "clean" => clean::run(sub, globals),
        "metal" => metal::run(sub, globals),
        "nix" => nix::run(sub),
        "vm" => vm::run(sub, logs),
        other => unreachable!("unknown subcommand {other}"),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_is_well_formed() {
        super::command().debug_assert();
    }

    #[test]
    fn globals_propagate_to_nested_subcommands() {
        let matches =
            super::command().get_matches_from(["koxi", "block", "setup", "--yes", "--verbose"]);
        let globals = super::cli::Globals::from_matches(&matches).unwrap();
        assert!(globals.yes);
        assert!(globals.verbose);
        let matches = super::command().get_matches_from(["koxi", "--yes", "metal", "boot"]);
        assert!(super::cli::Globals::from_matches(&matches).unwrap().yes);
    }
}
