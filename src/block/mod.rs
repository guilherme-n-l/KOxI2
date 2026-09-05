//! Block-device-driver instantiation of KOxI, mirroring v1 `block/`.

pub mod cli;
pub mod fio;
pub mod setup;

use setup::setup;
use std::process::ExitCode;

use clap::ArgMatches;

/// Dispatch a parsed `koxi block <command>` invocation.
pub fn run(matches: &ArgMatches) -> ExitCode {
    let (name, sub) = matches.subcommand().expect("subcommand is required");
    match name {
        "setup" => setup(sub),
        "test" => test(sub),
        "clean" => clean(sub),
        "perf" => perf(sub),
        "fuzz" => fuzz(sub),
        "static" => static_analysis(sub),
        "screen" => screen(sub),
        "compare" => compare(sub),
        "debug" => debug(sub),
        "all" => all(sub),
        other => unreachable!("unknown block subcommand {other}"),
    }
}

fn test(_matches: &ArgMatches) -> ExitCode {
    not_implemented("test")
}

fn clean(_matches: &ArgMatches) -> ExitCode {
    not_implemented("clean")
}

fn perf(_matches: &ArgMatches) -> ExitCode {
    not_implemented("perf")
}

fn fuzz(_matches: &ArgMatches) -> ExitCode {
    not_implemented("fuzz")
}

fn static_analysis(_matches: &ArgMatches) -> ExitCode {
    not_implemented("static")
}

fn screen(_matches: &ArgMatches) -> ExitCode {
    not_implemented("screen")
}

fn compare(_matches: &ArgMatches) -> ExitCode {
    not_implemented("compare")
}

fn debug(_matches: &ArgMatches) -> ExitCode {
    not_implemented("debug")
}

fn all(_matches: &ArgMatches) -> ExitCode {
    setup(_matches)
}

fn not_implemented(name: &str) -> ExitCode {
    eprintln!("koxi block {name}: not implemented yet");
    ExitCode::FAILURE
}
