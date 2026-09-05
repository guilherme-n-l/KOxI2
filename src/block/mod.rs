//! Block-device-driver instantiation of KOxI, mirroring v1 `block/`.

pub mod cli;
pub mod fio;
pub mod setup;
pub mod test;

use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::ArgMatches;

use cli::Opts;

use crate::config::Project;

/// Dispatch a parsed `koxi block <command>` invocation.
pub fn run(matches: &ArgMatches) -> ExitCode {
    let (name, sub) = matches.subcommand().expect("subcommand is required");
    let mut opts = Opts::from_matches(sub);
    // Anchor the default logfile to the global koxi home instead of
    // the working directory; explicit --logfile paths are honored as
    // given.
    if sub.value_source("logfile") == Some(ValueSource::DefaultValue) {
        if let Ok(home) = crate::fetch::koxi_home() {
            opts.logfile = home.join(&opts.logfile);
        }
    }
    crate::logging::init(
        opts.verbose,
        opts.debug,
        (!opts.nologfile).then_some(opts.logfile.as_path()),
    );
    match name {
        "setup" => setup::setup(&opts),
        "test" => test::test(&opts),
        "clean" => clean(&opts),
        "perf" => perf(&opts),
        "fuzz" => fuzz(&opts),
        "static" => static_analysis(&opts),
        "screen" => screen(&opts),
        "compare" => compare(&opts),
        "debug" => debug(&opts),
        "all" => all(&opts),
        other => unreachable!("unknown block subcommand {other}"),
    }
}

fn clean(_opts: &Opts) -> ExitCode {
    not_implemented("clean")
}

fn perf(_opts: &Opts) -> ExitCode {
    not_implemented("perf")
}

fn fuzz(_opts: &Opts) -> ExitCode {
    not_implemented("fuzz")
}

fn static_analysis(_opts: &Opts) -> ExitCode {
    not_implemented("static")
}

fn screen(_opts: &Opts) -> ExitCode {
    not_implemented("screen")
}

fn compare(_opts: &Opts) -> ExitCode {
    not_implemented("compare")
}

fn debug(_opts: &Opts) -> ExitCode {
    not_implemented("debug")
}

fn all(_opts: &Opts) -> ExitCode {
    not_implemented("all")
}

fn not_implemented(name: &str) -> ExitCode {
    eprintln!("koxi block {name}: not implemented yet");
    ExitCode::FAILURE
}
