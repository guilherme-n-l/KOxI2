//! Block-device-driver instantiation of KOxI, mirroring v1 `block/`.

pub mod cli;
pub mod fio;
pub mod setup;
pub mod test;

use std::process::ExitCode;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::parser::ValueSource;
use clap::ArgMatches;

use cli::Opts;

use crate::config::Project;

/// Dispatch a parsed `koxi block <command>` invocation.
pub fn run(matches: &ArgMatches) -> ExitCode {
    let (name, sub) = matches.subcommand().expect("subcommand is required");
    let mut opts = Opts::from_matches(sub);
    // Per-run log directory: log/<project-label>/<run-id> under the
    // koxi home; the default logfile lives inside it, while explicit
    // --logfile paths are honored as given.
    let logs = run_log_dir();
    if sub.value_source("logfile") == Some(ValueSource::DefaultValue) {
        opts.logfile = logs.join("run.log");
    }
    crate::logging::init(
        opts.verbose,
        opts.debug,
        (!opts.nologfile).then_some(opts.logfile.as_path()),
    );
    match name {
        "setup" => setup::setup(&opts, &logs),
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

/// `log/<project-label>/<run-id>` under the koxi home, with the
/// project label derived from the project root path (or "global"
/// outside a project). Falls back to a relative `log/` dir when the
/// home cannot be determined.
fn run_log_dir() -> PathBuf {
    let label = match Project::locate() {
        Ok(project) => project
            .root
            .display()
            .to_string()
            .replace(['/', '\\'], "-")
            .trim_start_matches('-')
            .to_owned(),
        Err(_) => "global".to_owned(),
    };
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let base = crate::fetch::koxi_home().unwrap_or_else(|_| PathBuf::from("."));
    base.join("log").join(label).join(run_id.to_string())
}

fn not_implemented(name: &str) -> ExitCode {
    eprintln!("koxi block {name}: not implemented yet");
    ExitCode::FAILURE
}
