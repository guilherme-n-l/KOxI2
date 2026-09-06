//! Block-device-driver instantiation of KOxI, mirroring v1 `block/`.

pub mod cli;
pub mod fio;
pub mod fuzz;
pub mod perf;
pub mod results;
pub mod setup;
pub mod test;

use std::process::ExitCode;

use clap::parser::ValueSource;
use clap::ArgMatches;

use cli::Opts;

use crate::config::Project;
use crate::logging::run_log_dir;

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
    // Run header: lands in the run log (TRACE sink) without console
    // noise at the default level.
    tracing::debug!(
        "koxi {} | argv {:?} | cwd {} | logs {}",
        env!("CARGO_PKG_VERSION"),
        std::env::args().collect::<Vec<_>>(),
        std::env::current_dir().map_or_else(|_| "?".into(), |cwd| cwd.display().to_string()),
        logs.display()
    );
    match name {
        "setup" => setup::setup(&opts, &logs),
        "test" => test::test(&opts, &logs),
        "clean" => clean(&opts),
        "perf" => perf::perf(&opts, &logs),
        "fuzz" => fuzz::fuzz(&opts, &logs),
        "static" => static_analysis(&opts),
        "screen" => screen(&opts),
        "compare" => compare(&opts),
        "debug" => debug(&opts),
        "all" => all(&opts),
        other => unreachable!("unknown block subcommand {other}"),
    }
}

/// Remove the project's built artifacts (artifacts/); results and
/// the shared home are untouched (orphaned scratch is `koxi clean`,
/// the download cache is --nocache).
fn clean(_opts: &Opts) -> ExitCode {
    let project = match Project::locate() {
        Ok(project) => project,
        Err(err) => {
            eprintln!("koxi block clean: {err}");
            return ExitCode::FAILURE;
        }
    };
    let artifacts = project.root.join(crate::kernel::build::ARTIFACTS_DIR);
    if artifacts.exists() {
        if let Err(err) = std::fs::remove_dir_all(&artifacts) {
            eprintln!("koxi block clean: {err}");
            return ExitCode::FAILURE;
        }
        println!("removed {}", artifacts.display());
    } else {
        println!("nothing to clean ({} absent)", artifacts.display());
    }
    ExitCode::SUCCESS
}

/// Every registered (rs, c) driver pair, filtered by --only on the
/// C driver name (the Rust pair follows, v1-style).
pub(crate) fn driver_pairs<'c>(
    config: &'c crate::config::Config,
    only: &[String],
) -> Vec<(
    &'c String,
    &'c crate::config::Driver,
    &'c String,
    &'c crate::config::Driver,
)> {
    config
        .block
        .drivers
        .iter()
        .filter(|(_, driver)| driver.role == crate::config::Role::Rs)
        .filter_map(|(rs_name, rs_driver)| {
            let c_name = rs_driver.pair.as_ref()?;
            let c_driver = config.block.drivers.get(c_name)?;
            Some((rs_name, rs_driver, c_name, c_driver))
        })
        .filter(|(_, _, c_name, _)| only.is_empty() || only.contains(c_name))
        .collect()
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
