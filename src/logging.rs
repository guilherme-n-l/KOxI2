//! Two-sink logging: a quiet human console on stderr (level driven by
//! `--verbose`/`--debug`) and an always-verbose run log file.
//! Subprocess output does not go through here — `fetch` tees it to
//! per-task files under `out/logs/`.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// `log/<project-label>/<run-id>` under the koxi home, with the
/// project label derived from the project root path (or "global"
/// outside a project). Falls back to a relative `log/` dir when the
/// home cannot be determined.
pub fn run_log_dir() -> PathBuf {
    let label = match crate::config::Project::locate() {
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

/// Install the global subscriber. `logfile: None` means console only
/// (`--nologfile`); a file that cannot be opened degrades to console
/// only with a warning rather than failing the run.
pub fn init(verbose: bool, debug: bool, logfile: Option<&Path>) {
    let console_filter = if debug {
        LevelFilter::TRACE
    } else if verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let console = fmt::layer()
        .with_writer(io::stderr)
        .without_time()
        .with_target(false)
        .with_filter(console_filter);

    let file = logfile.and_then(|path| {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        match OpenOptions::new().create(true).append(true).open(path) {
            Ok(file) => Some(
                fmt::layer()
                    .with_writer(Arc::new(file))
                    .with_ansi(false)
                    .with_filter(LevelFilter::TRACE),
            ),
            Err(err) => {
                eprintln!("warning: cannot open log file {}: {err}", path.display());
                None
            }
        }
    });

    tracing_subscriber::registry()
        .with(console)
        .with(file)
        .init();
}
