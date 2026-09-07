//! `koxi clean` — housekeeping over the shared home and the project:
//! dead build scratch (always; live builds are skipped by their
//! liveness lock), the download cache (`--cache`: entries this
//! project's lock does not reference), and the project's built
//! artifacts (`--artifacts`). Results are never touched.

use std::collections::BTreeSet;
use std::fs;
use std::process::ExitCode;

use anyhow::{bail, Context};
use clap::{Arg, ArgAction, ArgMatches, Command};
use tracing::info;

use crate::cli::Globals;
use crate::config::Project;
use crate::home::{self, CacheLock};
use crate::kernel::build::ARTIFACTS_DIR;
use crate::lock::{Lock, LOCK_PATH};
use crate::util::confirm;
use crate::{fetch, scratch};

/// "1 entry" but "2 entries": the sweep reports counts to a human.
fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Keeps the sweep's own scope apart from the root globals in help.
const SCOPE: &str = "Scope";

pub fn command() -> Command {
    Command::new("clean")
        .about("Sweep dead build scratch; optionally the cache and the project's artifacts")
        .arg(
            Arg::new("cache")
                .long("cache")
                .action(ArgAction::SetTrue)
                .help_heading(SCOPE)
                .help("Also remove cache entries this project's koxi.lock does not reference"),
        )
        .arg(
            Arg::new("artifacts")
                .long("artifacts")
                .action(ArgAction::SetTrue)
                .help_heading(SCOPE)
                .help("Also remove the project's built artifacts (artifacts/; results preserved)"),
        )
        .arg(
            Arg::new("all")
                .long("all")
                .action(ArgAction::SetTrue)
                .help_heading(SCOPE)
                .help("Everything above"),
        )
}

pub fn run(matches: &ArgMatches, globals: &Globals) -> anyhow::Result<ExitCode> {
    let all = matches.get_flag("all");
    let cache = all || matches.get_flag("cache");
    let artifacts = all || matches.get_flag("artifacts");
    let home = home::koxi_home()?;

    let swept = scratch::sweep(&home)?;
    for path in &swept.removed {
        println!("removed {} (dead build scratch)", path.display());
    }
    for path in &swept.live {
        println!("kept    {} (a running koxi holds it)", path.display());
    }
    if swept.removed.is_empty() && swept.live.is_empty() {
        println!(
            "no build scratch under {}",
            home.join(home::TMP_DIR).display()
        );
    }

    if cache {
        collect_cache(&home, globals.yes)?;
    }
    if artifacts {
        let project = Project::locate().context("--artifacts needs a project")?;
        let dir = project.root.join(ARTIFACTS_DIR);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
            println!("removed {}", dir.display());
        } else {
            println!("nothing to clean ({} absent)", dir.display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Garbage-collect the shared cache down to what this project's lock
/// references. Other projects sharing the home re-fetch what they
/// lose, which is the trade the shared cache always made.
fn collect_cache(home: &std::path::Path, assume_yes: bool) -> anyhow::Result<()> {
    let project =
        Project::locate().context("--cache needs a project (its koxi.lock says what to keep)")?;
    // An absent lock is not an empty lock. Defaulting here would make
    // "we have no record of what this project needs" indistinguishable
    // from "this project needs nothing", and the sweep would then
    // propose the entire cache -- which is shared with every other
    // project under this KOXI_HOME, and goes without a prompt under
    // --yes.
    let Some(lock) = Lock::load(&project.root.join(LOCK_PATH))? else {
        bail!(
            "{} has no {LOCK_PATH}, so there is no record of which cache entries it needs; \
             run `koxi block setup` first (the cache is shared across projects)",
            project.root.display()
        );
    };
    let referenced: BTreeSet<String> = lock
        .sources
        .iter()
        .flat_map(|(name, source)| fetch::cache_entries(name, source))
        .collect();

    let _guard = CacheLock::acquire(home)?;
    let plan = home::gc_plan(home, &referenced)?;
    if plan.remove.is_empty() {
        println!(
            "cache is clean ({} referenced entries under {})",
            plan.keep.len(),
            home.join(home::CACHE_DIR).display()
        );
        return Ok(());
    }
    let total: u64 = plan.remove.iter().map(|path| home::size_of(path)).sum();
    println!("unreferenced cache entries ({}):", home::human_size(total));
    for path in &plan.remove {
        println!("  {}", path.display());
    }
    if !confirm("remove them?", assume_yes)? {
        info!("cache left as is");
        return Ok(());
    }
    let freed = home::gc_apply(&plan)?;
    println!(
        "removed {} ({} freed); {} kept",
        plural(plan.remove.len(), "entry", "entries"),
        home::human_size(freed),
        plan.keep.len()
    );
    Ok(())
}
