//! Block-device-driver instantiation of KOxI, mirroring v1 `block/`.

pub mod cli;
pub mod compare;
pub mod fio;
pub mod fuzz;
pub mod perf;
pub mod results;
pub mod setup;
pub mod static_analysis;
pub mod test;

use std::path::Path;
use std::process::ExitCode;

use anyhow::{anyhow, Context};
use clap::ArgMatches;
use tracing::{info, warn};

use cli::{
    BuildOpts, CompareOpts, FioOpts, FuzzOpts, Profile, RunOpts, Scope, ScreenOpts, StaticOpts,
};

use crate::cli::{Globals, GuestOpts, VmOpts};
use crate::config::{Config, Driver, Role};
use crate::host;

/// Dispatch a parsed `koxi block <command>` invocation. Each arm
/// resolves exactly the option groups its subcommand declares, so an
/// invalid env var for a knob this verb never reads stays harmless.
pub fn run(matches: &ArgMatches, globals: &Globals, logs: &Path) -> anyhow::Result<ExitCode> {
    let (name, sub) = matches.subcommand().expect("subcommand is required");
    match name {
        "setup" => setup::drive(&BuildOpts::from_matches(sub)?, globals.yes, logs)?,
        "test" => test::drive(&BuildOpts::cc_or_default(sub)?, logs)?,
        "perf" => {
            let profile = Profile::from_matches(sub)?;
            perf::drive(
                &RunOpts::from_matches(sub)?,
                profile,
                &VmOpts::from_matches(sub)?,
                &FioOpts::with_profile(sub, profile)?,
                globals.yes,
                logs,
            )?;
        }
        "fuzz" => {
            let profile = Profile::from_matches(sub)?;
            fuzz::drive(
                &RunOpts::from_matches(sub)?,
                profile,
                &GuestOpts::from_matches(sub)?,
                &FuzzOpts::with_profile(sub, profile)?,
                globals.yes,
                logs,
            )?;
        }
        "static" => static_analysis::drive(
            &RunOpts::from_matches(sub)?,
            &StaticOpts::from_matches(sub)?,
            globals.yes,
            logs,
        )?,
        "screen" => {
            compare::screen::drive(&Scope::from_matches(sub)?, &ScreenOpts::from_matches(sub)?)?;
        }
        "compare" => compare::drive(
            &Scope::from_matches(sub)?,
            &cli::require_campaign(sub)?,
            &CompareOpts::from_matches(sub)?,
        )?,
        "all" => all(sub, globals, logs)?,
        other => unreachable!("unknown block subcommand {other}"),
    }
    Ok(ExitCode::SUCCESS)
}

/// The whole pipeline in phase order; each phase already handles p1
/// baselines and the p2 campaign itself (phase-aware), screening
/// lands before compare so the verdict can fold it in. The campaign
/// name is minted once here — the phases must agree on it, or the
/// comparator has nothing to compare.
fn all(matches: &ArgMatches, globals: &Globals, logs: &Path) -> anyhow::Result<()> {
    let profile = Profile::from_matches(matches)?;
    let mut run = RunOpts::from_matches(matches)?;
    let campaign = run.campaign(crate::util::unix_now());
    run.campaign = Some(campaign.clone());
    let vm = VmOpts::from_matches(matches)?;
    let fio = FioOpts::with_profile(matches, profile)?;
    let fuzz_opts = FuzzOpts::with_profile(matches, profile)?;
    let static_opts = StaticOpts::from_matches(matches)?;
    let compare_opts = CompareOpts::from_matches(matches)?;

    let phase = |name: &str| info!("=== koxi block {name} ===");
    phase("static");
    static_analysis::drive(&run, &static_opts, globals.yes, logs).context("static phase")?;
    phase("perf");
    perf::drive(&run, profile, &vm, &fio, globals.yes, logs).context("perf phase")?;
    phase("fuzz");
    fuzz::drive(&run, profile, &vm.guest, &fuzz_opts, globals.yes, logs).context("fuzz phase")?;
    phase("screen");
    compare::screen::drive(&run.scope, &compare_opts.screen).context("screen phase")?;
    phase("compare");
    compare::drive(&run.scope, &campaign, &compare_opts).context("compare phase")
}

/// One registered (rs, c) driver pair: the Rust driver under study
/// and the C driver it replaces.
pub(crate) struct DriverPair<'c> {
    pub rs_name: &'c str,
    pub rs: &'c Driver,
    pub c_name: &'c str,
    pub c: &'c Driver,
}

/// Every registered (rs, c) driver pair, filtered by --only on the
/// C driver name (the Rust pair follows, v1-style).
pub(crate) fn driver_pairs<'c>(config: &'c Config, only: &[String]) -> Vec<DriverPair<'c>> {
    config
        .block
        .drivers
        .iter()
        .filter(|(_, driver)| driver.role == Role::Rs)
        .filter_map(|(rs_name, rs)| {
            let c_name = rs.pair.as_ref()?;
            let c = config.block.drivers.get(c_name)?;
            Some(DriverPair {
                rs_name,
                rs,
                c_name,
                c,
            })
        })
        .filter(|pair| only.is_empty() || only.iter().any(|name| name == pair.c_name))
        .collect()
}

/// Refuse hosts whose numbers would be fiction: TCG timing, or more
/// guest memory than the machine has. `--quick` is the smoke-run
/// escape (it keeps v1's TCG warning), `--allow-unfit-host` the
/// explicit one.
pub(crate) fn check_host(profile: Profile, memory: &str, smp: u32, vms: u32) -> anyhow::Result<()> {
    if profile.quick {
        if host::accel() == "tcg" {
            warn!("no KVM on this host — TCG numbers are smoke-only, never thesis data");
        }
        return Ok(());
    }
    let vm_memory = host::parse_memory(memory)
        .ok_or_else(|| anyhow!("cannot parse --memory {memory} as a size"))?;
    let demand = host::Demand {
        vms: u64::from(vms),
        vm_memory,
        smp: u64::from(smp),
    };
    match host::check(&host::probe(), &demand) {
        Ok(()) => Ok(()),
        Err(unfit) if profile.allow_unfit_host => {
            warn!("--allow-unfit-host: {unfit}");
            Ok(())
        }
        Err(unfit) => Err(unfit.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn campaign_profile(allow_unfit_host: bool) -> Profile {
        Profile {
            quick: false,
            longrun: false,
            allow_unfit_host,
        }
    }

    #[test]
    fn the_host_gate_reads_the_geometry_and_honors_its_escapes() {
        // Geometry that cannot be parsed is an error before the host
        // is ever probed.
        assert!(check_host(campaign_profile(false), "lots", 4, 1).is_err());
        // The escapes never block, on a fit host or an unfit one.
        assert!(check_host(campaign_profile(true), "4G", 4, 1).is_ok());
        assert!(check_host(
            Profile {
                quick: true,
                ..campaign_profile(false)
            },
            "lots",
            4,
            1
        )
        .is_ok());
    }
}
