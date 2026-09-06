//! `koxi block compare` — diff a p2 campaign against its p1
//! baselines (v1 `compare/compare`). Manifest-first: each domain dir
//! under the campaign records the identity hash of the baseline it
//! was measured against, so the comparator resolves
//! `results/p1/<c>/<domain>/<hash>/` from data, not symlinks, and
//! refuses to pool results whose identities disagree on host/accel.
//! Gate outputs land in `<campaign>/compare/` in v1's JSON shapes.

pub mod fuzz;
pub mod perf;

use std::path::Path;
use std::process::ExitCode;

use tracing::{error, info, warn};

use crate::block::cli::Opts;
use crate::block::results::{self, Manifest};
use crate::config::{anchored, Project};

pub fn compare(opts: &Opts, logs: &Path) -> ExitCode {
    match drive(opts, logs) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("koxi block compare: {err}");
            ExitCode::FAILURE
        }
    }
}

fn drive(opts: &Opts, _logs: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let campaign = opts
        .campaign
        .as_deref()
        .ok_or("compare requires --campaign <name>")?;
    let project = Project::locate()?;
    let results_root = anchored(&project.root, &opts.output);

    let pairs = super::driver_pairs(&project.config, &opts.only);
    if pairs.is_empty() {
        return Err("no matching driver pairs in the [block.drivers] registry".into());
    }

    let mut compared = 0;
    for (rs_name, _, c_name, _) in pairs {
        let campaign_root = results_root
            .join("p2")
            .join(format!("{c_name}::{rs_name}"))
            .join(campaign);
        if !campaign_root.is_dir() {
            warn!(
                "no campaign data for {c_name}::{rs_name} at {}",
                campaign_root.display()
            );
            continue;
        }
        let compare_dir = campaign_root.join("compare");
        std::fs::create_dir_all(&compare_dir)?;

        // Performance gate.
        match load_domain(&results_root, &campaign_root, c_name, "perf")? {
            Some((p2_dir, p1_dir, manifest)) => {
                info!("compare perf: {} vs {}", p1_dir.display(), p2_dir.display());
                perf::compare_perf(&p1_dir, &p2_dir, &manifest, opts, &compare_dir)?;
                compared += 1;
            }
            None => info!("perf comparison: missing perf data; skipping"),
        }

        // Fuzzing gate.
        match load_domain(&results_root, &campaign_root, c_name, "fuzz")? {
            Some((p2_dir, p1_dir, manifest)) => {
                info!("compare fuzz: {} vs {}", p1_dir.display(), p2_dir.display());
                fuzz::compare_fuzz(
                    &p1_dir,
                    &p2_dir,
                    &manifest,
                    opts,
                    &compare_dir,
                    c_name,
                    rs_name,
                )?;
                compared += 1;
            }
            None => info!("fuzz comparison: missing fuzz data; skipping"),
        }

        // The safety comparator lands with the static analysis port.
        if campaign_root.join("static").is_dir() {
            info!("static comparison not ported yet; skipping");
        }
    }
    if compared == 0 {
        return Err("no domains available for comparison".into());
    }
    Ok(())
}

/// Resolve a campaign domain dir and its recorded baseline. Errors
/// when data exists but is unusable (incomplete or identity-skewed);
/// Ok(None) when the domain was simply never run.
fn load_domain(
    results_root: &Path,
    campaign_root: &Path,
    c_name: &str,
    domain: &str,
) -> Result<Option<(std::path::PathBuf, std::path::PathBuf, Manifest)>, Box<dyn std::error::Error>>
{
    let p2_dir = campaign_root.join(domain);
    let Some(manifest) = Manifest::load(&p2_dir)? else {
        return Ok(None);
    };
    if !manifest.complete {
        return Err(format!(
            "{} is incomplete; re-run the {domain} phase",
            p2_dir.display()
        )
        .into());
    }
    let Some(p2) = &manifest.p2 else {
        return Err(format!("{} has no campaign record", p2_dir.display()).into());
    };
    let p1_dir = results::p1_dir(results_root, c_name, domain, &p2.baseline);
    let Some(baseline) = Manifest::load(&p1_dir)? else {
        return Err(format!(
            "baseline {} missing for {} — re-run the {domain} phase",
            p1_dir.display(),
            p2_dir.display()
        )
        .into());
    };
    if !baseline.complete {
        return Err(format!("baseline {} is incomplete", p1_dir.display()).into());
    }
    // Same-substrate guard: the identity carries host+accel exactly
    // so cross-machine or KVM-vs-TCG data can never be pooled.
    if baseline.identity.host != manifest.identity.host
        || baseline.identity.accel != manifest.identity.accel
    {
        return Err(format!(
            "baseline and campaign ran on different substrates ({}/{:?} vs {}/{:?})",
            baseline.identity.host,
            baseline.identity.accel,
            manifest.identity.host,
            manifest.identity.accel
        )
        .into());
    }
    Ok(Some((p2_dir, p1_dir, manifest)))
}
