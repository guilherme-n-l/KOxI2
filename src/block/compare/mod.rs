//! `koxi block compare` — diff a p2 campaign against its p1
//! baselines (v1 `compare/compare`). Manifest-first: each domain dir
//! under the campaign records the identity hash of the baseline it
//! was measured against, so the comparator resolves
//! `results/p1/<c>/<domain>/<hash>/` from data, not symlinks, and
//! refuses to pool results whose identities disagree on host/accel.
//! Gate outputs land in `<campaign>/compare/` in v1's JSON shapes.

pub mod fuzz;
pub mod perf;
pub mod safety;
pub mod screen;
pub mod verdict;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::bail;
use tracing::{info, warn};

use crate::block::cli::{CompareOpts, Scope};
use crate::block::results::{self, Manifest};
use crate::config::{anchored, Project};

pub(crate) fn drive(scope: &Scope, campaign: &str, opts: &CompareOpts) -> anyhow::Result<()> {
    let project = Project::locate()?;
    let results_root = anchored(&project.root, &scope.output);

    let pairs = super::driver_pairs(&project.config, &scope.only);
    if pairs.is_empty() {
        bail!("no matching driver pairs in the [block.drivers] registry");
    }

    let mut compared = 0;
    for pair in pairs {
        let (c_name, rs_name) = (pair.c_name, pair.rs_name);
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
        let mut baselines = BTreeMap::new();
        let mut record = |domain: &str, manifest: &Manifest, baselines: &mut BTreeMap<_, _>| {
            if let Some(p2) = &manifest.p2 {
                baselines.insert(domain.to_owned(), p2.baseline.clone());
            }
            compared += 1;
        };

        // Performance gate.
        if let Some((p2_dir, p1_dir, manifest)) =
            load_domain(&results_root, &campaign_root, c_name, "perf")?
        {
            info!("compare perf: {} vs {}", p1_dir.display(), p2_dir.display());
            perf::compare_perf(&p1_dir, &p2_dir, &manifest, opts, &compare_dir)?;
            record("perf", &manifest, &mut baselines);
        } else {
            info!("perf comparison: missing perf data; skipping");
        }

        // Fuzzing gate.
        if let Some((p2_dir, p1_dir, manifest)) =
            load_domain(&results_root, &campaign_root, c_name, "fuzz")?
        {
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
            record("fuzz", &manifest, &mut baselines);
        } else {
            info!("fuzz comparison: missing fuzz data; skipping");
        }

        // Safety gate over the static analysis outputs.
        if let Some((p2_dir, p1_dir, manifest)) =
            load_domain(&results_root, &campaign_root, c_name, "static")?
        {
            info!(
                "compare safety: {} vs {}",
                p1_dir.display(),
                p2_dir.display()
            );
            safety::compare_safety(&p1_dir, &p2_dir, opts, &compare_dir)?;
            record("static", &manifest, &mut baselines);
        } else {
            info!("safety comparison: missing static data; skipping");
        }

        // Fold whatever landed into the overall verdict.
        // An unreadable screening.json is not an absent one. Chaining
        // .ok() twice made a truncated file -- an interrupted write, a
        // partial rsync between machines -- look exactly like a driver
        // that was never screened, and the verdict would then omit its
        // phase-1 context without saying why.
        let screening_path = results_root.join("p1").join(c_name).join("screening.json");
        let screening = match std::fs::read_to_string(&screening_path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(value) => Some(value),
                Err(err) => {
                    warn!("{}: unreadable screening ({err}); the verdict will carry no phase-1 context",
                        screening_path.display());
                    None
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                warn!(
                    "{}: unreadable screening ({err}); the verdict will carry no phase-1 context",
                    screening_path.display()
                );
                None
            }
        };
        verdict::write_verdict(
            &compare_dir,
            campaign,
            &baselines,
            c_name,
            rs_name,
            screening.as_ref(),
        )?;
    }
    if compared == 0 {
        bail!("no domains available for comparison");
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
) -> anyhow::Result<Option<(PathBuf, PathBuf, Manifest)>> {
    let p2_dir = campaign_root.join(domain);
    let Some(manifest) = Manifest::load(&p2_dir)? else {
        return Ok(None);
    };
    if !manifest.complete {
        bail!(
            "{} is incomplete; re-run the {domain} phase",
            p2_dir.display()
        );
    }
    let Some(p2) = &manifest.p2 else {
        bail!("{} has no campaign record", p2_dir.display());
    };
    let p1_dir = results::p1_dir(results_root, c_name, domain, &p2.baseline);
    let Some(baseline) = Manifest::load(&p1_dir)? else {
        bail!(
            "baseline {} missing for {} — re-run the {domain} phase",
            p1_dir.display(),
            p2_dir.display()
        );
    };
    if !baseline.complete {
        bail!("baseline {} is incomplete", p1_dir.display());
    }
    // Same-substrate guard: the identity carries host+accel exactly
    // so cross-machine or KVM-vs-TCG data can never be pooled.
    if baseline.identity.host != manifest.identity.host
        || baseline.identity.accel != manifest.identity.accel
    {
        bail!(
            "baseline and campaign ran on different substrates ({}/{:?} vs {}/{:?})",
            baseline.identity.host,
            baseline.identity.accel,
            manifest.identity.host,
            manifest.identity.accel
        );
    }
    Ok(Some((p2_dir, p1_dir, manifest)))
}
