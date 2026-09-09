//! `koxi block compare` — diff a p2 campaign against its p1
//! baselines (v1 `compare/compare`). Manifest-first: each domain dir
//! under the campaign records the identity hash of the baseline it
//! was measured against, so the comparator resolves
//! `results/p1/<c>/<domain>/<hash>/` from data, not symlinks, and
//! refuses to pool results whose identities describe different
//! experiments (host, accel, guest shape, artifacts, knobs).
//! Gate outputs land in `<campaign>/compare/` in v1's JSON shapes.

pub mod fuzz;
pub mod perf;
pub mod safety;
pub mod screen;
pub mod verdict;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use tracing::{info, warn};

use crate::block::cli::{CompareOpts, Scope};
use crate::block::results::{self, Identity, Manifest};
use crate::config::{anchored, Project};
use verdict::Substrate;

/// Everything a compare writes under `<campaign>/compare/`.
const GATE_ARTIFACTS: [&str; 7] = [
    "perf_stats.json",
    "perf.csv",
    "fuzz_stats.json",
    "fuzz.csv",
    "safety.json",
    "safety.csv",
    "verdict.json",
];

pub(crate) fn drive(scope: &Scope, campaign: &str, opts: &CompareOpts) -> anyhow::Result<()> {
    let project = Project::locate()?;
    let results_root = anchored(&project.root, &scope.output);

    let pairs = super::driver_pairs(&project.config, &scope.only);
    if pairs.is_empty() {
        bail!("no matching driver pairs in the [block.drivers] registry");
    }
    let _gate = results::gate_lock(&results_root)?;

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
        // A previous run's artifacts do not survive into this one: a
        // compare that fails halfway must not leave last time's
        // verdict.json looking like this time's.
        for stale in GATE_ARTIFACTS {
            let path = compare_dir.join(stale);
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing stale {}", path.display()))?;
            }
        }
        let mut baselines = BTreeMap::new();
        // Each guest-side domain says where it ran. Kept per domain:
        // a fuzz campaign under TCG beside a KVM perf run must not
        // borrow the perf run's substrate and travel as measured.
        let mut substrates: BTreeMap<String, Substrate> = BTreeMap::new();
        let mut domains = 0;
        let mut record = |domain: &str,
                          manifest: &Manifest,
                          baselines: &mut BTreeMap<_, _>,
                          substrates: &mut BTreeMap<String, Substrate>| {
            if let Some(p2) = &manifest.p2 {
                baselines.insert(domain.to_owned(), p2.baseline.clone());
            }
            // Static is host-side and says nothing about the substrate.
            if manifest.identity.accel.is_some() {
                substrates.insert(
                    domain.to_owned(),
                    Substrate {
                        host: manifest.identity.host.clone(),
                        accel: manifest.identity.accel.clone(),
                    },
                );
            }
            domains += 1;
        };

        // Performance gate.
        if let Some((p2_dir, p1_dir, manifest)) = load_domain(
            &results_root,
            &campaign_root,
            campaign,
            c_name,
            rs_name,
            "perf",
        )? {
            info!("compare perf: {} vs {}", p1_dir.display(), p2_dir.display());
            perf::compare_perf(&p1_dir, &p2_dir, &manifest, opts, &compare_dir)
                .with_context(|| format!("performance gate under {}", compare_dir.display()))?;
            record("perf", &manifest, &mut baselines, &mut substrates);
        } else {
            info!("perf comparison: missing perf data; skipping");
        }

        // Fuzzing gate.
        if let Some((p2_dir, p1_dir, manifest)) = load_domain(
            &results_root,
            &campaign_root,
            campaign,
            c_name,
            rs_name,
            "fuzz",
        )? {
            info!("compare fuzz: {} vs {}", p1_dir.display(), p2_dir.display());
            fuzz::compare_fuzz(
                &p1_dir,
                &p2_dir,
                &manifest,
                opts,
                &compare_dir,
                c_name,
                rs_name,
                &pair.rs.abstractions,
            )
            .with_context(|| format!("fuzzing gate under {}", compare_dir.display()))?;
            record("fuzz", &manifest, &mut baselines, &mut substrates);
        } else {
            info!("fuzz comparison: missing fuzz data; skipping");
        }

        // Safety gate over the static analysis outputs.
        if let Some((p2_dir, p1_dir, manifest)) = load_domain(
            &results_root,
            &campaign_root,
            campaign,
            c_name,
            rs_name,
            "static",
        )? {
            info!(
                "compare safety: {} vs {}",
                p1_dir.display(),
                p2_dir.display()
            );
            safety::compare_safety(&p1_dir, &p2_dir, opts, &compare_dir)
                .with_context(|| format!("safety gate under {}", compare_dir.display()))?;
            record("static", &manifest, &mut baselines, &mut substrates);
        } else {
            info!("safety comparison: missing static data; skipping");
        }

        // A campaign directory with no domain in it has nothing to
        // gate. Writing a verdict here would leave an all-unavailable
        // verdict.json behind a failed compare, and the next reader
        // would take it for this campaign's result.
        if domains == 0 {
            warn!(
                "no domain data for {c_name}::{rs_name} under {}",
                campaign_root.display()
            );
            continue;
        }
        compared += domains;

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
            &substrates,
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
    campaign: &str,
    c_name: &str,
    rs_name: &str,
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
    // The record must be this campaign's, and it must point into the
    // baseline cache by hash: a dirname that is not one cannot have
    // been written by the perf or fuzz phase.
    if p2.campaign != campaign {
        bail!(
            "{} records campaign {:?}, not {campaign:?}",
            p2_dir.display(),
            p2.campaign
        );
    }
    if p2.baseline.len() != 12 || !p2.baseline.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "{} records baseline {:?}, which is not an identity hash",
            p2_dir.display(),
            p2.baseline
        );
    }
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
    if baseline.p2.is_some() {
        bail!(
            "baseline {} carries a campaign record: it is phase-2 data filed as a baseline",
            p1_dir.display()
        );
    }
    for (dir, identity) in [(&p1_dir, &baseline.identity), (&p2_dir, &manifest.identity)] {
        if let Err(why) = identity.validate() {
            bail!("{}: {why}", dir.display());
        }
    }
    let actual_hash = results::identity_hash(&baseline.identity)?;
    if actual_hash != p2.baseline {
        bail!(
            "baseline {} has identity hash {actual_hash}, but the campaign records {}; \
             restore the recorded baseline or re-run the {domain} phase",
            p1_dir.display(),
            p2.baseline
        );
    }
    // The two manifests must describe the registered pair, in this
    // domain, and nothing else.
    if p2.c_driver != c_name || p2.rs_driver != rs_name {
        bail!(
            "{} records the pair {}::{}, not {c_name}::{rs_name}",
            p2_dir.display(),
            p2.c_driver,
            p2.rs_driver
        );
    }
    for (dir, found, wanted) in [
        (&p1_dir, &baseline.identity.driver, c_name),
        (&p2_dir, &manifest.identity.driver, rs_name),
    ] {
        if found != wanted {
            bail!("{} measured driver {found}, not {wanted}", dir.display());
        }
    }
    for (dir, found) in [
        (&p1_dir, &baseline.identity.domain),
        (&p2_dir, &manifest.identity.domain),
    ] {
        if found != domain {
            bail!("{} holds {found} data, not {domain} data", dir.display());
        }
    }
    // Same-conditions guard: everything in the identity that is not
    // the driver itself must agree, or the two sides measured
    // different experiments. Host and accel keep cross-machine and
    // KVM-vs-TCG data apart; the guest shape, the artifacts and the
    // workload knobs keep a 4-vCPU io_uring baseline from being read
    // against an 8-vCPU psync campaign.
    let skew = identity_skew(&baseline.identity, &manifest.identity);
    if !skew.is_empty() {
        bail!(
            "baseline {} and campaign {} were measured under different conditions: {}",
            p1_dir.display(),
            p2_dir.display(),
            skew.join("; ")
        );
    }
    Ok(Some((p2_dir, p1_dir, manifest)))
}

/// The identity fields two comparable sides must share, and how each
/// differs. Driver-specific fields (driver, spec, prep, the module
/// sha, the static scope paths) are expected to differ and are not
/// compared.
fn identity_skew(baseline: &Identity, campaign: &Identity) -> Vec<String> {
    let mut skew = Vec::new();
    let mut check = |field: &str, left: String, right: String| {
        if left != right {
            skew.push(format!("{field} {left} vs {right}"));
        }
    };
    let text = |value: &dyn std::fmt::Debug| format!("{value:?}");
    check("host", text(&baseline.host), text(&campaign.host));
    check("accel", text(&baseline.accel), text(&campaign.accel));
    check("smp", text(&baseline.smp), text(&campaign.smp));
    check("memory", text(&baseline.memory), text(&campaign.memory));
    let artifacts = |identity: &Identity| {
        identity.artifacts.as_ref().map(|shas| {
            (
                shas.kernel.clone(),
                shas.initrd.clone(),
                shas.kconfig.clone(),
                shas.syzkaller.clone(),
                shas.syz_template.clone(),
            )
        })
    };
    check(
        "artifacts (kernel, initrd, kconfig, syzkaller, syz_template)",
        text(&artifacts(baseline)),
        text(&artifacts(campaign)),
    );
    check("source", text(&baseline.source), text(&campaign.source));
    check("fio", text(&baseline.fio), text(&campaign.fio));
    check("fuzz", text(&baseline.fuzz), text(&campaign.fuzz));
    let static_scope = |identity: &Identity| {
        identity
            .static_
            .as_ref()
            .map(|knobs| (knobs.since.clone(), knobs.ast_recipe))
    };
    check(
        "static (since, ast_recipe)",
        text(&static_scope(baseline)),
        text(&static_scope(campaign)),
    );
    skew
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::results::Campaign;

    fn baseline_manifest() -> Manifest {
        toml::from_str(
            r#"
            complete = true
            created = 1
            seed = 42
            koxi = "test"
            [identity]
            domain = "perf"
            driver = "null_blk"
            spec = "c:null_blk:null_blk.ko:/dev/nullb0:::"
            prep = ""
            host = "test"
            accel = "kvm"
            [identity.fio]
            bs = ["4k"]
            rw = ["randread"]
            qd = [32]
            size = ["512M"]
            reps = 11
            runtime = 5
            engine = "io_uring"
            "#,
        )
        .unwrap()
    }

    /// Hardening 29.
    #[test]
    fn the_recorded_baseline_hash_must_match_its_manifest() {
        let root = std::env::temp_dir().join(format!("koxi-baseline-hash-{}", std::process::id()));
        let campaign_root = root.join("p2/null_blk::rnull/trial");
        let mut baseline = baseline_manifest();
        let hash = results::identity_hash(&baseline.identity).unwrap();
        let p1 = results::p1_dir(&root, "null_blk", "perf", &hash);
        baseline.save(&p1).unwrap();
        let mut campaign = baseline.clone();
        campaign.identity.driver = "rnull".into();
        campaign.p2 = Some(Campaign {
            campaign: "trial".into(),
            c_driver: "null_blk".into(),
            rs_driver: "rnull".into(),
            baseline: hash,
        });
        campaign.save(&campaign_root.join("perf")).unwrap();
        assert!(
            load_domain(&root, &campaign_root, "trial", "null_blk", "rnull", "perf")
                .unwrap()
                .is_some()
        );

        // State and read-back geometry are not part of the identity.
        baseline.created += 1;
        baseline
            .device
            .insert("queue.scheduler".into(), "none".into());
        baseline.save(&p1).unwrap();
        assert!(
            load_domain(&root, &campaign_root, "trial", "null_blk", "rnull", "perf")
                .unwrap()
                .is_some()
        );

        // A changed setup contract must not masquerade as the old baseline.
        baseline.identity.prep = "echo mq-deadline > /sys/block/nullb0/queue/scheduler".into();
        baseline.save(&p1).unwrap();
        let error =
            load_domain(&root, &campaign_root, "trial", "null_blk", "rnull", "perf").unwrap_err();
        assert!(error.to_string().contains("identity hash"));
        assert!(error.to_string().contains(&p1.display().to_string()));
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Host and accel were the whole guard; a baseline measured on
    /// four vCPUs with io_uring compared silently against a campaign
    /// on eight with psync. Everything in the identity that is not
    /// the driver must agree.
    /// Hardening 38, 44.
    #[test]
    fn the_two_sides_must_describe_the_same_experiment() {
        use crate::block::results::FioKnobs;
        type Mutation<'a> = &'a dyn Fn(&mut Manifest);
        let root = std::env::temp_dir().join(format!("koxi-identity-skew-{}", std::process::id()));
        let campaign_root = root.join("p2/null_blk::rnull/trial");
        let mut baseline = baseline_manifest();
        baseline.identity.smp = Some(4);
        baseline.identity.memory = Some("4G".into());
        baseline.identity.fio = Some(FioKnobs {
            bs: vec!["4k".into()],
            rw: vec!["randread".into()],
            qd: vec![32],
            size: vec!["512M".into()],
            reps: 11,
            runtime: 5,
            engine: "io_uring".into(),
        });
        let hash = results::identity_hash(&baseline.identity).unwrap();
        let p1 = results::p1_dir(&root, "null_blk", "perf", &hash);
        baseline.save(&p1).unwrap();
        let campaign = |mutate: Mutation| {
            let mut campaign = baseline.clone();
            campaign.identity.driver = "rnull".into();
            campaign.identity.spec = "rs:rnull:rnull_mod.ko:/dev/rnullb0:::".into();
            campaign.p2 = Some(Campaign {
                campaign: "trial".into(),
                c_driver: "null_blk".into(),
                rs_driver: "rnull".into(),
                baseline: hash.clone(),
            });
            mutate(&mut campaign);
            campaign.save(&campaign_root.join("perf")).unwrap();
            load_domain(&root, &campaign_root, "trial", "null_blk", "rnull", "perf")
        };
        // The driver-specific fields differ by design.
        assert!(campaign(&|_| {}).unwrap().is_some());

        let skews: [(&str, Mutation); 8] = [
            ("smp", &|m| m.identity.smp = Some(8)),
            ("memory", &|m| m.identity.memory = Some("8G".into())),
            ("accel", &|m| m.identity.accel = Some("tcg".into())),
            ("host", &|m| m.identity.host = "elsewhere".into()),
            ("fio", &|m| {
                m.identity.fio.as_mut().unwrap().engine = "psync".into();
            }),
            ("fio", &|m| m.identity.fio.as_mut().unwrap().runtime = 60),
            ("not perf data", &|m| m.identity.domain = "static".into()),
            ("measured driver brd", &|m| m.identity.driver = "brd".into()),
        ];
        for (expected, mutate) in skews {
            let error = campaign(mutate).unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        let error = campaign(&|m| m.p2.as_mut().unwrap().rs_driver = "brd".into())
            .unwrap_err()
            .to_string();
        assert!(error.contains("null_blk::brd"), "{error}");
        // The campaign record itself: this campaign, a real hash, and
        // a plan the gate can run.
        let records: [(&str, Mutation); 4] = [
            ("records campaign \"other\"", &|m| {
                m.p2.as_mut().unwrap().campaign = "other".into();
            }),
            ("not an identity hash", &|m| {
                m.p2.as_mut().unwrap().baseline = "../../elsewhere".into();
            }),
            ("empty axis", &|m| {
                m.identity.fio.as_mut().unwrap().rw.clear();
            }),
            ("reps is 0", &|m| m.identity.fio.as_mut().unwrap().reps = 0),
        ];
        for (expected, mutate) in records {
            let error = campaign(mutate).unwrap_err().to_string();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        // A phase-2 manifest filed under p1 is not a baseline.
        let mut filed = baseline.clone();
        filed.p2 = Some(Campaign {
            campaign: "trial".into(),
            c_driver: "null_blk".into(),
            rs_driver: "rnull".into(),
            baseline: "000000000000".into(),
        });
        filed.save(&p1).unwrap();
        let error = campaign(&|_| {}).unwrap_err().to_string();
        assert!(error.contains("campaign record"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }
}
