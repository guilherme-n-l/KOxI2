//! The fuzzing gate. The descriptive layer is the v1 comparator —
//! Mann-Whitney U + A12 over per-campaign crash counts, crash
//! attribution with reconciliation, fuzz.csv — but the gated
//! quantity is count-grade instead of rank-grade: a non-inferiority
//! test on the target-attributable crash *rate ratio* rs/c via the
//! exact conditional binomial (conditional on the total event count,
//! the rs share is binomial with p fixed by the exposure split;
//! Clopper-Pearson bounds transform to rate-ratio bounds). Rank
//! tests on sparse counts have essentially no power, which made the
//! v1 criterion ("no significant large-effect increase") pass by
//! default; the ratio bound plus an analytic MDE report exactly how
//! much evidence the exposure actually bought. With zero events on
//! both sides the ratio is unbounded, so the verdict passes on the
//! per-side exact Poisson rate sensitivity bound instead, explicitly
//! labeled. Crash classification is v1 classify_crashes inline: the
//! call stack alone decides target attribution (`Modules linked
//! in:` is stripped — the driver is always loaded), infrastructure
//! signatures may match anywhere, and a --validated-crashes CSV
//! overrides per-crash verdicts.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use regex::{Regex, RegexBuilder};
use serde_json::json;
use tracing::{info, warn};

use crate::block::cli::CompareOpts;
use crate::block::fuzz::CAMPAIGN_DONE;
use crate::block::results::Manifest;
use crate::stats;
use crate::util::{csv_text, files_under, round};

const TARGET: &str = "target_attributable";
const INFRA: &str = "infrastructure_noise";
const UNKNOWN: &str = "unknown";
const CLASSES: [&str; 3] = [TARGET, INFRA, UNKNOWN];

pub(super) struct Classifier {
    target: Regex,
    infra: Regex,
    modules: Regex,
    call_trace: Regex,
    evidence: Regex,
}

impl Classifier {
    /// Attribution is by driver name in the call stack, so the
    /// classifier takes every name the subject answers to: both
    /// halves of a pair, or just the C driver when phase 1 screens a
    /// driver nobody has rewritten.
    pub(super) fn new(names: &[&str]) -> Result<Self, regex::Error> {
        let alternation = names
            .iter()
            .map(|name| regex::escape(name))
            .collect::<Vec<_>>()
            .join("|");
        Ok(Self {
            target: RegexBuilder::new(&alternation)
                .case_insensitive(true)
                .build()?,
            infra: RegexBuilder::new(
                "(no output from test machine|lost connection to test machine|SYZFAIL|\
                 failed to connect to manager|connection (?:reset|refused)|ssh: connect|\
                 transport endpoint is not connected)",
            )
            .case_insensitive(true)
            .build()?,
            modules: Regex::new(r"(?m)^Modules linked in:.*$")?,
            call_trace: Regex::new(
                r"(?s)(?:Call Trace:|RIP:)(.*?)(?:\n\s*\n|\nModules linked in:|\z)",
            )?,
            evidence: Regex::new(r"^(description|report\d*)$")?,
        })
    }

    fn classify(&self, text: &str) -> &'static str {
        let cleaned = self.modules.replace_all(text, "");
        let stack: String = self
            .call_trace
            .captures_iter(&cleaned)
            .filter_map(|captures| captures.get(1))
            .map(|group| group.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if self.target.is_match(&stack) {
            TARGET
        } else if self.infra.is_match(text) {
            INFRA
        } else {
            UNKNOWN
        }
    }
}

#[derive(Clone)]
pub(super) struct OverrideRow {
    classification: String,
    validator: String,
    date: String,
    notes: String,
}

/// Sidecar override CSV: campaign,crash_id,classification,validator,date,notes.
pub(super) fn load_validated_crashes(
    path: &Path,
) -> anyhow::Result<HashMap<(String, String), OverrideRow>> {
    let mut overrides = HashMap::new();
    let content =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let get = |index: usize| fields.get(index).map_or("", |field| field.trim());
        let (campaign, crash_id, class) = (get(0), get(1), get(2));
        if campaign.is_empty() || crash_id.is_empty() || class.is_empty() {
            continue;
        }
        ensure!(
            CLASSES.contains(&class),
            "{}: invalid classification {class:?} for {campaign}/{crash_id}; \
             expected one of {CLASSES:?}",
            path.display()
        );
        overrides.insert(
            (campaign.to_string(), crash_id.to_string()),
            OverrideRow {
                classification: class.to_string(),
                validator: get(3).to_string(),
                date: get(4).to_string(),
                notes: get(5).to_string(),
            },
        );
    }
    Ok(overrides)
}

#[derive(Default)]
pub(super) struct Counts {
    pub(super) target: u64,
    pub(super) infra: u64,
    pub(super) unknown: u64,
}

pub(super) struct CampaignSummary {
    id: String,
    unique_crashes: u64,
    pub(super) counts: Counts,
    pub(super) quality: &'static str,
    /// Hours syz-manager actually ran, read from the completion
    /// marker. None for a campaign that died before writing one, or
    /// for v1 data whose marker is empty.
    pub(super) hours: Option<f64>,
}

impl CampaignSummary {
    fn count(&self, class: &str) -> u64 {
        match class {
            TARGET => self.counts.target,
            INFRA => self.counts.infra,
            _ => self.counts.unknown,
        }
    }
}

/// Classify one campaign's syzkaller crash buckets and persist the
/// v1-shape crash_classification.json beside them (idempotent; the
/// screen verb and the paper appendix read it too).
pub(super) fn classify_campaign(
    classifier: &Classifier,
    campaign_dir: &Path,
    overrides: &HashMap<(String, String), OverrideRow>,
) -> anyhow::Result<CampaignSummary> {
    let campaign = campaign_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let groups = crash_buckets(campaign_dir)?;

    let mut counts = Counts::default();
    let mut manual_applied = 0u64;
    let mut records = Vec::new();
    for (crash_id, files) in &groups {
        let evidence: Vec<&PathBuf> = files
            .iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| classifier.evidence.is_match(name))
            })
            .collect();
        let text = evidence
            .iter()
            .map(|path| fs::read_to_string(path).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n");
        let auto = classifier.classify(&text);
        let manual = overrides.get(&(campaign.clone(), crash_id.clone()));
        let effective = manual.map_or(auto, |row| row.classification.as_str());
        if manual.is_some() {
            manual_applied += 1;
        }
        match effective {
            TARGET => counts.target += 1,
            INFRA => counts.infra += 1,
            _ => counts.unknown += 1,
        }
        records.push(json!({
            "crash_id": crash_id,
            "classification": effective,
            "auto_classification": auto,
            "manual_classification": manual.map(|row| row.classification.clone())
                .unwrap_or_default(),
            "validator": manual.map(|row| row.validator.clone()).unwrap_or_default(),
            "validation_date": manual.map(|row| row.date.clone()).unwrap_or_default(),
            "notes": manual.map(|row| row.notes.clone()).unwrap_or_default(),
            "evidence_files": evidence
                .iter()
                .filter_map(|path| path.strip_prefix(campaign_dir).ok())
                .map(|path| path.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        }));
    }

    // A campaign that ran its whole budget is measured evidence even
    // when it crashed nothing: syzkaller only creates `crashes/` once
    // there is something to put in it, so "no directory" from a
    // completed campaign means zero crashes, not missing data. Only a
    // campaign that neither completed nor left any crashes behind is
    // genuinely unavailable.
    let quality = if manual_applied > 0 {
        "manually_validated"
    } else if campaign_dir.join(CAMPAIGN_DONE).is_file() || campaign_dir.join("crashes").is_dir() {
        "measured"
    } else {
        "unavailable"
    };
    let classification = json!({
        "campaign_id": campaign,
        "raw_unique_crashes": groups.len(),
        "counts": {
            TARGET: counts.target,
            INFRA: counts.infra,
            UNKNOWN: counts.unknown,
        },
        "manual_overrides_applied": manual_applied,
        "classified_crashes": records,
        "data_quality": {"status": quality},
    });
    fs::write(
        campaign_dir.join("crash_classification.json"),
        serde_json::to_string_pretty(&classification)?,
    )?;

    Ok(CampaignSummary {
        id: campaign,
        unique_crashes: groups.len() as u64,
        counts,
        quality,
        hours: measured_hours(campaign_dir),
    })
}

/// The exposure a campaign actually bought, from the seconds its
/// completion marker records. An empty marker (v1, and koxi before
/// the marker carried a number) reads as unknown rather than zero.
fn measured_hours(campaign_dir: &Path) -> Option<f64> {
    let text = fs::read_to_string(campaign_dir.join(CAMPAIGN_DONE)).ok()?;
    let seconds: f64 = text.trim().parse().ok()?;
    (seconds > 0.0).then_some(seconds / 3600.0)
}

/// syzkaller's crashes/ dir: one bucket per unique crash, either a
/// dir of evidence files or a single file. Sorted for determinism.
fn crash_buckets(campaign_dir: &Path) -> anyhow::Result<Vec<(String, Vec<PathBuf>)>> {
    let crashes_dir = campaign_dir.join("crashes");
    if !crashes_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut children: Vec<PathBuf> = fs::read_dir(&crashes_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    children.sort();
    let mut groups = Vec::new();
    for child in children {
        let name = child
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let files = if child.is_dir() {
            files_under(&child, |_| true)?
        } else {
            vec![child]
        };
        groups.push((name, files));
    }
    Ok(groups)
}

fn load_side(
    classifier: &Classifier,
    fuzz_dir: &Path,
    overrides: &HashMap<(String, String), OverrideRow>,
) -> anyhow::Result<Vec<CampaignSummary>> {
    let campaigns_dir = fuzz_dir.join("campaigns");
    if !campaigns_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut dirs: Vec<PathBuf> = fs::read_dir(&campaigns_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    let mut campaigns = Vec::new();
    for dir in dirs {
        if !dir.join(CAMPAIGN_DONE).is_file() {
            warn!(
                "{} has no {CAMPAIGN_DONE} marker; including anyway",
                dir.display()
            );
        }
        campaigns.push(classify_campaign(classifier, &dir, overrides)?);
    }
    Ok(campaigns)
}

/// v1 mannwhitney_a12 block over per-campaign counts: MWU of (c, rs)
/// with A12 of (rs, c) — a12 above 0.5 means more crashes in Rust.
fn crash_metric(
    c_campaigns: &[CampaignSummary],
    rs_campaigns: &[CampaignSummary],
    class: &str,
    alpha: f64,
) -> anyhow::Result<Option<serde_json::Value>> {
    let extract = |campaigns: &[CampaignSummary]| -> Vec<f64> {
        campaigns
            .iter()
            .map(|campaign| match class {
                "unique_crashes" => campaign.unique_crashes as f64,
                other => campaign.count(other) as f64,
            })
            .collect()
    };
    let c_values = extract(c_campaigns);
    let rs_values = extract(rs_campaigns);
    if c_values.is_empty() || rs_values.is_empty() {
        return Ok(None);
    }
    let test = stats::mann_whitney(
        &c_values,
        &rs_values,
        stats::Alternative::TwoSided,
        stats::Method::Auto,
    )?;
    let a12 = stats::vargha_delaney_a12(&rs_values, &c_values);
    let side = |values: &[f64]| -> Result<serde_json::Value, stats::Error> {
        let desc = stats::descriptive(values)?;
        Ok(json!({
            "values": values.iter().map(|v| *v as u64).collect::<Vec<_>>(),
            "median": desc.median,
            "iqr": [desc.p25, desc.p75],
        }))
    };
    Ok(Some(json!({
        "c": side(&c_values)?,
        "rs": side(&rs_values)?,
        "test": {
            "name": "Mann-Whitney U",
            "statistic": test.u1,
            "p_value": round(test.p, 6),
            "significant": test.p < alpha,
            "alpha": alpha,
        },
        "effect_size": {
            "name": "Vargha-Delaney A12",
            "value": round(a12, 4),
            "label": stats::a12_label(a12),
        },
    })))
}

fn aggregate_attribution(campaigns: &[CampaignSummary]) -> serde_json::Value {
    let target: u64 = campaigns.iter().map(|c| c.counts.target).sum();
    let infra: u64 = campaigns.iter().map(|c| c.counts.infra).sum();
    let unknown: u64 = campaigns.iter().map(|c| c.counts.unknown).sum();
    let raw: u64 = campaigns.iter().map(|c| c.unique_crashes).sum();
    let status = if campaigns.is_empty() {
        "unavailable"
    } else if campaigns.iter().any(|c| c.quality == "manually_validated") {
        "manually_validated"
    } else if campaigns.iter().any(|c| c.quality == "unavailable") {
        "inferred"
    } else {
        "measured"
    };
    json!({
        "counts": {
            TARGET: target,
            INFRA: infra,
            UNKNOWN: unknown,
            "raw_unique_crashes": raw,
            "reconciles": target + infra + unknown == raw,
        },
        "data_quality": status,
    })
}

/// The gate: exact conditional rate-ratio bound on the
/// target-attributable totals, or the zero-event sensitivity bound.
fn rate_ratio_gate(
    c_total: u64,
    rs_total: u64,
    t_c: f64,
    t_rs: f64,
    alpha: f64,
    margin: f64,
) -> (serde_json::Value, serde_json::Value) {
    if c_total + rs_total == 0 {
        zero_event_sensitivity(t_c, t_rs, alpha, margin)
    } else {
        conditional_rate_ratio(c_total, rs_total, t_c, t_rs, alpha, margin)
    }
}

/// No events anywhere: the ratio is 0/0 and unbounded, so the gate
/// falls back to what the exposure could have ruled out — the exact
/// one-sided Poisson bound per side (the rule of three at 95%).
fn zero_event_sensitivity(
    t_c: f64,
    t_rs: f64,
    alpha: f64,
    margin: f64,
) -> (serde_json::Value, serde_json::Value) {
    let one_sided = 1.0 - alpha;
    let bound_c = stats::poisson_upper(0, one_sided) / t_c;
    let bound_rs = stats::poisson_upper(0, one_sided) / t_rs;
    let block = json!({
        "events": {"c": 0, "rs": 0},
        "exposure_hours": {"c": round(t_c, 3), "rs": round(t_rs, 3)},
        "rates_per_hour": {"c": 0.0, "rs": 0.0},
        "max_undetected_rate_per_hour": {
            "level": one_sided,
            "c": round(bound_c, 4),
            "rs": round(bound_rs, 4),
        },
        "ratio": serde_json::Value::Null,
        "mde_ratio_80pct_power": serde_json::Value::Null,
    });
    // No ratio can be bounded, so nothing has been shown either way.
    // `pass: null` keeps the verdict honest: the aggregate reads it as
    // undecided rather than as a pass bought with no evidence. The
    // per-side bound is what the exposure did establish.
    let verdict = json!({
        "pass": serde_json::Value::Null,
        "outcome": OUTCOME_INCONCLUSIVE,
        "gate_basis": "zero_event_sensitivity",
        "criterion": format!(
            "one-sided {:.0}% exact upper bound on the rs/c attributable crash \
             rate ratio <= {margin}; with zero events on both sides the ratio is \
             unbounded, so the gate is inconclusive and reports the per-side \
             exact Poisson rate bound instead",
            one_sided * 100.0
        ),
        "detail": format!(
            "0 target-attributable crashes over {t_c:.2}h (C) and {t_rs:.2}h (Rust): \
             inconclusive; {:.0}% per-side rate bound {:.4}/h (C), {:.4}/h (Rust)",
            one_sided * 100.0,
            bound_c,
            bound_rs
        ),
    });
    (block, verdict)
}

const OUTCOME_NON_INFERIOR: &str = "non_inferior";
const OUTCOME_INFERIOR: &str = "inferior";
const OUTCOME_INCONCLUSIVE: &str = "inconclusive";

/// Events on at least one side: conditional on the total, the rs
/// share is binomial with p0 fixed by the exposure split, so the
/// Clopper-Pearson bounds on that share transform into exact bounds
/// on the rate ratio.
fn conditional_rate_ratio(
    c_total: u64,
    rs_total: u64,
    t_c: f64,
    t_rs: f64,
    alpha: f64,
    margin: f64,
) -> (serde_json::Value, serde_json::Value) {
    let one_sided = 1.0 - alpha;
    let total = c_total + rs_total;
    let p0 = t_rs / (t_rs + t_c);
    let p_one_sided = stats::binomial_sf(rs_total, total, p0);
    // One-sided (1 - alpha) bounds = the matching sides of the
    // (1 - 2*alpha) Clopper-Pearson interval.
    let (p_lo, p_hi) = stats::clopper_pearson(rs_total, total, 1.0 - 2.0 * alpha);
    let to_ratio = |p: f64| {
        if p >= 1.0 {
            f64::INFINITY
        } else {
            p / (1.0 - p) * t_c / t_rs
        }
    };
    let (ratio_lo, ratio_hi) = (to_ratio(p_lo), to_ratio(p_hi));
    let c_rate = c_total as f64 / t_c;
    let rs_rate = rs_total as f64 / t_rs;
    let point = if c_total > 0 {
        json!(round(rs_rate / c_rate, 4))
    } else {
        serde_json::Value::Null
    };
    let mde = stats::binomial_mde_ratio(total, t_c, t_rs, alpha, 0.8);

    let block = json!({
        "events": {"c": c_total, "rs": rs_total},
        "exposure_hours": {"c": round(t_c, 3), "rs": round(t_rs, 3)},
        "rates_per_hour": {"c": round(c_rate, 4), "rs": round(rs_rate, 4)},
        "ratio": {
            "point": point,
            "test": {
                "name": "exact conditional binomial",
                "null": "rate ratio <= 1",
                "p_value_one_sided": round(p_one_sided, 6),
            },
            "ci": {
                "one_sided_level": one_sided,
                "lo": round(ratio_lo, 4),
                // Infinity serializes as null: unbounded above.
                "hi": round(ratio_hi, 4),
            },
        },
        "mde_ratio_80pct_power": mde.map(|value| round(value, 3)),
    });
    // Three outcomes, not two. Non-inferiority is shown when the upper
    // bound clears the margin; inferiority when the lower bound sits
    // above 1 (the Rust rate is higher, and significantly so); and
    // anything else is evidence of neither. Collapsing the third case
    // into "fail" made one C crash against zero Rust crashes fail the
    // Rust side, while zero against zero passed it.
    let (pass, outcome) = if ratio_hi <= margin {
        (json!(true), OUTCOME_NON_INFERIOR)
    } else if ratio_lo > 1.0 {
        (json!(false), OUTCOME_INFERIOR)
    } else {
        (serde_json::Value::Null, OUTCOME_INCONCLUSIVE)
    };
    let verdict = json!({
        "pass": pass,
        "outcome": outcome,
        "gate_basis": "rate_ratio_ci",
        "criterion": format!(
            "one-sided {:.0}% exact upper bound on the rs/c attributable crash rate \
             ratio <= {margin} passes; lower bound > 1 fails; otherwise inconclusive \
             (exact conditional binomial)",
            one_sided * 100.0
        ),
        "detail": format!(
            "target-attributable totals c={c_total} rs={rs_total} over \
             {t_c:.2}h/{t_rs:.2}h; ratio bounds [{:.3}, {}], margin {margin}: {outcome}; \
             one-sided p={p_one_sided:.4}{}",
            ratio_lo,
            if ratio_hi.is_finite() {
                format!("{ratio_hi:.3}")
            } else {
                "unbounded".to_string()
            },
            match mde {
                Some(mde) => format!(", MDE ratio {mde:.2} at 80% power"),
                None => ", too few events for 80% power at any ratio".to_string(),
            }
        ),
    });
    (block, verdict)
}

pub fn compare_fuzz(
    p1_dir: &Path,
    p2_dir: &Path,
    manifest: &Manifest,
    opts: &CompareOpts,
    outdir: &Path,
    c_name: &str,
    rs_name: &str,
) -> anyhow::Result<()> {
    let alpha = opts.alpha;
    let margin = opts.fuzz_rate_margin;

    let classifier = Classifier::new(&[c_name, rs_name])?;
    let overrides = match &opts.screen.validated_crashes {
        Some(path) => load_validated_crashes(path)?,
        None => HashMap::new(),
    };
    let c_campaigns = load_side(&classifier, p1_dir, &overrides)?;
    let rs_campaigns = load_side(&classifier, p2_dir, &overrides)?;
    ensure!(
        !c_campaigns.is_empty() && !rs_campaigns.is_empty(),
        "missing fuzz campaign data for one or both drivers"
    );

    let (c_exposure, rs_exposure) = exposure_hours(p1_dir, manifest, &c_campaigns, &rs_campaigns)?;
    let (t_c, t_rs) = (c_exposure.hours, rs_exposure.hours);
    let evidence = Evidence::gather(&c_campaigns, &rs_campaigns, alpha)?;

    let c_total: u64 = c_campaigns.iter().map(|c| c.counts.target).sum();
    let rs_total: u64 = rs_campaigns.iter().map(|c| c.counts.target).sum();
    let (rate_ratio, verdict) = rate_ratio_gate(c_total, rs_total, t_c, t_rs, alpha, margin);
    let outcome = match verdict["pass"].as_bool() {
        Some(true) => "PASS",
        Some(false) => "FAIL",
        None => "INCONCLUSIVE",
    };

    let result = json!({
        "methodology": "Klees et al. CCS 2018 + Schloegel et al. S&P 2024 campaign \
                        hygiene; exact conditional binomial rate-ratio gate over \
                        target-attributable crash totals, rank statistics kept as \
                        descriptive evidence",
        "thresholds": {
            "alpha": alpha,
            "rate_ratio_margin": margin,
            // The effect-size labels come from the fixed
            // Vargha-Delaney bands, not from a knob: the gate is the
            // rate ratio, so nothing a threshold could move.
            "a12_large_upper": round(stats::A12_LARGE, 4),
            "a12_large_lower": round(1.0 - stats::A12_LARGE, 4),
        },
        "data_quality": {
            "status": evidence.status(),
            "crash_attribution": evidence.attribution_quality,
        },
        "sample_size": {"c": c_campaigns.len(), "rs": rs_campaigns.len()},
        "exposure_hours": {"c": round(t_c, 3), "rs": round(t_rs, 3)},
        // Whether the denominator is what the campaigns ran or what
        // they were budgeted: a fallback means some campaign left no
        // duration behind, so the rates below are upper-bounded.
        "exposure_basis": if c_exposure.measured && rs_exposure.measured {
            "measured"
        } else {
            "nominal_fallback"
        },
        "metrics": evidence.metrics,
        "rate_ratio": rate_ratio,
        "verdict": verdict,
    });
    fs::write(
        outdir.join("fuzz_stats.json"),
        serde_json::to_string_pretty(&result)?,
    )?;
    fs::write(
        outdir.join("fuzz.csv"),
        fuzz_csv(&c_campaigns, &rs_campaigns),
    )?;

    info!(
        "fuzz gate: attributable c={c_total} rs={rs_total} over {t_c:.2}h/{t_rs:.2}h -> {outcome}"
    );
    Ok(())
}

/// Exposure comes from the identity knobs (hours per campaign),
/// scaled by the campaigns actually present on disk.
/// One side's exposure: the hours its campaigns actually ran,
/// falling back to the manifest's per-campaign budget for any
/// campaign that did not record its own. A campaign killed partway
/// through bought less exposure than its budget, and charging it the
/// budget would divide the crash count by too many hours — which
/// understates the rate, and on the Rust side flatters the gate.
struct Exposure {
    hours: f64,
    /// True when every campaign contributed a measured duration.
    measured: bool,
}

fn side_exposure(campaigns: &[CampaignSummary], nominal: f64) -> Exposure {
    let mut exposure = Exposure {
        hours: 0.0,
        measured: true,
    };
    for campaign in campaigns {
        if let Some(hours) = campaign.hours {
            exposure.hours += hours;
        } else {
            warn!(
                "campaign {} recorded no duration; charging the {nominal}h budget",
                campaign.id
            );
            exposure.hours += nominal;
            exposure.measured = false;
        }
    }
    exposure
}

fn exposure_hours(
    p1_dir: &Path,
    manifest: &Manifest,
    c_campaigns: &[CampaignSummary],
    rs_campaigns: &[CampaignSummary],
) -> anyhow::Result<(Exposure, Exposure)> {
    let baseline = Manifest::load(p1_dir)?
        .with_context(|| format!("{} lost its manifest", p1_dir.display()))?;
    let nominal = |manifest: &Manifest, side: &str| -> anyhow::Result<f64> {
        manifest
            .identity
            .fuzz
            .as_ref()
            .map(|knobs| knobs.hours)
            .with_context(|| format!("{side} manifest has no fuzz knobs in its identity"))
    };
    Ok((
        side_exposure(c_campaigns, nominal(&baseline, "baseline")?),
        side_exposure(rs_campaigns, nominal(manifest, "campaign")?),
    ))
}

/// The descriptive layer around the gate: v1's rank statistics over
/// per-campaign counts, the attribution reconciliation, and the
/// data-quality label they imply.
struct Evidence {
    metrics: serde_json::Map<String, serde_json::Value>,
    /// v1 reported the whole gate as unavailable when no
    /// attributable-crash metric could be formed at all.
    attributable: bool,
    attribution_quality: &'static str,
}

impl Evidence {
    fn gather(
        c_campaigns: &[CampaignSummary],
        rs_campaigns: &[CampaignSummary],
        alpha: f64,
    ) -> anyhow::Result<Self> {
        let mut metrics = serde_json::Map::new();
        if let Some(value) = crash_metric(c_campaigns, rs_campaigns, "unique_crashes", alpha)? {
            metrics.insert("unique_crashes".into(), value);
        }
        let attributable = crash_metric(c_campaigns, rs_campaigns, TARGET, alpha)?;
        if let Some(value) = &attributable {
            metrics.insert("target_attributable_crashes".into(), value.clone());
        }
        metrics.insert(
            "crash_attribution".into(),
            json!({
                "c": aggregate_attribution(c_campaigns),
                "rs": aggregate_attribution(rs_campaigns),
            }),
        );

        let quality = |side: &str| {
            metrics["crash_attribution"][side]["data_quality"]
                .as_str()
                .unwrap_or("inferred")
                .to_string()
        };
        let (c_quality, rs_quality) = (quality("c"), quality("rs"));
        let attribution_quality = if c_quality == "inferred" || rs_quality == "inferred" {
            "inferred"
        } else if c_quality == "manually_validated" || rs_quality == "manually_validated" {
            "manually_validated"
        } else {
            "measured"
        };
        Ok(Self {
            metrics,
            attributable: attributable.is_some(),
            attribution_quality,
        })
    }

    fn status(&self) -> &'static str {
        if self.attributable {
            self.attribution_quality
        } else {
            "unavailable"
        }
    }
}

/// v1 fuzz.csv columns; coverage/ttfc are not captured by the v2
/// fuzz phase and stay empty.
fn fuzz_csv(c_campaigns: &[CampaignSummary], rs_campaigns: &[CampaignSummary]) -> String {
    csv_text(|out| {
        out.write_record([
            "driver",
            "campaign_id",
            "unique_crashes",
            "coverage_blocks",
            "time_to_first_crash_s",
            "target_attributable",
            "infrastructure_noise",
            "unknown",
        ])?;
        for (driver, campaigns) in [("c", c_campaigns), ("rs", rs_campaigns)] {
            for campaign in campaigns {
                let unique = campaign.unique_crashes.to_string();
                let target = campaign.counts.target.to_string();
                let infra = campaign.counts.infra.to_string();
                let unknown = campaign.counts.unknown.to_string();
                out.write_record([
                    driver,
                    campaign.id.as_str(),
                    unique.as_str(),
                    "0",
                    "",
                    target.as_str(),
                    infra.as_str(),
                    unknown.as_str(),
                ])?;
            }
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::new(&["null_blk", "rnull"]).unwrap()
    }

    #[test]
    fn classification_uses_the_call_stack_not_the_modules_line() {
        let classifier = classifier();
        // Driver name only in Modules linked in: -> not attributable.
        let report = "BUG: something\nModules linked in: null_blk virtio\n\
                      Call Trace:\n do_generic_stuff+0x1\n other_frame+0x2\n\n";
        assert_eq!(classifier.classify(report), UNKNOWN);
        // Driver frame in the trace -> attributable.
        let report = "BUG: something\nModules linked in: ext4\n\
                      Call Trace:\n null_blk_submit+0x40\n\n";
        assert_eq!(classifier.classify(report), TARGET);
        // Infrastructure signature anywhere.
        assert_eq!(classifier.classify("no output from test machine"), INFRA);
        assert_eq!(classifier.classify("unrelated splat"), UNKNOWN);
        // A crash in the abstraction layer the Rust driver leans on,
        // with no driver frame at all (completion from softirq
        // context): the safety gate charges that layer to the driver,
        // so attribution does too. Both symbol spellings.
        let report =
            "Call Trace:\n _RNvMNtNtNtCs5678_6kernel5block2mq7requestNtB2_7Request6end_ok+0x22\n \
                      blk_done_softirq+0x9d\n\nModules linked in: rnull_mod\n";
        assert_eq!(classifier.classify(report), TARGET);
        let report = "Call Trace:\n <kernel::block::mq::request::Request>::end_ok+0x22\n\n";
        assert_eq!(classifier.classify(report), TARGET);
        // The driver name only in Modules linked in: still says nothing.
        let report = "Call Trace:\n do_syscall_64+0x3d\n\nModules linked in: rnull_mod null_blk\n";
        assert_eq!(classifier.classify(report), UNKNOWN);
        assert_eq!(
            abstraction_patterns(&[
                PathBuf::from("rust/kernel/block/"),
                PathBuf::from("drivers/x")
            ]),
            vec!["kernel::block".to_string(), "6kernel5block".to_string()]
        );
    }

    #[test]
    fn rate_ratio_gate_bounds_and_zero_events() {
        // Zero events on both sides: nothing shown either way, so the
        // gate is undecided and reports the rule of three per side
        // (2.9957 / exposure) as what the exposure did establish.
        let (block, verdict) = rate_ratio_gate(0, 0, 1.5, 1.5, 0.05, 2.0);
        assert!(verdict["pass"].is_null());
        assert_eq!(verdict["outcome"], OUTCOME_INCONCLUSIVE);
        assert_eq!(verdict["gate_basis"], "zero_event_sensitivity");
        let bound = block["max_undetected_rate_per_hour"]["rs"]
            .as_f64()
            .unwrap();
        assert!((bound - 2.9957 / 1.5).abs() < 1e-3);

        // One crash in C, none in Rust: the ratio cannot be bounded
        // below the margin with one event, and its lower bound is 0,
        // so nothing is shown: inconclusive, with an MDE explanation.
        // (Calling this a fail made more evidence against C count
        // against Rust.)
        let (block, verdict) = rate_ratio_gate(1, 0, 10.0, 10.0, 0.05, 2.0);
        assert!(verdict["pass"].is_null());
        assert_eq!(verdict["outcome"], OUTCOME_INCONCLUSIVE);
        assert_eq!(verdict["gate_basis"], "rate_ratio_ci");
        assert!(block["ratio"]["ci"]["hi"].as_f64().unwrap() > 2.0);
        assert!(block["mde_ratio_80pct_power"].is_null());

        // Comparable counts, too few to bound: still inconclusive.
        let (block, verdict) = rate_ratio_gate(10, 12, 10.0, 10.0, 0.05, 2.0);
        assert!(verdict["pass"].is_null());
        assert!(block["ratio"]["ci"]["lo"].as_f64().unwrap() < 1.0);
        assert!(block["ratio"]["ci"]["hi"].as_f64().unwrap() > 2.0);

        // Plenty of events, Rust clearly not worse: bound clears the
        // margin and the gate passes.
        let (block, verdict) = rate_ratio_gate(40, 20, 10.0, 10.0, 0.05, 2.0);
        assert_eq!(verdict["pass"], true);
        let hi = block["ratio"]["ci"]["hi"].as_f64().unwrap();
        assert!(hi < 2.0 && hi > 0.5, "upper bound {hi}");
        assert!(block["mde_ratio_80pct_power"].as_f64().unwrap() > 1.0);

        // Rust much worse: the lower bound clears 1, a real regression.
        let (block, verdict) = rate_ratio_gate(5, 50, 10.0, 10.0, 0.05, 2.0);
        assert_eq!(verdict["pass"], false);
        assert_eq!(verdict["outcome"], OUTCOME_INFERIOR);
        assert!(block["ratio"]["ci"]["lo"].as_f64().unwrap() > 1.0);
    }

    #[test]
    fn override_csv_rejects_bad_classes_and_applies_good_ones() {
        let dir = std::env::temp_dir().join(format!("koxi-fuzzcmp-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let csv = dir.join("validated.csv");
        fs::write(
            &csv,
            "campaign,crash_id,classification,validator,date,notes\n\
             campaign_1,deadbeef,target_attributable,gui,2026-09-06,confirmed\n",
        )
        .unwrap();
        let overrides = load_validated_crashes(&csv).unwrap();
        assert_eq!(
            overrides[&("campaign_1".to_string(), "deadbeef".to_string())].classification,
            TARGET
        );
        fs::write(&csv, "campaign,crash_id,classification\nc1,x,bogus\n").unwrap();
        assert!(load_validated_crashes(&csv).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn classify_campaign_writes_v1_shape_json() {
        let dir = std::env::temp_dir().join(format!("koxi-fuzzcls-{}", std::process::id()));
        let bucket = dir.join("crashes").join("abc123");
        fs::create_dir_all(&bucket).unwrap();
        fs::write(bucket.join("description"), "KASAN: use-after-free").unwrap();
        fs::write(
            bucket.join("report0"),
            "Call Trace:\n rnull_queue_rq+0x10\n\n",
        )
        .unwrap();
        fs::write(bucket.join("log0"), "raw console noise").unwrap();

        let summary = classify_campaign(&classifier(), &dir, &HashMap::new()).unwrap();
        assert_eq!(summary.unique_crashes, 1);
        assert_eq!(summary.counts.target, 1);
        assert_eq!(summary.quality, "measured");

        let written: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(dir.join("crash_classification.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(written["counts"][TARGET], 1);
        assert_eq!(written["classified_crashes"][0]["classification"], TARGET);
        // log0 is not classification evidence.
        let evidence = written["classified_crashes"][0]["evidence_files"]
            .as_array()
            .unwrap();
        assert_eq!(evidence.len(), 2);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// End-to-end over the whole pass: classification, exposure,
    /// descriptive metrics, the rate-ratio gate, artifacts.
    #[test]
    fn compare_fuzz_writes_both_artifacts() {
        use crate::block::cli::{CompareOpts, ScreenOpts};
        use crate::block::results::{FuzzKnobs, Identity, Manifest};

        let manifest = |hours: f64| Manifest {
            complete: true,
            created: 0,
            seed: 42,
            koxi: "test".to_owned(),
            device: std::collections::BTreeMap::new(),
            identity: Identity {
                domain: "fuzz".to_owned(),
                driver: "null_blk".to_owned(),
                spec: String::new(),
                prep: String::new(),
                host: "test".to_owned(),
                accel: None,
                smp: None,
                memory: None,
                artifacts: None,
                source: None,
                fio: None,
                fuzz: Some(FuzzKnobs {
                    campaigns: 2,
                    hours,
                    parallel: 1,
                }),
                static_: None,
            },
            p2: None,
        };

        let base = std::env::temp_dir().join(format!("koxi-fuzz-e2e-{}", std::process::id()));
        let (p1, p2, out) = (base.join("p1"), base.join("p2"), base.join("out"));
        for root in [&p1, &p2] {
            for campaign in ["campaign_1", "campaign_2"] {
                let dir = root.join("campaigns").join(campaign);
                fs::create_dir_all(&dir).unwrap();
                fs::write(dir.join(CAMPAIGN_DONE), "").unwrap();
            }
            fs::write(
                root.join("manifest.toml"),
                toml::to_string(&manifest(1.5)).unwrap(),
            )
            .unwrap();
        }
        // One attributable crash on the C side only.
        let bucket = p1.join("campaigns/campaign_1/crashes/abc");
        fs::create_dir_all(&bucket).unwrap();
        fs::write(bucket.join("report0"), "Call Trace:\n null_blk_rq+0x1\n\n").unwrap();
        fs::create_dir_all(&out).unwrap();

        let opts = CompareOpts {
            alpha: 0.05,
            perf_threshold: 5.0,
            bootstrap_resamples: 200,
            fuzz_rate_margin: 2.0,
            safety_threshold: 34.2,
            seed: Some(7),
            screen: ScreenOpts {
                validated_crashes: None,
            },
        };
        compare_fuzz(&p1, &p2, &manifest(1.5), &opts, &out, "null_blk", "rnull").unwrap();

        let stats: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("fuzz_stats.json")).unwrap())
                .unwrap();
        // Two campaigns per side at 1.5h each.
        assert_eq!(stats["exposure_hours"]["c"], 3.0);
        assert_eq!(stats["exposure_hours"]["rs"], 3.0);
        assert_eq!(stats["sample_size"]["c"], 2);
        assert_eq!(stats["rate_ratio"]["events"]["c"], 1);
        assert_eq!(stats["rate_ratio"]["events"]["rs"], 0);
        assert_eq!(stats["verdict"]["gate_basis"], "rate_ratio_ci");
        assert_eq!(
            stats["metrics"]["crash_attribution"]["c"]["counts"][TARGET],
            1
        );
        // These markers are empty, so exposure falls back to the
        // manifest budget and says so.
        assert_eq!(stats["exposure_basis"], "nominal_fallback");
        // Every campaign here ran its budget, so a side that crashed
        // nothing is still measured evidence: zero is a result.
        assert_eq!(stats["data_quality"]["status"], "measured");
        assert_eq!(
            stats["metrics"]["crash_attribution"]["rs"]["data_quality"], "measured",
            "the clean side measured zero crashes"
        );
        let csv = fs::read_to_string(out.join("fuzz.csv")).unwrap();
        assert_eq!(csv.lines().count(), 5);
        assert!(csv.contains("c,campaign_1,1,0,,1,0,0"));

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn completion_separates_a_clean_campaign_from_an_unknown_one() {
        let base = std::env::temp_dir().join(format!("koxi-fuzz-q-{}", std::process::id()));
        let done = base.join("done");
        let partial = base.join("partial");
        fs::create_dir_all(&done).unwrap();
        fs::create_dir_all(&partial).unwrap();
        fs::write(done.join(CAMPAIGN_DONE), "").unwrap();

        let classifier = classifier();
        let overrides = HashMap::new();
        // Ran its budget, crashed nothing: a measured zero.
        let clean = classify_campaign(&classifier, &done, &overrides).unwrap();
        assert_eq!(clean.counts.target, 0);
        assert_eq!(clean.quality, "measured");
        // Died mid-campaign with nothing to show: we do not know.
        let unknown = classify_campaign(&classifier, &partial, &overrides).unwrap();
        assert_eq!(unknown.quality, "unavailable");

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn exposure_counts_hours_run_not_hours_budgeted() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, marker: &str| {
            let campaign = dir.path().join(name);
            fs::create_dir_all(&campaign).unwrap();
            fs::write(campaign.join(CAMPAIGN_DONE), marker).unwrap();
            campaign
        };
        // A campaign killed at six minutes of a one-hour budget.
        assert_eq!(measured_hours(&write("short", "360.000\n")), Some(0.1));
        // v1 and pre-marker koxi wrote an empty marker: unknown, not zero.
        assert_eq!(measured_hours(&write("legacy", "")), None);
        assert_eq!(measured_hours(&write("odd", "not a number")), None);
        assert_eq!(measured_hours(&dir.path().join("absent")), None);

        let campaign = |hours: Option<f64>| CampaignSummary {
            id: "c".to_owned(),
            unique_crashes: 0,
            counts: Counts::default(),
            quality: "measured",
            hours,
        };
        // Two campaigns that ran six minutes each bought 0.2h, not
        // the 2h their budget would have charged them.
        let exposure = side_exposure(&[campaign(Some(0.1)), campaign(Some(0.1))], 1.0);
        assert!((exposure.hours - 0.2).abs() < 1e-9);
        assert!(exposure.measured);
        // One campaign with no record falls back to its budget, and
        // the whole side stops claiming a measured denominator.
        let exposure = side_exposure(&[campaign(Some(0.1)), campaign(None)], 1.0);
        assert!((exposure.hours - 1.1).abs() < 1e-9);
        assert!(!exposure.measured);
    }

    /// fuzz.csv is a v1 artifact shape: the header and the empty
    /// coverage/ttfc columns are read by downstream tooling.
    #[test]
    fn fuzz_csv_pins_the_v1_columns() {
        let summary = |id: &str, unique, target, infra, unknown| CampaignSummary {
            id: id.to_owned(),
            unique_crashes: unique,
            counts: Counts {
                target,
                infra,
                unknown,
            },
            quality: "measured",
            hours: Some(1.0),
        };
        let csv = fuzz_csv(
            &[summary("campaign_01", 3, 1, 1, 1)],
            &[summary("campaign_02", 0, 0, 0, 0)],
        );
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "driver,campaign_id,unique_crashes,coverage_blocks,time_to_first_crash_s,\
             target_attributable,infrastructure_noise,unknown"
        );
        assert_eq!(lines[1], "c,campaign_01,3,0,,1,1,1");
        assert_eq!(lines[2], "rs,campaign_02,0,0,,0,0,0");
        assert_eq!(lines.len(), 3);
        assert!(csv.ends_with('\n'));
    }
}
