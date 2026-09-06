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

use regex::{Regex, RegexBuilder};
use serde_json::json;
use tracing::{info, warn};

use crate::block::cli::Opts;
use crate::block::results::Manifest;
use crate::stats;

const TARGET: &str = "target_attributable";
const INFRA: &str = "infrastructure_noise";
const UNKNOWN: &str = "unknown";
const CLASSES: [&str; 3] = [TARGET, INFRA, UNKNOWN];

struct Classifier {
    target: Regex,
    infra: Regex,
    modules: Regex,
    call_trace: Regex,
    evidence: Regex,
}

impl Classifier {
    fn new(c_name: &str, rs_name: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            target: RegexBuilder::new(&format!(
                "{}|{}",
                regex::escape(c_name),
                regex::escape(rs_name)
            ))
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
struct OverrideRow {
    classification: String,
    validator: String,
    date: String,
    notes: String,
}

/// Sidecar override CSV: campaign,crash_id,classification,validator,date,notes.
fn load_validated_crashes(
    path: &Path,
) -> Result<HashMap<(String, String), OverrideRow>, Box<dyn std::error::Error>> {
    let mut overrides = HashMap::new();
    for line in fs::read_to_string(path)?.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let get = |index: usize| fields.get(index).map(|f| f.trim()).unwrap_or("");
        let (campaign, crash_id, class) = (get(0), get(1), get(2));
        if campaign.is_empty() || crash_id.is_empty() || class.is_empty() {
            continue;
        }
        if !CLASSES.contains(&class) {
            return Err(format!(
                "{}: invalid classification {class:?} for {campaign}/{crash_id}; \
                 expected one of {CLASSES:?}",
                path.display()
            )
            .into());
        }
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
struct Counts {
    target: u64,
    infra: u64,
    unknown: u64,
}

struct CampaignSummary {
    id: String,
    unique_crashes: u64,
    counts: Counts,
    quality: &'static str,
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
fn classify_campaign(
    classifier: &Classifier,
    campaign_dir: &Path,
    overrides: &HashMap<(String, String), OverrideRow>,
) -> Result<CampaignSummary, Box<dyn std::error::Error>> {
    let campaign = campaign_dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let crashes_dir = campaign_dir.join("crashes");

    let mut groups: Vec<(String, Vec<PathBuf>)> = Vec::new();
    if crashes_dir.is_dir() {
        let mut children: Vec<PathBuf> = fs::read_dir(&crashes_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        children.sort();
        for child in children {
            let name = child
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if child.is_dir() {
                let mut files: Vec<PathBuf> = walk_files(&child);
                files.sort();
                groups.push((name, files));
            } else {
                groups.push((name, vec![child]));
            }
        }
    }

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
        let effective = manual
            .map(|row| row.classification.as_str())
            .unwrap_or(auto);
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

    let quality = if manual_applied > 0 {
        "manually_validated"
    } else if crashes_dir.is_dir() {
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
    })
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walk_files(&path));
        } else {
            files.push(path);
        }
    }
    files
}

fn load_side(
    classifier: &Classifier,
    fuzz_dir: &Path,
    overrides: &HashMap<(String, String), OverrideRow>,
) -> Result<Vec<CampaignSummary>, Box<dyn std::error::Error>> {
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
        if !dir.join(".campaign_done").exists() {
            warn!(
                "{} has no .campaign_done marker; including anyway",
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
) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
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
    let one_sided = 1.0 - alpha;
    let total = c_total + rs_total;
    if total == 0 {
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
        let verdict = json!({
            "pass": true,
            "gate_basis": "zero_event_sensitivity",
            "criterion": format!(
                "one-sided {:.0}% exact upper bound on the rs/c attributable crash \
                 rate ratio <= {margin}; with zero events on both sides the per-side \
                 exact Poisson rate bound stands in",
                one_sided * 100.0
            ),
            "detail": format!(
                "0 target-attributable crashes over {t_c:.2}h (C) and {t_rs:.2}h (Rust); \
                 {:.0}% per-side rate bound {:.4}/h (C), {:.4}/h (Rust)",
                one_sided * 100.0,
                bound_c,
                bound_rs
            ),
        });
        return (block, verdict);
    }

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
    let pass = ratio_hi <= margin;

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
    let verdict = json!({
        "pass": pass,
        "gate_basis": "rate_ratio_ci",
        "criterion": format!(
            "one-sided {:.0}% exact upper bound on the rs/c attributable crash rate \
             ratio <= {margin} (exact conditional binomial)",
            one_sided * 100.0
        ),
        "detail": format!(
            "target-attributable totals c={c_total} rs={rs_total} over \
             {t_c:.2}h/{t_rs:.2}h; ratio upper bound {}, margin {margin}, one-sided \
             p={p_one_sided:.4}{}",
            if ratio_hi.is_finite() {
                format!("{:.3}", ratio_hi)
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
    opts: &Opts,
    outdir: &Path,
    c_name: &str,
    rs_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let alpha = opts.alpha;
    let margin = opts.fuzz_rate_margin;
    let a12_large_upper = opts.a12_large_threshold;

    let classifier = Classifier::new(c_name, rs_name)?;
    let overrides = match &opts.validated_crashes {
        Some(path) => load_validated_crashes(path)?,
        None => HashMap::new(),
    };
    let c_campaigns = load_side(&classifier, p1_dir, &overrides)?;
    let rs_campaigns = load_side(&classifier, p2_dir, &overrides)?;
    if c_campaigns.is_empty() || rs_campaigns.is_empty() {
        return Err("missing fuzz campaign data for one or both drivers".into());
    }

    // Exposure comes from the identity knobs (hours per campaign),
    // scaled by the campaigns actually present on disk.
    let baseline =
        Manifest::load(p1_dir)?.ok_or_else(|| format!("{} lost its manifest", p1_dir.display()))?;
    let hours = |manifest: &Manifest, side: &str| {
        manifest
            .identity
            .fuzz
            .as_ref()
            .map(|knobs| knobs.hours)
            .ok_or_else(|| format!("{side} manifest has no fuzz knobs in its identity"))
    };
    let t_c = hours(&baseline, "baseline")? * c_campaigns.len() as f64;
    let t_rs = hours(manifest, "campaign")? * rs_campaigns.len() as f64;

    let mut metrics = serde_json::Map::new();
    if let Some(value) = crash_metric(&c_campaigns, &rs_campaigns, "unique_crashes", alpha)? {
        metrics.insert("unique_crashes".into(), value);
    }
    let attributable = crash_metric(&c_campaigns, &rs_campaigns, TARGET, alpha)?;
    if let Some(value) = &attributable {
        metrics.insert("target_attributable_crashes".into(), value.clone());
    }
    metrics.insert(
        "crash_attribution".into(),
        json!({
            "c": aggregate_attribution(&c_campaigns),
            "rs": aggregate_attribution(&rs_campaigns),
        }),
    );

    let c_total: u64 = c_campaigns.iter().map(|c| c.counts.target).sum();
    let rs_total: u64 = rs_campaigns.iter().map(|c| c.counts.target).sum();
    let (rate_ratio, verdict) = rate_ratio_gate(c_total, rs_total, t_c, t_rs, alpha, margin);

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

    let result = json!({
        "methodology": "Klees et al. CCS 2018 + Schloegel et al. S&P 2024 campaign \
                        hygiene; exact conditional binomial rate-ratio gate over \
                        target-attributable crash totals, rank statistics kept as \
                        descriptive evidence",
        "thresholds": {
            "alpha": alpha,
            "rate_ratio_margin": margin,
            "a12_large_upper": round(a12_large_upper, 4),
            "a12_large_lower": round(1.0 - a12_large_upper, 4),
        },
        "data_quality": {
            "status": if attributable.is_none() { "unavailable" } else { attribution_quality },
            "crash_attribution": attribution_quality,
        },
        "sample_size": {"c": c_campaigns.len(), "rs": rs_campaigns.len()},
        "exposure_hours": {"c": round(t_c, 3), "rs": round(t_rs, 3)},
        "metrics": metrics,
        "rate_ratio": rate_ratio,
        "verdict": verdict,
    });
    fs::write(
        outdir.join("fuzz_stats.json"),
        serde_json::to_string_pretty(&result)?,
    )?;
    write_csv(&c_campaigns, &rs_campaigns, outdir)?;

    info!(
        "fuzz gate: attributable c={c_total} rs={rs_total} over {t_c:.2}h/{t_rs:.2}h -> {}",
        if result["verdict"]["pass"].as_bool() == Some(true) {
            "PASS"
        } else {
            "FAIL"
        }
    );
    Ok(())
}

/// v1 fuzz.csv columns; coverage/ttfc are not captured by the v2
/// fuzz phase and stay empty.
fn write_csv(
    c_campaigns: &[CampaignSummary],
    rs_campaigns: &[CampaignSummary],
    outdir: &Path,
) -> Result<(), std::io::Error> {
    let mut csv = String::from(
        "driver,campaign_id,unique_crashes,coverage_blocks,time_to_first_crash_s,\
         target_attributable,infrastructure_noise,unknown\n",
    );
    for (driver, campaigns) in [("c", c_campaigns), ("rs", rs_campaigns)] {
        for campaign in campaigns {
            csv.push_str(&format!(
                "{driver},{},{},0,,{},{},{}\n",
                campaign.id,
                campaign.unique_crashes,
                campaign.counts.target,
                campaign.counts.infra,
                campaign.counts.unknown
            ));
        }
    }
    fs::write(outdir.join("fuzz.csv"), csv)
}

/// Same rounding helper as the perf comparator.
fn round(value: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (value * factor).round() / factor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifier() -> Classifier {
        Classifier::new("null_blk", "rnull").unwrap()
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
    }

    #[test]
    fn rate_ratio_gate_bounds_and_zero_events() {
        // Zero events on both sides: pass on sensitivity, rule of
        // three per side (2.9957 / exposure).
        let (block, verdict) = rate_ratio_gate(0, 0, 1.5, 1.5, 0.05, 2.0);
        assert_eq!(verdict["pass"], true);
        assert_eq!(verdict["gate_basis"], "zero_event_sensitivity");
        let bound = block["max_undetected_rate_per_hour"]["rs"]
            .as_f64()
            .unwrap();
        assert!((bound - 2.9957 / 1.5).abs() < 1e-3);

        // One crash in C, none in Rust: the ratio cannot be bounded
        // below the margin with one event — honest FAIL with an MDE
        // explanation.
        let (block, verdict) = rate_ratio_gate(1, 0, 10.0, 10.0, 0.05, 2.0);
        assert_eq!(verdict["pass"], false);
        assert_eq!(verdict["gate_basis"], "rate_ratio_ci");
        assert!(block["ratio"]["ci"]["hi"].as_f64().unwrap() > 2.0);
        assert!(block["mde_ratio_80pct_power"].is_null());

        // Plenty of events, Rust clearly not worse: bound clears the
        // margin and the gate passes.
        let (block, verdict) = rate_ratio_gate(40, 20, 10.0, 10.0, 0.05, 2.0);
        assert_eq!(verdict["pass"], true);
        let hi = block["ratio"]["ci"]["hi"].as_f64().unwrap();
        assert!(hi < 2.0 && hi > 0.5, "upper bound {hi}");
        assert!(block["mde_ratio_80pct_power"].as_f64().unwrap() > 1.0);

        // Rust much worse: fails with a finite bound above margin.
        let (_, verdict) = rate_ratio_gate(5, 50, 10.0, 10.0, 0.05, 2.0);
        assert_eq!(verdict["pass"], false);
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
}
