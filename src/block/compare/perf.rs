//! The performance gate. The gated quantity is equivalence-grade:
//! per workload, a TOST non-inferiority test on the Hodges-Lehmann
//! log-IOPS ratio — the (1 - 2*alpha) order-statistic CI lower bound
//! must clear the margin ratio — combined across workloads as an
//! intersection-union test (Berger: "all cells pass at level alpha"
//! controls FWER at alpha with no multiplicity correction). The v1
//! machinery (Mann-Whitney U + Holm-Bonferroni, percentile bootstrap
//! CI on the median IOPS delta, A12 — now with a DeLong CI) is kept
//! as descriptive evidence, plus a global Wilcoxon signed-rank over
//! per-workload log-median IOPS. Output extends v1's
//! perf_stats.json/perf.csv shapes so downstream artifact tooling
//! keeps working; the bootstrap is seeded from the campaign
//! manifest, making the verdict reproducible (v1's was not).
//!
//! The pass reads load -> per-workload cells -> Holm annotation ->
//! coverage -> aggregate/gate -> artifacts, one function per step.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::ensure;
use serde_json::json;
use tracing::{info, warn};

use crate::block::cli::CompareOpts;
use crate::block::results::Manifest;
use crate::stats;
use crate::util::{csv_text, round};

#[derive(Debug, Clone)]
struct Run {
    iops: f64,
    lat_mean_us: f64,
    lat_p99_us: f64,
}

#[derive(Debug, Default)]
struct WorkloadBundle {
    runs: Vec<Run>,
    warmups_skipped: usize,
    total_files: usize,
    invalid_files: usize,
}

#[derive(Debug, Default)]
struct LoadStats {
    invalid_files: usize,
}

/// Everything the gate is parameterised by, resolved once from the
/// CLI and the campaign manifest.
#[derive(Debug, Clone, Copy)]
struct Gates {
    alpha: f64,
    threshold: f64,
    resamples: u64,
    seed: u64,
}

/// The IOPS numbers the aggregate re-reads after a workload's JSON
/// is built. They are stored exactly as emitted (already rounded),
/// because Holm and the gate must see the numbers the artifact
/// reports.
#[derive(Debug)]
struct IopsCell {
    p_value: f64,
    delta_pct: f64,
    /// Bootstrap median-delta CI lower bound, in percent.
    ci_lo: f64,
    tost_pass: bool,
    /// Filled in by the Holm pass, which runs over all cells at once.
    significant: bool,
    c_median: f64,
    rs_median: f64,
}

/// One workload: its JSON entry plus the typed IOPS cell. v1 threaded
/// the same numbers through parallel vectors and indexed back into
/// the entry list by position; the cell removes that coupling.
struct WorkloadOutcome {
    entry: serde_json::Value,
    iops: Option<IopsCell>,
}

pub fn compare_perf(
    p1_dir: &Path,
    p2_dir: &Path,
    manifest: &Manifest,
    opts: &CompareOpts,
    outdir: &Path,
) -> anyhow::Result<()> {
    let gates = Gates {
        alpha: opts.alpha,
        threshold: opts.perf_threshold,
        resamples: opts.bootstrap_resamples,
        seed: opts.seed.unwrap_or(manifest.seed),
    };

    let (c_workloads, c_stats) = load_workloads(p1_dir)?;
    let (rs_workloads, rs_stats) = load_workloads(p2_dir)?;
    ensure!(
        !c_workloads.is_empty() && !rs_workloads.is_empty(),
        "missing workload data for one or both drivers"
    );
    let common: Vec<&String> = c_workloads
        .keys()
        .filter(|name| rs_workloads.contains_key(*name))
        .collect();
    ensure!(
        !common.is_empty(),
        "no common workloads between baseline and campaign"
    );

    let mut outcomes = Vec::with_capacity(common.len());
    for name in &common {
        outcomes.push(workload_outcome(
            name,
            &c_workloads[*name],
            &rs_workloads[*name],
            &gates,
        )?);
    }
    holm_annotate(&mut outcomes, gates.alpha);

    let geometry = device_geometry_report(p1_dir, manifest)?;
    let coverage = Coverage::measure(
        &c_workloads,
        &rs_workloads,
        common.len(),
        &outcomes,
        &c_stats,
        &rs_stats,
    );
    let aggregate = Aggregate::fold(&outcomes, &coverage, gates.threshold)?;
    let mut result = perf_stats(&outcomes, &coverage, &aggregate, &gates);
    // Two devices on different geometries measure configuration as
    // much as implementation: never better than inferred.
    if geometry["matched"].as_bool() == Some(false) {
        result["data_quality"]["status"] = json!("inferred");
    }
    result["data_quality"]["device_geometry"] = geometry;

    fs::write(
        outdir.join("perf_stats.json"),
        serde_json::to_string_pretty(&result)?,
    )?;
    fs::write(
        outdir.join("perf.csv"),
        perf_csv(&c_workloads, &rs_workloads),
    )?;

    info!(
        "perf gate: tost {}/{} median_delta={}% worst={}% margin={}% -> {}",
        aggregate.tost_passed,
        coverage.common,
        aggregate.median_delta,
        aggregate.worst_delta,
        gates.threshold,
        if aggregate.tost_gate { "PASS" } else { "FAIL" }
    );
    Ok(())
}

/// One workload's three metric cells (v1's per-workload block). IOPS
/// is the gated metric, so it also carries the TOST cell; latency is
/// descriptive only.
fn workload_outcome(
    name: &str,
    c_bundle: &WorkloadBundle,
    rs_bundle: &WorkloadBundle,
    gates: &Gates,
) -> anyhow::Result<WorkloadOutcome> {
    let mut entry = json!({
        "name": name,
        "n_c_samples": c_bundle.runs.len(),
        "n_rs_samples": rs_bundle.runs.len(),
        "warmup_runs_skipped": {
            "c": c_bundle.warmups_skipped,
            "rs": rs_bundle.warmups_skipped,
        },
    });
    merge(&mut entry, &parse_workload_name(name));

    let mut iops = None;
    for (metric, extract) in [
        ("iops", (|run: &Run| run.iops) as fn(&Run) -> f64),
        ("lat_mean_us", |run| run.lat_mean_us),
        ("lat_p99_us", |run| run.lat_p99_us),
    ] {
        let c_values: Vec<f64> = c_bundle.runs.iter().map(extract).collect();
        let rs_values: Vec<f64> = rs_bundle.runs.iter().map(extract).collect();
        let Some(mut comparison) = compare_metric(
            &c_values,
            &rs_values,
            gates.alpha,
            gates.resamples,
            gates.seed,
        )?
        else {
            continue;
        };
        if metric == "iops" {
            let equivalence =
                equivalence_entry(&c_values, &rs_values, gates.alpha, gates.threshold);
            iops = Some(IopsCell {
                p_value: comparison["test"]["p_value"].as_f64().unwrap_or(f64::NAN),
                delta_pct: comparison["delta_pct"].as_f64().unwrap_or(0.0),
                ci_lo: comparison["ci_95"]["lo"].as_f64().unwrap_or(0.0),
                tost_pass: equivalence["pass"].as_bool() == Some(true),
                significant: false,
                c_median: stats::descriptive(&c_values)?.median,
                rs_median: stats::descriptive(&rs_values)?.median,
            });
            comparison["equivalence"] = equivalence;
        }
        entry[metric] = comparison;
    }
    Ok(WorkloadOutcome { entry, iops })
}

/// Holm-Bonferroni across the IOPS p-values (v1 semantics, kept as
/// descriptive evidence — the gate is the IUT below). Every workload
/// carries the two v1 keys; only cells with IOPS evidence get a
/// number.
fn holm_annotate(outcomes: &mut [WorkloadOutcome], alpha: f64) {
    let p_values: Vec<f64> = outcomes
        .iter()
        .filter_map(|outcome| outcome.iops.as_ref().map(|cell| cell.p_value))
        .collect();
    let (adjusted, significant) = stats::holm_bonferroni(&p_values, alpha);
    let mut tested = 0;
    for outcome in outcomes {
        outcome.entry["p_value_adjusted"] = serde_json::Value::Null;
        outcome.entry["significant_after_correction"] = json!(false);
        let Some(cell) = outcome.iops.as_mut() else {
            continue;
        };
        cell.significant = significant[tested];
        outcome.entry["p_value_adjusted"] = json!(round(adjusted[tested], 6));
        outcome.entry["significant_after_correction"] = json!(significant[tested]);
        tested += 1;
    }
}

/// What the two sides actually offered (v1's data_quality/coverage
/// block). The two zero-counts matter beyond reporting: a cell that
/// never produced comparable evidence is an untested cell, and the
/// IUT cannot claim equivalence for it.
/// Whether the C and Rust devices presented the same geometry. Older
/// roots recorded none, which is reported as unrecorded rather than
/// as matched.
fn device_geometry_report(
    p1_dir: &Path,
    rs_manifest: &Manifest,
) -> anyhow::Result<serde_json::Value> {
    let c = Manifest::load(p1_dir)?
        .map(|manifest| manifest.device)
        .unwrap_or_default();
    let rs = &rs_manifest.device;
    let recorded = !c.is_empty() && !rs.is_empty();
    // Only an attribute both devices expose can disagree. null_blk has
    // configfs knobs (queue depth, submit queues, memory backing) that
    // rnull does not, and their absence on one side is not a mismatch
    // of the same thing; it is listed, not counted.
    let differing: Vec<&String> = c
        .iter()
        .filter(|(key, value)| rs.get(*key).is_some_and(|other| other != *value))
        .map(|(key, _)| key)
        .collect();
    let one_sided: Vec<&String> = c
        .keys()
        .filter(|key| !rs.contains_key(*key))
        .chain(rs.keys().filter(|key| !c.contains_key(*key)))
        .collect();
    if recorded && !differing.is_empty() {
        warn!(
            "the C and Rust devices differ in geometry ({}); the performance comparison \
             is confounded by device configuration",
            differing
                .iter()
                .map(|key| format!("{key}: {:?} vs {:?}", c[*key], rs[*key]))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(json!({
        "recorded": recorded,
        "matched": if recorded { json!(differing.is_empty()) } else { serde_json::Value::Null },
        "differing": differing,
        "one_sided": one_sided,
        "c": c,
        "rs": rs,
    }))
}

/// A percentage delta for prose, or "n/a" where none was measured.
fn pct(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_owned(), |value| format!("{value}%"))
}

struct Coverage {
    common: usize,
    declared: usize,
    missing_on_one_side: usize,
    insufficient: usize,
    c_invalid: usize,
    rs_invalid: usize,
    status: &'static str,
}

impl Coverage {
    fn measure(
        c_workloads: &BTreeMap<String, WorkloadBundle>,
        rs_workloads: &BTreeMap<String, WorkloadBundle>,
        common: usize,
        outcomes: &[WorkloadOutcome],
        c_stats: &LoadStats,
        rs_stats: &LoadStats,
    ) -> Self {
        let declared = {
            let mut names: Vec<&String> = c_workloads.keys().chain(rs_workloads.keys()).collect();
            names.sort();
            names.dedup();
            names.len()
        };
        let missing_on_one_side = declared - common;
        let insufficient = outcomes
            .iter()
            .filter(|outcome| outcome.iops.is_none())
            .count();
        let degraded = c_stats.invalid_files > 0
            || rs_stats.invalid_files > 0
            || missing_on_one_side > 0
            || insufficient > 0;
        let status = if outcomes.is_empty() {
            "unavailable"
        } else if degraded {
            "inferred"
        } else {
            "measured"
        };
        Self {
            common,
            declared,
            missing_on_one_side,
            insufficient,
            c_invalid: c_stats.invalid_files,
            rs_invalid: rs_stats.invalid_files,
            status,
        }
    }
}

/// The aggregate row and the gate itself: an intersection-union over
/// the per-workload TOSTs. Every cell must pass, and every declared
/// cell must have been testable.
struct Aggregate {
    median_delta: f64,
    worst_delta: f64,
    ci_gate: bool,
    slower: usize,
    faster: usize,
    tost_passed: usize,
    tost_gate: bool,
}

impl Aggregate {
    fn fold(
        outcomes: &[WorkloadOutcome],
        coverage: &Coverage,
        threshold: f64,
    ) -> Result<Self, stats::Error> {
        let cells: Vec<&IopsCell> = outcomes
            .iter()
            .filter_map(|outcome| outcome.iops.as_ref())
            .collect();
        let mut deltas: Vec<f64> = cells.iter().map(|cell| cell.delta_pct).collect();
        deltas.sort_by(f64::total_cmp);
        let median_delta = if deltas.is_empty() {
            0.0
        } else {
            round(stats::descriptive(&deltas)?.median, 2)
        };
        let worst = deltas.iter().copied().fold(f64::INFINITY, f64::min);
        let worst_delta = if worst.is_finite() {
            round(worst, 2)
        } else {
            0.0
        };
        let ci_gate = !cells.is_empty() && cells.iter().all(|cell| cell.ci_lo > -threshold);
        let corrected = |direction: fn(f64) -> bool| {
            cells
                .iter()
                .filter(|cell| cell.significant && direction(cell.delta_pct))
                .count()
        };
        let tost_passed = cells.iter().filter(|cell| cell.tost_pass).count();
        Ok(Self {
            median_delta,
            worst_delta,
            ci_gate,
            slower: corrected(|delta| delta < 0.0),
            faster: corrected(|delta| delta > 0.0),
            tost_passed,
            tost_gate: !cells.is_empty()
                && tost_passed == cells.len()
                && coverage.insufficient == 0
                && coverage.missing_on_one_side == 0,
        })
    }
}

/// v1's perf_stats.json, extended with the TOST/IUT fields.
fn perf_stats(
    outcomes: &[WorkloadOutcome],
    coverage: &Coverage,
    aggregate: &Aggregate,
    gates: &Gates,
) -> serde_json::Value {
    let Gates {
        alpha,
        threshold,
        resamples,
        seed,
    } = *gates;
    let Aggregate {
        median_delta,
        worst_delta,
        tost_passed,
        tost_gate,
        ..
    } = *aggregate;
    let Coverage {
        common,
        insufficient,
        missing_on_one_side,
        ..
    } = *coverage;
    let conf_level = 1.0 - 2.0 * alpha;
    let margin_ratio = 1.0 - threshold / 100.0;

    let cells = || outcomes.iter().filter_map(|outcome| outcome.iops.as_ref());
    let c_medians: Vec<f64> = cells().map(|cell| cell.c_median).collect();
    let rs_medians: Vec<f64> = cells().map(|cell| cell.rs_median).collect();

    json!({
        "methodology": "Per-workload TOST non-inferiority on the Hodges-Lehmann log-IOPS \
                        ratio, combined as an intersection-union test across workloads; \
                        Mann-Whitney U + Holm-Bonferroni, bootstrap median-delta CI, A12 \
                        with DeLong CI, and a global Wilcoxon signed-rank retained as \
                        descriptive evidence",
        "threshold_pct": threshold,
        "thresholds": {
            "alpha": alpha,
            "tost_conf_level": conf_level,
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
        },
        "data_quality": {
            "status": coverage.status,
            "warmup_policy": "warmup-marked runs excluded from comparison",
            "coverage": {
                "common_workloads": common,
                "declared_common_workloads": coverage.declared,
                "workloads_missing_on_one_side": missing_on_one_side,
                "workloads_with_insufficient_samples": insufficient,
                "invalid_fio_json_files": {
                    "c": coverage.c_invalid,
                    "rs": coverage.rs_invalid,
                },
            },
        },
        "workloads": outcomes.iter().map(|outcome| &outcome.entry).collect::<Vec<_>>(),
        "global_descriptive": signed_rank_global(&c_medians, &rs_medians),
        "aggregate": {
            "median_delta_pct": median_delta,
            "worst_case_delta_pct": worst_delta,
            "workloads_significantly_slower": format!("{}/{common}", aggregate.slower),
            "workloads_significantly_faster": format!("{}/{common}", aggregate.faster),
            "workloads_passing_tost": format!("{tost_passed}/{common}"),
            "tost_gate": tost_gate,
            "bootstrap_ci_gate": aggregate.ci_gate,
        },
        "verdict": {
            "pass": tost_gate,
            "criterion": format!(
                "intersection-union TOST: every workload's {:.0}% Hodges-Lehmann CI lower \
                 bound on the IOPS ratio (rs/c) exceeds {margin_ratio} (margin {threshold}%); \
                 FWER <= alpha={alpha} with no multiplicity correction (Berger IUT)",
                conf_level * 100.0,
            ),
            "threshold": threshold,
            "actual_median_delta_pct": median_delta,
            "detail": format!(
                "{common} workloads, {tost_passed} pass TOST, median delta {median_delta}%, \
                 worst case {worst_delta}%{}",
                if insufficient > 0 || missing_on_one_side > 0 {
                    format!(
                        ", {insufficient} with insufficient samples, {missing_on_one_side} \
                         missing on one side"
                    )
                } else {
                    String::new()
                },
            ),
        },
    })
}

/// Independent-sample MWU + bootstrap CI + A12 for one metric (v1
/// compare_metric; None below 2 samples on either side).
fn compare_metric(
    c_values: &[f64],
    rs_values: &[f64],
    alpha: f64,
    resamples: u64,
    seed: u64,
) -> anyhow::Result<Option<serde_json::Value>> {
    if c_values.len() < 2 || rs_values.len() < 2 {
        return Ok(None);
    }
    let c_desc = stats::descriptive(c_values)?;
    let rs_desc = stats::descriptive(rs_values)?;
    let delta_pct = if c_desc.median == 0.0 {
        0.0
    } else {
        (rs_desc.median - c_desc.median) / c_desc.median * 100.0
    };
    let (ci_lo, ci_hi) = stats::bootstrap_median_delta_ci(c_values, rs_values, resamples, seed)?;
    let test = stats::mann_whitney(
        c_values,
        rs_values,
        stats::Alternative::TwoSided,
        stats::Method::Auto,
    )?;
    let a12 = stats::a12_delong_ci(rs_values, c_values, 1.0 - alpha)?;

    Ok(Some(json!({
        "c": describe(&c_desc),
        "rs": describe(&rs_desc),
        "delta_pct": round(delta_pct, 2),
        "test": {
            "name": "Mann-Whitney U",
            "statistic": test.u1,
            "p_value": round(test.p, 6),
            "significant": test.p < alpha,
            "alpha": alpha,
        },
        "effect_size": {
            "name": "Vargha-Delaney A12",
            "value": round(a12.a12, 4),
            "label": stats::a12_label(a12.a12),
            "ci": {
                "lo": round(a12.lo, 4),
                "hi": round(a12.hi, 4),
                "level": 1.0 - alpha,
                "method": "DeLong",
            },
        },
        "ci_95": {
            "lo": round(ci_lo, 2),
            "hi": round(ci_hi, 2),
            "method": format!(
                "bootstrap independent-sample median delta ({resamples} resamples)"
            ),
        },
    })))
}

/// One TOST non-inferiority cell: the (1 - 2*alpha) Hodges-Lehmann
/// CI on the log-IOPS shift, exponentiated back to a rs/c ratio;
/// pass means the CI lower bound clears the margin ratio
/// 1 - threshold/100. Sparse cells get infinite order-statistic
/// bounds (ratio lower bound 0), so missing evidence fails the gate
/// on its own.
fn equivalence_entry(
    c_values: &[f64],
    rs_values: &[f64],
    alpha: f64,
    threshold: f64,
) -> serde_json::Value {
    let conf_level = 1.0 - 2.0 * alpha;
    let margin_ratio = 1.0 - threshold / 100.0;
    if c_values.iter().chain(rs_values).any(|&value| value <= 0.0) {
        return json!({
            "pass": false,
            "reason": "non-positive IOPS values; log ratio undefined",
        });
    }
    let rs_log: Vec<f64> = rs_values.iter().map(|value| value.ln()).collect();
    let c_log: Vec<f64> = c_values.iter().map(|value| value.ln()).collect();
    let hl = match stats::hodges_lehmann_ci(&rs_log, &c_log, conf_level) {
        Ok(hl) => hl,
        Err(err) => return json!({"pass": false, "reason": err.to_string()}),
    };
    let (ratio, lo, hi) = (hl.estimate.exp(), hl.lo.exp(), hl.hi.exp());
    json!({
        "name": "TOST non-inferiority on Hodges-Lehmann IOPS ratio",
        "conf_level": conf_level,
        "margin_ratio": round(margin_ratio, 4),
        "hl_ratio": round(ratio, 4),
        "hl_delta_pct": round((ratio - 1.0) * 100.0, 2),
        // Infinite upper bounds serialize as null (unbounded).
        "ci_ratio": {"lo": round(lo, 4), "hi": round(hi, 4)},
        "ci_delta_pct": {
            "lo": round((lo - 1.0) * 100.0, 2),
            "hi": round((hi - 1.0) * 100.0, 2),
        },
        "pass": lo >= margin_ratio,
    })
}

/// Descriptive global check: two-sided Wilcoxon signed-rank over the
/// paired per-workload log-median IOPS. Not part of the gate — the
/// IUT is the criterion; this summarizes whether the grid as a whole
/// shifts one way.
fn signed_rank_global(c_medians: &[f64], rs_medians: &[f64]) -> serde_json::Value {
    let test_name = "Wilcoxon signed-rank on per-workload log-median IOPS";
    if c_medians.is_empty()
        || c_medians
            .iter()
            .chain(rs_medians)
            .any(|&value| value <= 0.0)
    {
        return serde_json::Value::Null;
    }
    let rs_log: Vec<f64> = rs_medians.iter().map(|value| value.ln()).collect();
    let c_log: Vec<f64> = c_medians.iter().map(|value| value.ln()).collect();
    match stats::wilcoxon_signed_rank(
        &rs_log,
        &c_log,
        stats::Alternative::TwoSided,
        stats::Method::Auto,
    ) {
        Ok(result) => json!({
            "test": test_name,
            "n_workloads": c_medians.len(),
            "statistic": result.statistic,
            "p_value": round(result.p, 6),
            "method": result.method,
        }),
        Err(err) => json!({"test": test_name, "error": err.to_string()}),
    }
}

fn describe(desc: &stats::Descriptive) -> serde_json::Value {
    json!({
        "median": round(desc.median, 2),
        "mean": round(desc.mean, 2),
        "std": round(desc.std, 2),
        "iqr": [round(desc.p25, 2), round(desc.p75, 2)],
    })
}

/// Load fio runs per workload dir (v1 load_workloads): warmups are
/// skipped, malformed files counted, non-workload entries (manifest,
/// kernel.log, compare/) ignored.
fn load_workloads(
    dir: &Path,
) -> Result<(BTreeMap<String, WorkloadBundle>, LoadStats), std::io::Error> {
    let mut workloads = BTreeMap::new();
    let mut stats = LoadStats::default();
    let mut entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    entries.sort();
    for config_dir in entries {
        let mut bundle = WorkloadBundle::default();
        let mut files: Vec<_> = fs::read_dir(&config_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension().is_some_and(|ext| ext == "json")
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("fio_"))
            })
            .collect();
        files.sort();
        for file in files {
            bundle.total_files += 1;
            if let Some((run, warmup)) = parse_fio_json(&file) {
                if warmup {
                    bundle.warmups_skipped += 1;
                } else {
                    bundle.runs.push(run);
                }
            } else {
                warn!("skipping malformed fio JSON: {}", file.display());
                bundle.invalid_files += 1;
                stats.invalid_files += 1;
            }
        }
        if !bundle.runs.is_empty() {
            let name = config_dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            workloads.insert(name, bundle);
        }
    }
    Ok((workloads, stats))
}

/// v1 parse_fio_json: first direction of read/write/trim with IOPS,
/// latencies in microseconds, warmup from the metadata (koxi_metadata
/// here; nullb_metadata accepted for imported v1 results).
fn parse_fio_json(path: &Path) -> Option<(Run, bool)> {
    let data: serde_json::Value = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    let job = data.get("jobs")?.as_array()?.first()?;
    let section = ["read", "write", "trim"]
        .iter()
        .filter_map(|direction| job.get(*direction))
        .find(|section| {
            section
                .get("iops")
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0)
                > 0.0
        })?;
    let run = Run {
        iops: section.get("iops")?.as_f64()?,
        lat_mean_us: section.get("lat_ns")?.get("mean")?.as_f64()? / 1000.0,
        lat_p99_us: section
            .get("clat_ns")?
            .get("percentile")?
            .get("99.000000")?
            .as_f64()?
            / 1000.0,
    };
    let warmup = data
        .get("koxi_metadata")
        .or_else(|| data.get("nullb_metadata"))
        .and_then(|meta| meta.get("warmup"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    Some((run, warmup))
}

/// v1 parse_workload_name over `<bs>_<rw>_<qd>[_<size>]` dir names.
fn parse_workload_name(name: &str) -> serde_json::Value {
    let parts: Vec<&str> = name.split('_').collect();
    if parts.len() >= 3 {
        json!({
            "block_size": parts[0],
            "rw": parts[1],
            "iodepth": parts[2].parse::<u64>().unwrap_or(0),
        })
    } else {
        json!({"block_size": name, "rw": "unknown", "iodepth": 0})
    }
}

/// v1 perf.csv: one row per retained run, C side then Rust side.
/// Warmups never reach `runs`, so the column is constant.
fn perf_csv(
    c_workloads: &BTreeMap<String, WorkloadBundle>,
    rs_workloads: &BTreeMap<String, WorkloadBundle>,
) -> String {
    csv_text(|out| {
        out.write_record([
            "workload",
            "driver",
            "run_id",
            "warmup",
            "iops",
            "lat_mean_us",
            "lat_p99_us",
        ])?;
        for (driver, workloads) in [("c", c_workloads), ("rs", rs_workloads)] {
            for (name, bundle) in workloads {
                for (index, run) in bundle.runs.iter().enumerate() {
                    let run_id = (index + 1).to_string();
                    let iops = round(run.iops, 2).to_string();
                    let lat_mean = round(run.lat_mean_us, 2).to_string();
                    let lat_p99 = round(run.lat_p99_us, 2).to_string();
                    out.write_record([
                        name.as_str(),
                        driver,
                        run_id.as_str(),
                        "false",
                        iops.as_str(),
                        lat_mean.as_str(),
                        lat_p99.as_str(),
                    ])?;
                }
            }
        }
        Ok(())
    })
}

fn merge(target: &mut serde_json::Value, extra: &serde_json::Value) {
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::cli::ScreenOpts;
    use crate::block::results::Identity;

    /// Ten reps per side, the same grid on both, Rust 0.1% slower:
    /// well inside a 5% margin.
    const REPS: [f64; 10] = [
        100.0, 102.0, 98.0, 101.0, 99.0, 100.5, 97.5, 103.0, 100.2, 99.8,
    ];

    fn opts() -> CompareOpts {
        CompareOpts {
            alpha: 0.05,
            perf_threshold: 5.0,
            bootstrap_resamples: 200,
            fuzz_rate_margin: 2.0,
            safety_threshold: 34.2,
            seed: Some(7),
            screen: ScreenOpts {
                validated_crashes: None,
            },
        }
    }

    #[test]
    fn geometry_disagrees_only_on_attributes_both_devices_expose() {
        let dir = std::env::temp_dir().join(format!("koxi-geom-{}", std::process::id()));
        let p1 = dir.join("p1");
        fs::create_dir_all(&p1).unwrap();
        let mut c = manifest();
        c.device = [
            ("queue.nr_requests", "256"),
            ("configfs.hw_queue_depth", "256"),
            ("queue.scheduler", "[none] mq-deadline"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        c.save(&p1).unwrap();
        let mut rs = manifest();
        rs.device = [
            ("queue.nr_requests", "256"),
            ("queue.scheduler", "[none] mq-deadline"),
            ("configfs.rotational", "0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let report = device_geometry_report(&p1, &rs).unwrap();
        assert_eq!(report["matched"], true, "{report}");
        assert_eq!(report["differing"].as_array().unwrap().len(), 0);
        assert_eq!(report["one_sided"].as_array().unwrap().len(), 2);

        rs.device
            .insert("queue.nr_requests".to_owned(), "64".to_owned());
        let report = device_geometry_report(&p1, &rs).unwrap();
        assert_eq!(report["matched"], false);
        assert_eq!(report["differing"][0], "queue.nr_requests");

        // Nothing recorded on one side: unknown, not matched.
        rs.device.clear();
        assert!(device_geometry_report(&p1, &rs).unwrap()["matched"].is_null());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn manifest() -> Manifest {
        Manifest {
            complete: true,
            created: 0,
            seed: 42,
            koxi: "test".to_owned(),
            device: std::collections::BTreeMap::new(),
            identity: Identity {
                domain: "perf".to_owned(),
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
                fuzz: None,
                static_: None,
            },
            p2: None,
        }
    }

    fn write_fio(dir: &Path, index: usize, iops: f64) {
        fs::write(
            dir.join(format!("fio_{index}.json")),
            serde_json::to_string(&json!({
                "jobs": [{"read": {
                    "iops": iops,
                    "lat_ns": {"mean": 32000.0},
                    "clat_ns": {"percentile": {"99.000000": 64000.0}},
                }}],
                "koxi_metadata": {"warmup": false},
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// End-to-end over the whole pass: load, cells, Holm, coverage,
    /// aggregate, artifacts.
    #[test]
    fn compare_perf_writes_both_artifacts() {
        let base = std::env::temp_dir().join(format!("koxi-perf-e2e-{}", std::process::id()));
        let (p1, p2, out) = (base.join("p1"), base.join("p2"), base.join("out"));
        for (root, scale) in [(&p1, 1.0), (&p2, 0.999)] {
            for workload in ["4k_randread_32", "4k_randwrite_1"] {
                let dir = root.join(workload);
                fs::create_dir_all(&dir).unwrap();
                for (index, iops) in REPS.iter().enumerate() {
                    write_fio(&dir, index + 1, iops * scale);
                }
            }
        }
        fs::create_dir_all(&out).unwrap();
        compare_perf(&p1, &p2, &manifest(), &opts(), &out).unwrap();

        let stats: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(out.join("perf_stats.json")).unwrap())
                .unwrap();
        assert_eq!(stats["data_quality"]["status"], "measured");
        assert_eq!(stats["aggregate"]["workloads_passing_tost"], "2/2");
        assert_eq!(stats["verdict"]["pass"], true);
        assert_eq!(stats["thresholds"]["bootstrap_seed"], 7);
        // Every workload entry carries the Holm keys and a TOST cell.
        for entry in stats["workloads"].as_array().unwrap() {
            assert!(entry["p_value_adjusted"].is_number());
            assert_eq!(entry["significant_after_correction"], false);
            assert_eq!(entry["iops"]["equivalence"]["pass"], true);
            assert!(entry["lat_p99_us"]["delta_pct"].is_number());
        }
        // Header plus two workloads x ten reps x two drivers.
        let csv = fs::read_to_string(out.join("perf.csv")).unwrap();
        assert_eq!(csv.lines().count(), 1 + 2 * 10 * 2);

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn workload_names_parse_like_v1() {
        let parsed = parse_workload_name("4k_randread_32_512M");
        assert_eq!(parsed["block_size"], "4k");
        assert_eq!(parsed["rw"], "randread");
        assert_eq!(parsed["iodepth"], 32);
        assert_eq!(parse_workload_name("odd")["rw"], "unknown");
    }

    #[test]
    fn fio_json_parses_metrics_and_warmup() {
        let dir = std::env::temp_dir().join(format!("koxi-cmp-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("fio_1.json");
        fs::write(
            &path,
            serde_json::to_string(&json!({
                "jobs": [{
                    "read": {
                        "iops": 30236.4,
                        "lat_ns": {"mean": 32000.0},
                        "clat_ns": {"percentile": {"99.000000": 64000.0}},
                    },
                    "write": {"iops": 0.0},
                }],
                "koxi_metadata": {"warmup": true},
            }))
            .unwrap(),
        )
        .unwrap();
        let (run, warmup) = parse_fio_json(&path).unwrap();
        assert!(warmup);
        assert_eq!(run.iops, 30236.4);
        assert_eq!(run.lat_mean_us, 32.0);
        assert_eq!(run.lat_p99_us, 64.0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn compare_metric_produces_v1_shape() {
        let c = [100.0, 102.0, 98.0, 101.0, 99.0];
        let rs = [85.0, 88.0, 84.0, 86.0, 87.0];
        let value = compare_metric(&c, &rs, 0.05, 500, 42).unwrap().unwrap();
        assert_eq!(value["delta_pct"], -14.0);
        assert_eq!(value["test"]["name"], "Mann-Whitney U");
        assert!(value["test"]["significant"].as_bool().unwrap());
        assert_eq!(value["effect_size"]["label"], "large");
        // Perfect separation collapses the DeLong interval onto A12.
        assert_eq!(value["effect_size"]["ci"]["lo"], 0.0);
        assert_eq!(value["effect_size"]["ci"]["hi"], 0.0);
        assert_eq!(value["effect_size"]["ci"]["level"], 0.95);
        assert!(value["ci_95"]["lo"].as_f64().unwrap() <= value["ci_95"]["hi"].as_f64().unwrap());
        assert!(compare_metric(&[1.0], &rs, 0.05, 10, 1).unwrap().is_none());
    }

    #[test]
    fn equivalence_gates_on_the_ratio_ci_lower_bound() {
        let c = [
            100.0, 102.0, 98.0, 101.0, 99.0, 100.5, 97.5, 103.0, 100.2, 99.8,
        ];

        // Clear ~14% regression: the ratio CI lower bound sits far
        // below the 5% margin.
        let rs = [85.0, 88.0, 84.0, 86.0, 87.0, 85.5, 83.5, 88.5, 86.2, 85.8];
        let entry = equivalence_entry(&c, &rs, 0.05, 5.0);
        assert_eq!(entry["pass"], false);
        assert_eq!(entry["conf_level"], 0.90);
        assert_eq!(entry["margin_ratio"], 0.95);
        assert!(entry["ci_ratio"]["lo"].as_f64().unwrap() < 0.95);

        // A 0.1% shift is well inside the margin: equivalence holds.
        let rs_flat: Vec<f64> = c.iter().map(|value| value * 0.999).collect();
        let entry = equivalence_entry(&c, &rs_flat, 0.05, 5.0);
        assert_eq!(entry["pass"], true);
        assert!(entry["ci_ratio"]["lo"].as_f64().unwrap() >= 0.95);

        // Two reps per side cannot reach 90% coverage: the
        // order-statistic bounds go infinite and the cell fails.
        let entry = equivalence_entry(&[100.0, 101.0], &[100.0, 101.0], 0.05, 5.0);
        assert_eq!(entry["pass"], false);
        assert_eq!(entry["ci_ratio"]["lo"], 0.0);

        // Non-positive values are refused, not log'd.
        let entry = equivalence_entry(&[0.0, 1.0], &[1.0, 2.0], 0.05, 5.0);
        assert_eq!(entry["pass"], false);
        assert!(entry["reason"].as_str().unwrap().contains("non-positive"));
    }

    #[test]
    fn signed_rank_global_summarizes_direction() {
        let c = [100.0, 105.0, 98.0, 102.0, 110.0, 95.0];
        let rs: Vec<f64> = c.iter().map(|value| value * 0.9).collect();
        let value = signed_rank_global(&c, &rs);
        assert_eq!(value["n_workloads"], 6);
        assert!(value["p_value"].as_f64().unwrap() < 0.05);

        assert_eq!(signed_rank_global(&[], &[]), serde_json::Value::Null);

        // Identical medians leave no non-zero differences: reported
        // as an error field, never a panic.
        let equal = [1.0, 2.0];
        assert!(signed_rank_global(&equal, &equal)["error"]
            .as_str()
            .is_some());
    }

    /// perf_stats.json is a v1 artifact shape: the aggregate counters
    /// and the verdict prose are quoted in the paper, so pin them.
    #[test]
    fn perf_stats_pins_the_v1_json_shape() {
        let cell = |delta_pct: f64, tost_pass: bool, significant: bool| IopsCell {
            p_value: 0.01,
            delta_pct,
            ci_lo: -1.0,
            tost_pass,
            significant,
            c_median: 100.0,
            rs_median: 99.0,
        };
        let outcomes = vec![
            WorkloadOutcome {
                entry: json!({"name": "4k_randread_32"}),
                iops: Some(cell(-1.5, true, true)),
            },
            WorkloadOutcome {
                entry: json!({"name": "4k_randwrite_1"}),
                iops: None,
            },
        ];
        let coverage = Coverage {
            common: 2,
            declared: 2,
            missing_on_one_side: 0,
            insufficient: 1,
            c_invalid: 0,
            rs_invalid: 0,
            status: "inferred",
        };
        let aggregate = Aggregate {
            median_delta: -1.5,
            worst_delta: -3.0,
            ci_gate: true,
            slower: 1,
            faster: 0,
            tost_passed: 1,
            tost_gate: false,
        };
        let gates = Gates {
            alpha: 0.05,
            threshold: 5.0,
            resamples: 1000,
            seed: 7,
        };
        let stats = perf_stats(&outcomes, &coverage, &aggregate, &gates);

        assert_eq!(stats["threshold_pct"], 5.0);
        assert_eq!(stats["thresholds"]["tost_conf_level"], 0.9);
        assert_eq!(stats["thresholds"]["bootstrap_seed"], 7);
        assert_eq!(stats["data_quality"]["status"], "inferred");
        assert_eq!(
            stats["data_quality"]["coverage"]["workloads_with_insufficient_samples"],
            1
        );
        assert_eq!(stats["workloads"].as_array().unwrap().len(), 2);
        assert_eq!(stats["aggregate"]["workloads_significantly_slower"], "1/2");
        assert_eq!(stats["aggregate"]["workloads_significantly_faster"], "0/2");
        assert_eq!(stats["aggregate"]["workloads_passing_tost"], "1/2");
        assert_eq!(stats["aggregate"]["tost_gate"], false);
        assert_eq!(stats["verdict"]["pass"], false);
        assert_eq!(
            stats["verdict"]["criterion"],
            "intersection-union TOST: every workload's 90% Hodges-Lehmann CI lower bound on \
             the IOPS ratio (rs/c) exceeds 0.95 (margin 5%); FWER <= alpha=0.05 with no \
             multiplicity correction (Berger IUT)"
        );
        assert_eq!(
            stats["verdict"]["detail"],
            "2 workloads, 1 pass TOST, median delta -1.5%, worst case -3%, 1 with \
             insufficient samples, 0 missing on one side"
        );
        // The global test pairs the per-workload medians of the
        // cells that produced IOPS evidence — here, one of the two.
        assert_eq!(stats["global_descriptive"]["n_workloads"], 1);
    }

    /// perf.csv is a v1 artifact shape: header and row layout are
    /// read by downstream tooling and must not drift.
    #[test]
    fn perf_csv_pins_the_v1_columns() {
        let bundle = |iops: f64| WorkloadBundle {
            runs: vec![
                Run {
                    iops,
                    lat_mean_us: 32.0,
                    lat_p99_us: 64.125,
                },
                Run {
                    iops: iops + 1.0,
                    lat_mean_us: 32.0,
                    lat_p99_us: 64.0,
                },
            ],
            ..WorkloadBundle::default()
        };
        let c: BTreeMap<String, WorkloadBundle> =
            [("4k_randread_32".to_owned(), bundle(30236.456))].into();
        let rs: BTreeMap<String, WorkloadBundle> =
            [("4k_randread_32".to_owned(), bundle(29000.0))].into();

        let csv = perf_csv(&c, &rs);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(
            lines[0],
            "workload,driver,run_id,warmup,iops,lat_mean_us,lat_p99_us"
        );
        assert_eq!(lines[1], "4k_randread_32,c,1,false,30236.46,32,64.13");
        assert_eq!(lines[2], "4k_randread_32,c,2,false,30237.46,32,64");
        assert_eq!(lines[3], "4k_randread_32,rs,1,false,29000,32,64.13");
        assert_eq!(lines.len(), 5);
        assert!(csv.ends_with('\n'));
    }
}
