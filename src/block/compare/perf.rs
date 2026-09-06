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

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::json;
use tracing::{info, warn};

use crate::block::cli::Opts;
use crate::block::results::Manifest;
use crate::stats;

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
    declared_workloads: usize,
    invalid_files: usize,
}

pub fn compare_perf(
    p1_dir: &Path,
    p2_dir: &Path,
    manifest: &Manifest,
    opts: &Opts,
    outdir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let alpha = opts.alpha;
    let threshold = opts.perf_threshold;
    let resamples = opts.bootstrap_resamples;
    let seed = opts.seed.unwrap_or(manifest.seed);

    let (c_workloads, c_stats) = load_workloads(p1_dir)?;
    let (rs_workloads, rs_stats) = load_workloads(p2_dir)?;
    if c_workloads.is_empty() || rs_workloads.is_empty() {
        return Err("missing workload data for one or both drivers".into());
    }
    let common: Vec<&String> = c_workloads
        .keys()
        .filter(|name| rs_workloads.contains_key(*name))
        .collect();
    if common.is_empty() {
        return Err("no common workloads between baseline and campaign".into());
    }

    let mut workload_results = Vec::new();
    let mut iops_p_values = Vec::new();
    let mut iops_indices = Vec::new();
    let mut all_deltas = Vec::new();
    let mut ci_lower_bounds = Vec::new();
    let mut tost_passes = Vec::new();
    let mut c_medians = Vec::new();
    let mut rs_medians = Vec::new();
    let mut insufficient = 0usize;

    for (index, name) in common.iter().enumerate() {
        let c_bundle = &c_workloads[*name];
        let rs_bundle = &rs_workloads[*name];
        let mut entry = json!({
            "name": name,
            "n_c_samples": c_bundle.runs.len(),
            "n_rs_samples": rs_bundle.runs.len(),
            "warmup_runs_skipped": {
                "c": c_bundle.warmups_skipped,
                "rs": rs_bundle.warmups_skipped,
            },
        });
        merge(&mut entry, parse_workload_name(name));

        let mut had_iops = false;
        for (metric, extract) in [
            ("iops", (|run: &Run| run.iops) as fn(&Run) -> f64),
            ("lat_mean_us", |run| run.lat_mean_us),
            ("lat_p99_us", |run| run.lat_p99_us),
        ] {
            let c_values: Vec<f64> = c_bundle.runs.iter().map(extract).collect();
            let rs_values: Vec<f64> = rs_bundle.runs.iter().map(extract).collect();
            let Some(mut comparison) =
                compare_metric(&c_values, &rs_values, alpha, resamples, seed)?
            else {
                continue;
            };
            if metric == "iops" {
                had_iops = true;
                iops_p_values.push(comparison["test"]["p_value"].as_f64().unwrap_or(f64::NAN));
                iops_indices.push(index);
                all_deltas.push(comparison["delta_pct"].as_f64().unwrap_or(0.0));
                ci_lower_bounds.push(comparison["ci_95"]["lo"].as_f64().unwrap_or(0.0));
                let equivalence = equivalence_entry(&c_values, &rs_values, alpha, threshold);
                tost_passes.push(equivalence["pass"].as_bool() == Some(true));
                comparison["equivalence"] = equivalence;
                c_medians.push(stats::descriptive(&c_values)?.median);
                rs_medians.push(stats::descriptive(&rs_values)?.median);
            }
            entry[metric] = comparison;
        }
        if !had_iops {
            insufficient += 1;
        }
        workload_results.push(entry);
    }

    // Holm-Bonferroni across the IOPS p-values (v1 semantics, kept
    // as descriptive evidence — the gate is the IUT below).
    let (adjusted, significant) = stats::holm_bonferroni(&iops_p_values, alpha);
    for entry in workload_results.iter_mut() {
        entry["p_value_adjusted"] = serde_json::Value::Null;
        entry["significant_after_correction"] = json!(false);
    }
    for (holm_index, &workload_index) in iops_indices.iter().enumerate() {
        workload_results[workload_index]["p_value_adjusted"] =
            json!(round(adjusted[holm_index], 6));
        workload_results[workload_index]["significant_after_correction"] =
            json!(significant[holm_index]);
    }

    let median_delta = if all_deltas.is_empty() {
        0.0
    } else {
        let mut sorted = all_deltas.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));
        round(stats::descriptive(&sorted)?.median, 2)
    };
    let worst_delta = all_deltas.iter().copied().fold(f64::INFINITY, f64::min);
    let worst_delta = if worst_delta.is_finite() {
        round(worst_delta, 2)
    } else {
        0.0
    };
    let ci_gate =
        !ci_lower_bounds.is_empty() && ci_lower_bounds.iter().all(|&bound| bound > -threshold);
    let count_corrected = |direction: fn(f64) -> bool| {
        iops_indices
            .iter()
            .enumerate()
            .filter(|(holm_index, &workload_index)| {
                significant[*holm_index]
                    && workload_results[workload_index]["iops"]["delta_pct"]
                        .as_f64()
                        .is_some_and(direction)
            })
            .count()
    };
    let slower = count_corrected(|delta| delta < 0.0);
    let faster = count_corrected(|delta| delta > 0.0);

    let declared: usize = {
        let mut names: Vec<&String> = c_workloads.keys().chain(rs_workloads.keys()).collect();
        names.sort();
        names.dedup();
        names.len()
    };
    let missing_on_one_side = declared - common.len();
    let degraded = c_stats.invalid_files > 0
        || rs_stats.invalid_files > 0
        || missing_on_one_side > 0
        || insufficient > 0;
    let data_quality = if workload_results.is_empty() {
        "unavailable"
    } else if degraded {
        "inferred"
    } else {
        "measured"
    };

    // The gate: intersection-union over the per-workload TOSTs. A
    // cell that never produced comparable evidence (missing on one
    // side, too few samples) is an untested cell — the IUT cannot
    // claim equivalence for it, so the gate fails.
    let tost_passed = tost_passes.iter().filter(|&&pass| pass).count();
    let tost_gate = !tost_passes.is_empty()
        && tost_passed == tost_passes.len()
        && insufficient == 0
        && missing_on_one_side == 0;
    let conf_level = 1.0 - 2.0 * alpha;
    let margin_ratio = 1.0 - threshold / 100.0;
    let global_descriptive = signed_rank_global(&c_medians, &rs_medians);

    let result = json!({
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
            "status": data_quality,
            "warmup_policy": "warmup-marked runs excluded from comparison",
            "coverage": {
                "common_workloads": common.len(),
                "declared_common_workloads": declared,
                "workloads_missing_on_one_side": missing_on_one_side,
                "workloads_with_insufficient_samples": insufficient,
                "invalid_fio_json_files": {
                    "c": c_stats.invalid_files,
                    "rs": rs_stats.invalid_files,
                },
            },
        },
        "workloads": workload_results,
        "global_descriptive": global_descriptive,
        "aggregate": {
            "median_delta_pct": median_delta,
            "worst_case_delta_pct": worst_delta,
            "workloads_significantly_slower": format!("{slower}/{}", common.len()),
            "workloads_significantly_faster": format!("{faster}/{}", common.len()),
            "workloads_passing_tost": format!("{tost_passed}/{}", common.len()),
            "tost_gate": tost_gate,
            "bootstrap_ci_gate": ci_gate,
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
                "{} workloads, {tost_passed} pass TOST, median delta {median_delta}%, worst \
                 case {worst_delta}%{}",
                common.len(),
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
    });
    fs::write(
        outdir.join("perf_stats.json"),
        serde_json::to_string_pretty(&result)?,
    )?;
    write_csv(&c_workloads, &rs_workloads, outdir)?;

    info!(
        "perf gate: tost {tost_passed}/{} median_delta={median_delta}% worst={worst_delta}% \
         margin={threshold}% -> {}",
        common.len(),
        if tost_gate { "PASS" } else { "FAIL" }
    );
    let _ = c_stats.declared_workloads + rs_stats.declared_workloads;
    Ok(())
}

/// Independent-sample MWU + bootstrap CI + A12 for one metric (v1
/// compare_metric; None below 2 samples on either side).
fn compare_metric(
    c_values: &[f64],
    rs_values: &[f64],
    alpha: f64,
    resamples: u64,
    seed: u64,
) -> Result<Option<serde_json::Value>, Box<dyn std::error::Error>> {
    if c_values.len() < 2 || rs_values.len() < 2 {
        return Ok(None);
    }
    let c_desc = stats::descriptive(c_values)?;
    let rs_desc = stats::descriptive(rs_values)?;
    let delta_pct = if c_desc.median != 0.0 {
        (rs_desc.median - c_desc.median) / c_desc.median * 100.0
    } else {
        0.0
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
        stats.declared_workloads += 1;
        let mut bundle = WorkloadBundle::default();
        let mut files: Vec<_> = fs::read_dir(&config_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("fio_") && name.ends_with(".json"))
            })
            .collect();
        files.sort();
        for file in files {
            bundle.total_files += 1;
            match parse_fio_json(&file) {
                Some((run, warmup)) => {
                    if warmup {
                        bundle.warmups_skipped += 1;
                    } else {
                        bundle.runs.push(run);
                    }
                }
                None => {
                    warn!("skipping malformed fio JSON: {}", file.display());
                    bundle.invalid_files += 1;
                    stats.invalid_files += 1;
                }
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
        .find(|section| section.get("iops").and_then(|v| v.as_f64()).unwrap_or(0.0) > 0.0)?;
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
        .and_then(|value| value.as_bool())
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

fn write_csv(
    c_workloads: &BTreeMap<String, WorkloadBundle>,
    rs_workloads: &BTreeMap<String, WorkloadBundle>,
    outdir: &Path,
) -> Result<(), std::io::Error> {
    let mut csv = String::from("workload,driver,run_id,warmup,iops,lat_mean_us,lat_p99_us\n");
    for (driver, workloads) in [("c", c_workloads), ("rs", rs_workloads)] {
        for (name, bundle) in workloads {
            for (index, run) in bundle.runs.iter().enumerate() {
                csv.push_str(&format!(
                    "{name},{driver},{},false,{},{},{}\n",
                    index + 1,
                    round(run.iops, 2),
                    round(run.lat_mean_us, 2),
                    round(run.lat_p99_us, 2)
                ));
            }
        }
    }
    fs::write(outdir.join("perf.csv"), csv)
}

fn merge(target: &mut serde_json::Value, extra: serde_json::Value) {
    if let (Some(target), Some(extra)) = (target.as_object_mut(), extra.as_object()) {
        for (key, value) in extra {
            target.insert(key.clone(), value.clone());
        }
    }
}

/// Python-style rounding for the output shape (half away from zero
/// is close enough at these magnitudes). NaN passes through and
/// serializes as null.
fn round(value: f64, decimals: u32) -> f64 {
    let factor = 10f64.powi(decimals as i32);
    (value * factor).round() / factor
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
