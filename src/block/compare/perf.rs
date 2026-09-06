//! The performance gate (v1 `compare/perf_compare`): per-workload
//! Mann-Whitney U + Vargha-Delaney A12 + percentile bootstrap CI on
//! the median IOPS delta, Holm-Bonferroni across workloads, and the
//! do-no-harm criterion — every workload's CI lower bound must stay
//! above -threshold%. Output mirrors v1's perf_stats.json/perf.csv
//! shapes so downstream artifact tooling keeps working; the bootstrap
//! is seeded from the campaign manifest, making the gate verdict
//! reproducible (v1's was not).

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
            let Some(comparison) = compare_metric(&c_values, &rs_values, alpha, resamples, seed)?
            else {
                continue;
            };
            if metric == "iops" {
                had_iops = true;
                iops_p_values.push(comparison["test"]["p_value"].as_f64().unwrap_or(f64::NAN));
                iops_indices.push(index);
                all_deltas.push(comparison["delta_pct"].as_f64().unwrap_or(0.0));
                ci_lower_bounds.push(comparison["ci_95"]["lo"].as_f64().unwrap_or(0.0));
            }
            entry[metric] = comparison;
        }
        if !had_iops {
            insufficient += 1;
        }
        workload_results.push(entry);
    }

    // Holm-Bonferroni across the IOPS p-values (v1 semantics).
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

    let result = json!({
        "methodology": "Independent-sample Mann-Whitney U per workload + bootstrap 95% CI \
                        for median delta + Holm-Bonferroni correction across workloads",
        "threshold_pct": threshold,
        "thresholds": {
            "alpha": alpha,
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
        "aggregate": {
            "median_delta_pct": median_delta,
            "worst_case_delta_pct": worst_delta,
            "workloads_significantly_slower": format!("{slower}/{}", common.len()),
            "workloads_significantly_faster": format!("{faster}/{}", common.len()),
            "bootstrap_ci_gate": ci_gate,
        },
        "verdict": {
            "pass": ci_gate,
            "criterion": format!(
                "all workload bootstrap CI lower bounds on median delta exceed -{threshold}%"
            ),
            "threshold": threshold,
            "actual_median_delta_pct": median_delta,
            "detail": format!(
                "{} workloads, median delta {median_delta}%, worst case {worst_delta}%, {} \
                 workload CIs remain within threshold",
                common.len(),
                if ci_gate { "all" } else { "not all" }
            ),
        },
    });
    fs::write(
        outdir.join("perf_stats.json"),
        serde_json::to_string_pretty(&result)?,
    )?;
    write_csv(&c_workloads, &rs_workloads, outdir)?;

    info!(
        "perf gate: median_delta={median_delta}% worst={worst_delta}% threshold={threshold}% -> {}",
        if ci_gate { "PASS" } else { "FAIL" }
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
    let a12 = stats::vargha_delaney_a12(rs_values, c_values);

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
            "value": round(a12, 4),
            "label": stats::a12_label(a12),
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
        assert!(value["ci_95"]["lo"].as_f64().unwrap() <= value["ci_95"]["hi"].as_f64().unwrap());
        assert!(compare_metric(&[1.0], &rs, 0.05, 10, 1).unwrap().is_none());
    }
}
