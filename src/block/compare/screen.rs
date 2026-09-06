//! Phase 1 screening synthesizer (v1 `compare/screen`) over the v2
//! content-addressed p1 layout: per domain the newest complete
//! manifest wins and its hash is recorded in the output (v1 had a
//! single baseline dir). Campaign crash classification is produced
//! with the same classifier the fuzz comparator uses, so screening
//! works straight off a phase-1 run without a compare pass first.
//! Output: results/p1/<driver>/screening.json.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::json;
use tracing::{error, info};

use super::fuzz::{classify_campaign, load_validated_crashes, Classifier};
use super::safety::{get, number, read_csv};
use super::verdict::worst_quality;
use crate::block::cli::Opts;
use crate::block::results::Manifest;
use crate::config::{anchored, Project};

pub fn screen(opts: &Opts) -> ExitCode {
    match drive(opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            error!("koxi block screen: {err}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn drive(opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    let project = Project::locate()?;
    let results_root = anchored(&project.root, &opts.output);
    let pairs = crate::block::driver_pairs(&project.config, &opts.only);
    if pairs.is_empty() {
        return Err("no matching driver pairs in the [block.drivers] registry".into());
    }
    let overrides = match &opts.validated_crashes {
        Some(path) => load_validated_crashes(path)?,
        None => Default::default(),
    };

    for (rs_name, _, c_name, _) in pairs {
        let driver_root = results_root.join("p1").join(c_name);
        let static_pick = latest_complete(&driver_root.join("static"))?;
        let fuzz_pick = latest_complete(&driver_root.join("fuzz"))?;
        let classifier = Classifier::new(c_name, rs_name)?;

        let historical = match &static_pick {
            Some((dir, _)) => historical_risk(dir)?,
            None => missing("missing commit-history artifacts"),
        };
        let surface = match &static_pick {
            Some((dir, _)) => static_surface(dir)?,
            None => missing("missing static surface artifacts"),
        };
        let (dynamic, campaign_count) = match &fuzz_pick {
            Some((dir, _)) => dynamic_robustness(dir, &classifier, &overrides)?,
            None => (missing("missing fuzz campaign artifacts"), 0),
        };
        let tract = tractability(static_pick.is_some(), fuzz_pick.is_some(), campaign_count);

        let dimensions = json!({
            "historical_risk": historical,
            "static_surface": surface,
            "dynamic_robustness": dynamic,
            "tractability": tract,
        });
        let scores: Vec<f64> = dimensions
            .as_object()
            .unwrap()
            .values()
            .filter_map(|dimension| dimension["score"].as_f64())
            .collect();
        let overall = if scores.len() < 2 {
            "inconclusive"
        } else {
            let average = scores.iter().sum::<f64>() / scores.len() as f64;
            if average >= 2.5 {
                "strong_candidate"
            } else if average >= 1.5 {
                "moderate"
            } else {
                "weak"
            }
        };
        let status = worst_quality(
            dimensions
                .as_object()
                .unwrap()
                .values()
                .filter_map(|dimension| dimension["data_quality"].as_str())
                .filter(|status| *status != "unavailable"),
        )
        .to_string();

        let result = json!({
            "driver": c_name,
            "sources": {
                "static": static_pick.as_ref().map(|(_, hash)| hash.clone()),
                "fuzz": fuzz_pick.as_ref().map(|(_, hash)| hash.clone()),
            },
            "data_quality": {"status": status},
            "dimensions": dimensions,
            "overall": overall,
        });
        fs::create_dir_all(&driver_root)?;
        let out = driver_root.join("screening.json");
        fs::write(&out, serde_json::to_string_pretty(&result)?)?;
        info!("screening {c_name}: {overall} -> {}", out.display());
    }
    Ok(())
}

fn missing(evidence: &str) -> serde_json::Value {
    json!({"score": null, "evidence": evidence, "data_quality": "unavailable"})
}

/// Newest complete manifest under results/p1/<driver>/<domain>/.
fn latest_complete(
    domain_root: &Path,
) -> Result<Option<(PathBuf, String)>, Box<dyn std::error::Error>> {
    if !domain_root.is_dir() {
        return Ok(None);
    }
    let mut best: Option<(u64, PathBuf, String)> = None;
    for entry in fs::read_dir(domain_root)?.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(manifest) = Manifest::load(&path)? else {
            continue;
        };
        if !manifest.complete {
            continue;
        }
        let hash = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if best
            .as_ref()
            .is_none_or(|(created, _, _)| manifest.created >= *created)
        {
            best = Some((manifest.created, path, hash));
        }
    }
    Ok(best.map(|(_, path, hash)| (path, hash)))
}

fn historical_risk(static_dir: &Path) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let commits = read_csv(&static_dir.join("commits.csv"))?;
    let summary = read_csv(&static_dir.join("commits_summary.csv"))?;
    if commits.is_empty() && summary.is_empty() {
        return Ok(missing("missing commit-history artifacts"));
    }
    let metric = |name: &str| -> f64 {
        summary
            .iter()
            .find(|row| get(row, "metric") == name)
            .and_then(|row| get(row, "value").trim().parse().ok())
            .unwrap_or(0.0)
    };
    let total_commits = {
        let from_summary = metric("total_commits") as u64;
        if from_summary > 0 {
            from_summary
        } else {
            commits.len() as u64
        }
    };
    let safety_related = metric("safety_related") as u64;
    let safety_pct = metric("safety_pct");

    let score = if safety_pct >= 40.0 || safety_related >= 25 {
        3
    } else if safety_pct >= 20.0 || safety_related >= 10 {
        2
    } else if safety_related > 0 {
        1
    } else {
        0
    };
    let quality = if commits
        .iter()
        .any(|row| !get(row, "manual_cwe").trim().is_empty())
    {
        "manually_validated"
    } else {
        "inferred"
    };
    Ok(json!({
        "score": score,
        "evidence": format!(
            "{safety_related}/{total_commits} safety-related commits \
             ({safety_pct:.1}% of observed history)"
        ),
        "data_quality": quality,
    }))
}

fn static_surface(static_dir: &Path) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let functions = read_csv(&static_dir.join("functions.csv"))?;
    let densities = read_csv(&static_dir.join("unsafe_density.csv"))?;
    if functions.is_empty() && densities.is_empty() {
        return Ok(missing("missing static surface artifacts"));
    }
    let total_lines: u64 = functions.iter().map(|row| number(row, "line_count")).sum();
    let unsafe_ops: u64 = densities
        .iter()
        .filter(|row| get(row, "language") == "C")
        .map(|row| {
            [
                "ptr_derefs",
                "alloc_calls",
                "free_calls",
                "memop_calls",
                "cast_exprs",
            ]
            .iter()
            .map(|column| number(row, column))
            .sum::<u64>()
        })
        .sum();

    let score = if total_lines >= 2000 || unsafe_ops >= 500 {
        3
    } else if total_lines >= 800 || unsafe_ops >= 150 {
        2
    } else if total_lines > 0 {
        1
    } else {
        0
    };
    Ok(json!({
        "score": score,
        "evidence": format!(
            "{} functions, {total_lines} lines, {unsafe_ops} implicit unsafe operations",
            functions.len()
        ),
        "data_quality": "measured",
    }))
}

fn dynamic_robustness(
    fuzz_dir: &Path,
    classifier: &Classifier,
    overrides: &std::collections::HashMap<(String, String), super::fuzz::OverrideRow>,
) -> Result<(serde_json::Value, usize), Box<dyn std::error::Error>> {
    let campaigns_dir = fuzz_dir.join("campaigns");
    if !campaigns_dir.is_dir() {
        return Ok((missing("missing fuzz campaign artifacts"), 0));
    }
    let mut dirs: Vec<PathBuf> = fs::read_dir(&campaigns_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();

    let (mut target, mut infra, mut unknown) = (0u64, 0u64, 0u64);
    let mut qualities = Vec::new();
    for dir in &dirs {
        let summary = classify_campaign(classifier, dir, overrides)?;
        target += summary.counts.target;
        infra += summary.counts.infra;
        unknown += summary.counts.unknown;
        qualities.push(summary.quality);
    }

    let score = if target > 0 {
        3
    } else if unknown > 0 {
        2
    } else if infra > 0 {
        1
    } else {
        0
    };
    let quality = if qualities.is_empty() {
        "unavailable"
    } else if qualities
        .iter()
        .any(|quality| *quality == "manually_validated")
    {
        "manually_validated"
    } else if qualities.iter().any(|quality| *quality == "unavailable") {
        "inferred"
    } else {
        "measured"
    };
    Ok((
        json!({
            "score": score,
            "evidence": format!(
                "{} campaigns; target={target}, infrastructure={infra}, unknown={unknown}",
                dirs.len()
            ),
            "data_quality": quality,
        }),
        dirs.len(),
    ))
}

fn tractability(static_present: bool, fuzz_present: bool, campaigns: usize) -> serde_json::Value {
    if !static_present && !fuzz_present {
        return missing("neither static nor fuzz screening inputs are cached");
    }
    let score = if static_present && fuzz_present && campaigns >= 10 {
        3
    } else if static_present && fuzz_present {
        2
    } else {
        1
    };
    json!({
        "score": score,
        "evidence": format!(
            "cached static={}, cached fuzz={}, campaigns={campaigns}",
            if static_present { "yes" } else { "no" },
            if fuzz_present { "yes" } else { "no" }
        ),
        "data_quality": "measured",
    })
}
