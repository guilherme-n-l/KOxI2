//! The overall verdict (v1 `compare/verdict`): folds the three
//! dimension JSONs from a campaign's compare/ dir into verdict.json
//! with a pass/fail/partial/inconclusive overall and the
//! recommendation matrix. Divergences from v1: the timestamp is
//! unix seconds (the repo's manifest convention — no calendar
//! dependency), baselines are recorded per domain (v2 has one
//! content-addressed baseline per domain, not one per campaign),
//! and the fuzzing key numbers surface the rate-ratio bound that
//! now gates alongside the descriptive rank stats.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::json;
use tracing::info;

use crate::util::unix_now;

const QUALITY_ORDER: [&str; 4] = ["unavailable", "inferred", "measured", "manually_validated"];

fn quality_rank(status: &str) -> usize {
    QUALITY_ORDER
        .iter()
        .position(|known| *known == status)
        .unwrap_or(1) // unknown labels rank as inferred, v1-style
}

pub(super) fn worst_quality<'a>(statuses: impl Iterator<Item = &'a str>) -> &'a str {
    statuses
        .min_by_key(|status| quality_rank(status))
        .unwrap_or("unavailable")
}

/// (safety, fuzzing, performance) -> recommendation.
fn recommendation(key: (bool, bool, bool)) -> &'static str {
    match key {
        (true, true, true) => "Replace: Rust driver meets all criteria for production use",
        (true, true, false) => "Caution: safety and fuzzing pass but performance regresses",
        (true, false, true) => "Caution: fuzzing shows regression, investigate before replacing",
        (true, false, false) => "Do not replace: fuzzing and performance both regress",
        (false, true, true) => "Caution: safety elimination rate below threshold",
        (false, true, false) => "Do not replace: safety and performance fail",
        (false, false, true) => "Do not replace: safety and fuzzing both fail",
        (false, false, false) => "Do not replace: all dimensions fail",
    }
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

fn summarize(name: &str, data: Option<&serde_json::Value>) -> serde_json::Value {
    let Some(data) = data else {
        return json!({"available": false, "pass": null, "data_quality": "unavailable"});
    };
    let pass = data["verdict"]["pass"].clone();
    let quality = data["data_quality"]["status"]
        .as_str()
        .unwrap_or("inferred");
    match name {
        "safety" => json!({
            "available": true,
            "pass": pass,
            "data_quality": quality,
            "summary": data["comparison"]["elimination_detail"].as_str().unwrap_or(""),
            "key_numbers": {
                "elimination_rate": data["comparison"]["elimination_rate"],
                "threshold": data["verdict"]["threshold"],
            },
        }),
        "fuzzing" => {
            let metrics = &data["metrics"];
            let metric_name = if metrics.get("target_attributable_crashes").is_some() {
                "target_attributable_crashes"
            } else {
                "unique_crashes"
            };
            json!({
                "available": true,
                "pass": pass,
                "data_quality": quality,
                "summary": data["verdict"]["detail"].as_str().unwrap_or(""),
                "key_numbers": {
                    "metric": metric_name,
                    "p_value": metrics[metric_name]["test"]["p_value"],
                    "a12": metrics[metric_name]["effect_size"]["value"],
                    "rate_ratio_upper": data["rate_ratio"]["ratio"]["ci"]["hi"],
                    "outcome": data["verdict"]["outcome"],
                    "gate_basis": data["verdict"]["gate_basis"],
                },
            })
        }
        "performance" => json!({
            "available": true,
            "pass": pass,
            "data_quality": quality,
            "summary": data["verdict"]["detail"].as_str().unwrap_or(""),
            "key_numbers": {
                "median_delta_pct": data["aggregate"]["median_delta_pct"],
                "workloads_passing_tost": data["aggregate"]["workloads_passing_tost"],
                "threshold": data["verdict"]["threshold"],
            },
        }),
        _ => json!({"available": false, "pass": null, "data_quality": "unavailable"}),
    }
}

/// What the dimensions add up to: v1's overall label, the
/// recommendation row it selects, and the caveat that choice implies.
struct Outcome {
    overall: &'static str,
    recommendation: String,
    caveat: Option<String>,
}

/// Fold the three dimension summaries into the overall verdict.
/// "partial" means a dimension is missing outright; "inconclusive"
/// means what is present did not decide.
fn decide(dimensions: &serde_json::Map<String, serde_json::Value>) -> Outcome {
    let available: Vec<&serde_json::Value> = dimensions
        .values()
        .filter(|summary| summary["available"].as_bool() == Some(true))
        .collect();
    let missing: Vec<&str> = dimensions
        .iter()
        .filter(|(_, summary)| summary["available"].as_bool() != Some(true))
        .map(|(name, _)| name.as_str())
        .collect();

    if available.is_empty() {
        return Outcome {
            overall: "inconclusive",
            recommendation: "Inconclusive: no comparison dimensions were measured".to_string(),
            caveat: Some("missing dimensions: safety, fuzzing, performance".into()),
        };
    }

    let all_present = missing.is_empty();
    let passes: Vec<Option<bool>> = ["safety", "fuzzing", "performance"]
        .iter()
        .map(|name| dimensions[*name]["pass"].as_bool())
        .collect();
    let all_decidable = all_present && passes.iter().all(Option::is_some);
    let any_fail = passes.contains(&Some(false));
    let all_pass = all_present && passes.iter().all(|pass| *pass == Some(true));
    let none_decidable = available
        .iter()
        .all(|summary| summary["pass"].as_bool().is_none());

    if none_decidable {
        Outcome {
            overall: "inconclusive",
            recommendation: "Inconclusive: available dimensions did not yield usable verdicts"
                .to_string(),
            caveat: None,
        }
    } else if all_decidable {
        let key = (passes[0].unwrap(), passes[1].unwrap(), passes[2].unwrap());
        Outcome {
            overall: if any_fail {
                "fail"
            } else if all_pass {
                "pass"
            } else {
                "inconclusive"
            },
            recommendation: recommendation(key).to_string(),
            caveat: None,
        }
    } else if missing.is_empty() {
        Outcome {
            overall: "inconclusive",
            recommendation: "Inconclusive: at least one dimension did not yield a decisive verdict"
                .to_string(),
            caveat: None,
        }
    } else {
        let missing_msg = missing.join(", ");
        Outcome {
            overall: "partial",
            recommendation: format!(
                "Partial evidence only: missing dimensions prevent a full verdict \
                 ({missing_msg})"
            ),
            caveat: Some(format!("missing dimensions: {missing_msg}")),
        }
    }
}

pub fn write_verdict(
    compare_dir: &Path,
    campaign: &str,
    baselines: &BTreeMap<String, String>,
    c_name: &str,
    rs_name: &str,
    screening: Option<&serde_json::Value>,
) -> anyhow::Result<()> {
    let files = [
        ("safety", "safety.json"),
        ("fuzzing", "fuzz_stats.json"),
        ("performance", "perf_stats.json"),
    ];
    let mut dimensions = serde_json::Map::new();
    let mut caveats: Vec<String> = Vec::new();
    for (name, file) in files {
        let data = read_json(&compare_dir.join(file));
        if data.is_none() {
            caveats.push(format!("{name}: not available (data missing)"));
        }
        dimensions.insert(name.to_string(), summarize(name, data.as_ref()));
    }

    let Outcome {
        overall,
        recommendation: recommendation_text,
        caveat,
    } = decide(&dimensions);
    caveats.extend(caveat);

    let overall_status = worst_quality(
        dimensions
            .values()
            .filter_map(|summary| summary["data_quality"].as_str())
            .filter(|status| *status != "unavailable"),
    );

    let result = json!({
        "timestamp": unix_now(),
        "campaign": campaign,
        "baselines": baselines,
        "drivers": {"c": c_name, "rs": rs_name},
        "data_quality": {
            "status": overall_status,
            "dimensions": dimensions
                .iter()
                .map(|(name, summary)| (name.clone(), summary["data_quality"].clone()))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
            "phase1_screening": screening
                .and_then(|value| value["data_quality"]["status"].as_str())
                .unwrap_or("unavailable"),
        },
        "dimensions": dimensions,
        "phase1_screening": screening,
        "overall": overall,
        "recommendation": recommendation_text,
        "caveats": caveats,
    });
    let out = compare_dir.join("verdict.json");
    fs::write(&out, serde_json::to_string_pretty(&result)?)?;

    info!("verdict -> {}", out.display());
    info!("overall={overall}: {recommendation_text}");
    for (name, summary) in result["dimensions"].as_object().unwrap() {
        if summary["available"].as_bool() != Some(true) {
            continue;
        }
        let status = match summary["pass"].as_bool() {
            Some(true) => "PASS",
            Some(false) => "FAIL",
            None => "SKIP",
        };
        info!(
            "  {name}: {status} — {}",
            summary["summary"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_in(dir: &Path) -> serde_json::Value {
        serde_json::from_str(&fs::read_to_string(dir.join("verdict.json")).unwrap()).unwrap()
    }

    #[test]
    fn verdict_combines_dimensions_like_v1() {
        let dir = std::env::temp_dir().join(format!("koxi-verdict-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, value: serde_json::Value| {
            fs::write(dir.join(name), serde_json::to_string(&value).unwrap()).unwrap();
        };

        // All three present, fuzzing fails -> overall fail with the
        // matching recommendation row.
        write(
            "safety.json",
            json!({"verdict": {"pass": true, "threshold": 34.2},
                   "comparison": {"elimination_rate": 0.5, "elimination_detail": "d"},
                   "data_quality": {"status": "manually_validated"}}),
        );
        write(
            "fuzz_stats.json",
            json!({"verdict": {"pass": false, "detail": "ratio unbounded",
                               "gate_basis": "rate_ratio_ci"},
                   "metrics": {"target_attributable_crashes": {
                       "test": {"p_value": 0.4}, "effect_size": {"value": 0.6}}},
                   "rate_ratio": {"ratio": {"ci": {"hi": 19.0}}},
                   "data_quality": {"status": "measured"}}),
        );
        write(
            "perf_stats.json",
            json!({"verdict": {"pass": true, "detail": "ok", "threshold": 5.0},
                   "aggregate": {"median_delta_pct": -1.0, "workloads_passing_tost": "18/18"},
                   "data_quality": {"status": "measured"}}),
        );
        let mut baselines = BTreeMap::new();
        baselines.insert("perf".to_string(), "abc123".to_string());
        write_verdict(&dir, "trial", &baselines, "null_blk", "rnull", None).unwrap();
        let verdict = verdict_in(&dir);
        assert_eq!(verdict["overall"], "fail");
        assert_eq!(
            verdict["recommendation"],
            "Caution: fuzzing shows regression, investigate before replacing"
        );
        // Worst-of quality across available dimensions.
        assert_eq!(verdict["data_quality"]["status"], "measured");
        assert_eq!(
            verdict["dimensions"]["fuzzing"]["key_numbers"]["rate_ratio_upper"],
            19.0
        );

        // Missing a dimension -> partial with a caveat.
        fs::remove_file(dir.join("fuzz_stats.json")).unwrap();
        write_verdict(&dir, "trial", &baselines, "null_blk", "rnull", None).unwrap();
        let verdict = verdict_in(&dir);
        assert_eq!(verdict["overall"], "partial");
        assert!(verdict["caveats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|caveat| caveat.as_str().unwrap().contains("fuzzing")));

        fs::remove_dir_all(&dir).unwrap();
    }
}
