//! Phase 1 screening synthesizer (v1 `compare/screen`) over the v2
//! content-addressed p1 layout: per domain the newest complete
//! manifest wins and its hash is recorded in the output (v1 had a
//! single baseline dir). Campaign crash classification is produced
//! with the same classifier the fuzz comparator uses, so screening
//! works straight off a phase-1 run without a compare pass first.
//! Output: results/p1/<driver>/screening.json.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context};
use serde_json::json;
use tracing::{info, warn};

use super::fuzz::{classify_campaign, load_validated_crashes, unmatched_overrides, Classifier};
use super::safety::{get, number, read_csv};
use super::verdict::worst_quality;
use crate::block::cli::{Scope, ScreenOpts};
use crate::block::results::{self, Manifest};
use crate::config::{anchored, Project};

pub(crate) fn drive(scope: &Scope, opts: &ScreenOpts) -> anyhow::Result<()> {
    let project = Project::locate()?;
    let results_root = anchored(&project.root, &scope.output);
    let subjects = crate::block::subjects(&project.config, &scope.only);
    if subjects.is_empty() {
        bail!("no matching C drivers in the [block.drivers] registry");
    }
    let overrides = match &opts.validated_crashes {
        Some(path) => load_validated_crashes(path)?,
        None => HashMap::new(),
    };
    let _gate = results::gate_lock(&results_root)?;

    for subject in subjects {
        let c_name = subject.c_name;
        let driver_root = results_root.join("p1").join(c_name);
        // Last time's screening does not survive into this run: a
        // screen that fails halfway must not leave the old artifact
        // looking like this run's result.
        let out = driver_root.join("screening.json");
        if out.exists() {
            fs::remove_file(&out).with_context(|| format!("removing stale {}", out.display()))?;
        }
        let static_pick = latest_complete(&driver_root.join("static"), c_name, "static")?;
        let fuzz_pick = latest_complete(&driver_root.join("fuzz"), c_name, "fuzz")?;
        // Screening is a phase-1 verdict on the C driver. A
        // registered counterpart only widens crash attribution, so a
        // driver nobody has rewritten screens on its own name.
        let mut names = vec![c_name];
        names.extend(subject.rs.map(|(rs_name, _)| rs_name));
        let abstractions = subject
            .rs
            .map(|(_, driver)| driver.abstractions.as_slice())
            .unwrap_or_default();
        let classifier = Classifier::new(&names, abstractions)?;

        let historical = match &static_pick {
            Some((dir, _, _)) => historical_risk(dir),
            None => missing("missing commit-history artifacts"),
        };
        let surface = match &static_pick {
            Some((dir, _, _)) => static_surface(dir),
            None => missing("missing static surface artifacts"),
        };
        let (dynamic, campaign_count) = match &fuzz_pick {
            Some((dir, _, manifest)) => dynamic_robustness(dir, manifest, &classifier, &overrides)?,
            None => (missing("missing fuzz campaign artifacts"), 0),
        };
        let tract = tractability(static_pick.is_some(), fuzz_pick.is_some(), campaign_count);

        let dimensions = json!({
            "historical_risk": historical,
            "static_surface": surface,
            "dynamic_robustness": dynamic,
            "tractability": tract,
        });
        let (overall, status) = rate(&dimensions);

        let result = json!({
            "driver": c_name,
            "sources": {
                "static": static_pick.as_ref().map(|(_, hash, _)| hash.clone()),
                "fuzz": fuzz_pick.as_ref().map(|(_, hash, _)| hash.clone()),
            },
            "data_quality": {"status": status},
            "dimensions": dimensions,
            "overall": overall,
        });
        fs::create_dir_all(&driver_root)?;
        fs::write(&out, serde_json::to_string_pretty(&result)?)?;
        info!("screening {c_name}: {overall} -> {}", out.display());
    }
    Ok(())
}

fn missing(evidence: &str) -> serde_json::Value {
    json!({"score": null, "evidence": evidence, "data_quality": "unavailable"})
}

/// v1's screening rating: the mean of the scored dimensions, with
/// fewer than two scores refusing to rate at all, and the worst
/// data quality of the dimensions that produced any.
fn rate(dimensions: &serde_json::Value) -> (&'static str, &str) {
    let blocks = || {
        dimensions
            .as_object()
            .expect("screening dimensions are an object")
            .values()
    };
    let scores: Vec<f64> = blocks()
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
        blocks()
            .filter_map(|dimension| dimension["data_quality"].as_str())
            .filter(|status| *status != "unavailable"),
    );
    (overall, status)
}

/// Newest complete manifest under results/p1/<driver>/<domain>/.
/// Every complete baseline found there must be what the path says
/// it is: this driver, this domain, filed under its own identity
/// hash, with no campaign record and a plan the gates can run. A
/// misfiled or corrupt baseline is an error, not one to skip past,
/// since the pick is recorded as the screening's source.
fn latest_complete(
    domain_root: &Path,
    c_name: &str,
    domain: &str,
) -> anyhow::Result<Option<(PathBuf, String, Manifest)>> {
    if !domain_root.is_dir() {
        return Ok(None);
    }
    // Sorted, so two baselines minted in the same second resolve by
    // hash rather than by directory order: the pick is recorded in
    // screening.json, and a run has to re-derive it.
    let mut entries: Vec<PathBuf> = fs::read_dir(domain_root)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    let mut best: Option<(u64, PathBuf, String, Manifest)> = None;
    for path in entries {
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
        ensure!(
            manifest.p2.is_none(),
            "{}: carries a campaign record; phase-2 data filed as a baseline",
            path.display()
        );
        ensure!(
            manifest.identity.driver == c_name && manifest.identity.domain == domain,
            "{}: holds {} {} data, not {c_name} {domain} data",
            path.display(),
            manifest.identity.driver,
            manifest.identity.domain
        );
        let actual = results::identity_hash(&manifest.identity)?;
        ensure!(
            actual == hash,
            "{}: identity hashes to {actual}, not to its directory name",
            path.display()
        );
        if let Err(why) = manifest.identity.validate() {
            bail!("{}: {why}", path.display());
        }
        if best
            .as_ref()
            .is_none_or(|(created, _, _, _)| manifest.created >= *created)
        {
            best = Some((manifest.created, path, hash, manifest));
        }
    }
    Ok(best.map(|(_, path, hash, manifest)| (path, hash, manifest)))
}

/// Validated CWE wins over the automatic one, as in the safety gate.
fn cwe(row: &super::safety::Row) -> &str {
    let manual = get(row, "manual_cwe").trim();
    if manual.is_empty() {
        get(row, "auto_cwe").trim()
    } else {
        manual
    }
}

/// Scored from commits.csv itself. commits_summary.csv is derived
/// from the same rows by the static phase; reading the totals from
/// it scored a driver whose summary was absent at zero, with ten
/// safety-related commits sitting in the table beside it.
fn historical_risk(static_dir: &Path) -> serde_json::Value {
    let commits = read_csv(&static_dir.join("commits.csv"));
    if commits.is_empty() {
        return missing("missing commit-history artifacts");
    }
    let total_commits = commits.len() as u64;
    let safety_related = commits
        .iter()
        .filter(|row| get(row, "safety_related").trim() == "true" || !cwe(row).is_empty())
        .count() as u64;
    let safety_pct = safety_related as f64 * 100.0 / total_commits as f64;

    let score = if safety_pct >= 40.0 || safety_related >= 25 {
        3
    } else if safety_pct >= 20.0 || safety_related >= 10 {
        2
    } else {
        u8::from(safety_related > 0)
    };
    // The same rule as the safety gate: validated means every
    // classified commit was reviewed by a person, whose signature is
    // the validator column, not that one row carries a manual CWE.
    let classified: Vec<&super::safety::Row> =
        commits.iter().filter(|row| !cwe(row).is_empty()).collect();
    let quality = if !classified.is_empty()
        && classified
            .iter()
            .all(|row| !get(row, "validator").trim().is_empty())
    {
        "manually_validated"
    } else {
        "inferred"
    };
    json!({
        "score": score,
        "evidence": format!(
            "{safety_related}/{total_commits} safety-related commits \
             ({safety_pct:.1}% of observed history)"
        ),
        "data_quality": quality,
    })
}

fn static_surface(static_dir: &Path) -> serde_json::Value {
    let functions = read_csv(&static_dir.join("functions.csv"));
    let densities = read_csv(&static_dir.join("unsafe_density.csv"));
    if functions.is_empty() && densities.is_empty() {
        return missing("missing static surface artifacts");
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

    // The two upper bands read either measure, so the bottom one does
    // too. Keying it on lines alone scored a driver whose function
    // table came back empty at 0 -- below a one-line driver -- while
    // its unsafe-operation census sat there measured and ignored.
    // This is a deliberate divergence from v1's rubric.
    let score = if total_lines >= 2000 || unsafe_ops >= 500 {
        3
    } else if total_lines >= 800 || unsafe_ops >= 150 {
        2
    } else {
        u8::from(total_lines > 0 || unsafe_ops > 0)
    };
    json!({
        "score": score,
        "evidence": format!(
            "{} functions, {total_lines} lines, {unsafe_ops} implicit unsafe operations",
            functions.len()
        ),
        "data_quality": "measured",
    })
}

/// Returns the dimension and the number of usable campaigns: the
/// ones that completed or crashed, which is what tractability counts.
/// A campaign that did neither is no evidence of anything, and eight
/// of them beside two real ones used to make a ten-campaign baseline.
fn dynamic_robustness(
    fuzz_dir: &Path,
    manifest: &Manifest,
    classifier: &Classifier,
    overrides: &HashMap<(String, String), super::fuzz::OverrideRow>,
) -> anyhow::Result<(serde_json::Value, usize)> {
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
    // The plan bounds the data here as it does in compare.
    let planned = manifest
        .identity
        .fuzz
        .as_ref()
        .map_or(0, |knobs| knobs.campaigns) as usize;
    ensure!(
        dirs.len() == planned,
        "{}: {} campaign directories, but the manifest declares {planned}",
        fuzz_dir.display(),
        dirs.len()
    );

    let (mut target, mut infra, mut unknown) = (0u64, 0u64, 0u64);
    let mut qualities = Vec::new();
    let mut summaries = Vec::new();
    for dir in &dirs {
        let summary = classify_campaign(classifier, dir, overrides)?;
        target += summary.counts.target;
        infra += summary.counts.infra;
        unknown += summary.counts.unknown;
        qualities.push(summary.quality);
        summaries.push(summary);
    }
    let usable = summaries
        .iter()
        .filter(|summary| summary.quality != "unavailable")
        .count();
    for summary in &summaries {
        if summary.quality == "unavailable" {
            warn!(
                "campaign {} neither completed nor crashed; not counted as tractable exposure",
                summary.id()
            );
        }
    }
    unmatched_overrides(overrides, &summaries.iter().collect::<Vec<_>>());

    let score = if target > 0 {
        3
    } else if unknown > 0 {
        2
    } else {
        u8::from(infra > 0)
    };
    let quality = if qualities.is_empty() {
        "unavailable"
    } else if qualities.contains(&"manually_validated") {
        "manually_validated"
    } else if qualities.contains(&"unavailable") {
        "inferred"
    } else {
        "measured"
    };
    Ok((
        json!({
            "score": score,
            "evidence": format!(
                "{} campaigns ({usable} completed or crashed); target={target}, \
                 infrastructure={infra}, unknown={unknown}",
                dirs.len()
            ),
            "data_quality": quality,
        }),
        usable,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::results::Identity;

    /// A minimal static-domain identity, distinguished by `prep` so
    /// two baselines can coexist under their own hashes.
    fn manifest(created: u64, prep: &str) -> Manifest {
        Manifest {
            complete: true,
            created,
            seed: 1,
            koxi: "test".to_owned(),
            device: std::collections::BTreeMap::new(),
            identity: Identity {
                domain: "static".to_owned(),
                driver: "null_blk".to_owned(),
                spec: "c:null_blk:null_blk.ko:/dev/nullb0:::".to_owned(),
                prep: prep.to_owned(),
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

    /// Save under the identity's own hash, as the phases do.
    fn file(domain: &Path, manifest: &Manifest) -> String {
        let hash = results::identity_hash(&manifest.identity).unwrap();
        manifest.save(&domain.join(&hash)).unwrap();
        hash
    }

    fn pick(domain: &Path) -> anyhow::Result<Option<String>> {
        Ok(latest_complete(domain, "null_blk", "static")?.map(|(_, hash, _)| hash))
    }

    #[test]
    fn baseline_pick_is_deterministic_when_baselines_share_a_second() {
        let dir = tempfile::tempdir().unwrap();
        let domain = dir.path().join("static");
        // Two complete baselines minted in the same second: the pick
        // is recorded in screening.json, so it must not depend on the
        // order the filesystem hands the directories back.
        let mut hashes: Vec<String> = ["", "echo 1 > x"]
            .iter()
            .map(|prep| file(&domain, &manifest(1_700_000_000, prep)))
            .collect();
        hashes.sort();
        let picked = pick(&domain).unwrap().unwrap();
        assert_eq!(picked, hashes[1], "ties resolve by sorted name");
        for _ in 0..8 {
            assert_eq!(pick(&domain).unwrap().unwrap(), picked);
        }
    }

    #[test]
    fn newer_baselines_still_win_over_older_ones() {
        let dir = tempfile::tempdir().unwrap();
        let domain = dir.path().join("static");
        file(&domain, &manifest(10, "zzz"));
        let newer = file(&domain, &manifest(20, "aaa"));
        assert_eq!(
            pick(&domain).unwrap().unwrap(),
            newer,
            "recency beats the tie-break"
        );
    }

    #[test]
    fn an_incomplete_baseline_is_never_picked() {
        let dir = tempfile::tempdir().unwrap();
        let domain = dir.path().join("static");
        let mut partial = manifest(99, "");
        partial.complete = false;
        file(&domain, &partial);
        assert!(pick(&domain).unwrap().is_none());
        assert!(pick(&dir.path().join("absent")).unwrap().is_none());
    }

    /// The pick is recorded as the screening's source, so what sits
    /// under the domain root must be what the path says it is.
    /// Hardening 50.
    #[test]
    fn a_misfiled_baseline_is_an_error_not_a_skip() {
        use crate::block::results::Campaign;
        let dir = tempfile::tempdir().unwrap();
        let domain = dir.path().join("static");
        let expect = |manifest: &Manifest, name: &str, needle: &str| {
            manifest.save(&domain.join(name)).unwrap();
            let error = pick(&domain).unwrap_err().to_string();
            assert!(error.contains(needle), "{needle}: {error}");
            fs::remove_dir_all(domain.join(name)).unwrap();
        };
        let good = manifest(1, "");
        let hash = results::identity_hash(&good.identity).unwrap();
        expect(&good, "0123456789ab", "hashes to");
        let mut fuzz = good.clone();
        fuzz.identity.domain = "fuzz".into();
        let fuzz_hash = results::identity_hash(&fuzz.identity).unwrap();
        expect(&fuzz, &fuzz_hash, "holds null_blk fuzz data");
        let mut other = good.clone();
        other.identity.driver = "brd".into();
        let other_hash = results::identity_hash(&other.identity).unwrap();
        expect(&other, &other_hash, "holds brd static data");
        let mut filed = good.clone();
        filed.p2 = Some(Campaign {
            campaign: "trial".into(),
            c_driver: "null_blk".into(),
            rs_driver: "rnull".into(),
            baseline: hash.clone(),
        });
        expect(&filed, &hash, "campaign record");
        file(&domain, &good);
        assert_eq!(pick(&domain).unwrap().unwrap(), hash);
    }

    /// Writes the two CSVs `static_surface` reads.
    fn surface_dir(functions: &str, densities: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("functions.csv"), functions).unwrap();
        fs::write(dir.path().join("unsafe_density.csv"), densities).unwrap();
        dir
    }

    fn commits_dir(commits: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("commits.csv"), commits).unwrap();
        dir
    }

    /// The v1 screening bands. These numbers are the Phase-1 rubric:
    /// moving one re-rates every candidate, so they are pinned here
    /// rather than left to the next reader to infer. Scored from the
    /// commit rows, not from a summary table that may be absent.
    /// Hardening 49.
    #[test]
    fn historical_risk_follows_the_v1_bands() {
        use std::fmt::Write as _;
        let table = |total: u32, safety: u32, validator: &str| {
            let mut csv = String::from("hash,safety_related,auto_cwe,manual_cwe,validator\n");
            for index in 0..total {
                let related = index < safety;
                let _ = writeln!(
                    csv,
                    "{index},{related},{},,{}",
                    if related { "CWE-416" } else { "" },
                    if related { validator } else { "" }
                );
            }
            csv
        };
        let band = |total: u32, safety: u32| -> u64 {
            let dir = commits_dir(&table(total, safety, ""));
            historical_risk(dir.path())["score"].as_u64().unwrap()
        };
        assert_eq!(band(100, 40), 3, "40% is the top band");
        assert_eq!(band(200, 25), 3, "25 safety commits also reaches it");
        assert_eq!(band(100, 20), 2, "20% is the middle band");
        assert_eq!(band(200, 10), 2, "10 commits also reaches it");
        assert_eq!(band(100, 1), 1, "any safety commit scores");
        assert_eq!(band(100, 0), 0, "none does not");

        // Validated means every classified row signed, as in the
        // safety gate; one manual CWE without a validator is not.
        let signed = commits_dir(&table(10, 10, "reviewer"));
        assert_eq!(
            historical_risk(signed.path())["data_quality"],
            "manually_validated"
        );
        let unsigned = commits_dir(&table(10, 10, ""));
        assert_eq!(historical_risk(unsigned.path())["data_quality"], "inferred");
        let one_manual = commits_dir(
            "hash,safety_related,auto_cwe,manual_cwe,validator\n\
             a,true,CWE-401,CWE-416,\nb,true,CWE-416,,\n",
        );
        assert_eq!(
            historical_risk(one_manual.path())["data_quality"],
            "inferred"
        );
    }

    #[test]
    fn static_surface_follows_the_v1_bands() {
        let ops = |n: u64| {
            format!(
                "language,ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\n\
                 C,{n},0,0,0,0\n"
            )
        };
        let lines = |n: u64| format!("name,line_count\nf,{n}\n");
        let score = |f: &str, d: &str| {
            let dir = surface_dir(f, d);
            static_surface(dir.path())["score"].as_u64().unwrap()
        };
        assert_eq!(
            score(&lines(2000), &ops(0)),
            3,
            "2000 lines is the top band"
        );
        assert_eq!(
            score(&lines(0), &ops(500)),
            3,
            "500 unsafe ops also reaches it"
        );
        assert_eq!(
            score(&lines(800), &ops(0)),
            2,
            "800 lines is the middle band"
        );
        assert_eq!(
            score(&lines(0), &ops(150)),
            2,
            "150 unsafe ops also reaches it"
        );
        assert_eq!(score(&lines(1), &ops(0)), 1, "any measured line scores");
        assert_eq!(score(&lines(0), &ops(0)), 0, "an empty surface does not");
    }

    /// The bottom band reads both measures, like the two above it. A
    /// driver whose function table came back empty but whose
    /// unsafe-operation census did not is measured surface, not absent
    /// surface, and must not rank below a one-line driver.
    #[test]
    fn static_surface_bottom_band_counts_unsafe_ops_too() {
        let dir = surface_dir(
            "name,line_count\n",
            "language,ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\nC,140,0,0,0,0\n",
        );
        assert_eq!(
            static_surface(dir.path())["score"].as_u64().unwrap(),
            1,
            "140 measured operations is surface"
        );
        // Nothing measured on either axis still scores nothing.
        let empty = surface_dir(
            "name,line_count\nf,0\n",
            "language,ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\nC,0,0,0,0,0\n",
        );
        assert_eq!(static_surface(empty.path())["score"].as_u64().unwrap(), 0);
    }

    #[test]
    fn tractability_needs_both_domains_and_ten_campaigns() {
        assert_eq!(tractability(true, true, 10)["score"], 3);
        assert_eq!(tractability(true, true, 9)["score"], 2);
        assert_eq!(tractability(true, false, 0)["score"], 1);
        assert_eq!(tractability(false, true, 99)["score"], 1);
        assert!(tractability(false, false, 0)["score"].is_null());
    }

    /// Fewer than two scored dimensions is not a weak candidate, it is
    /// no candidate assessment at all.
    #[test]
    fn rating_refuses_to_average_a_single_dimension() {
        let one = json!({
            "a": {"score": 3, "data_quality": "measured"},
            "b": missing("nothing"),
            "c": missing("nothing"),
            "d": missing("nothing"),
        });
        assert_eq!(rate(&one).0, "inconclusive");
        // Quality describes the dimensions that produced data, so a
        // single measured dimension still reports "measured" even when
        // the rating itself refuses to conclude.
        assert_eq!(rate(&one).1, "measured");

        let two = json!({
            "a": {"score": 3, "data_quality": "measured"},
            "b": {"score": 2, "data_quality": "inferred"},
            "c": missing("nothing"),
            "d": missing("nothing"),
        });
        assert_eq!(
            rate(&two),
            ("strong_candidate", "inferred"),
            "2.5 rounds up"
        );

        let weak = json!({
            "a": {"score": 1, "data_quality": "measured"},
            "b": {"score": 1, "data_quality": "measured"},
            "c": {"score": 2, "data_quality": "measured"},
            "d": {"score": 2, "data_quality": "measured"},
        });
        assert_eq!(rate(&weak), ("moderate", "measured"));
    }
}
