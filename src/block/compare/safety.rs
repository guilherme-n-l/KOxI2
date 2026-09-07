//! The safety comparator (v1 `compare/safety`): the C-side picture
//! maps commit-history CWE data onto the ACSAC 2024 taxonomy (Li et
//! al.) and aggregates the implicitly-unsafe operation surface; the
//! Rust-side picture counts explicit unsafe sites with the
//! driver/abstraction split (USENIX ATC 2024 accounting) and Evans
//! et al. density metrics. The gate is v1's: the elimination rate —
//! the fraction of CWE-classified fix commits whose class Rust
//! removes at compile time — must reach --safety-threshold.
//! Validated CWEs (manual_cwe) win over automatic ones, mirroring
//! the static phase.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::json;
use tracing::info;

use crate::block::cli::CompareOpts;
use crate::util::{csv_text, round};

/// ACSAC 2024 taxonomy: CWE -> what Rust does about it.
/// CWE to what Rust does about it.
///
/// The three super-classes are the ACSAC 2024 (Li et al.) labels:
/// auto_eliminated is their "Yes", needs_discipline their "Yes+P",
/// unaffected their "No". The CWE encoding is *ours*: the string
/// "CWE" appears nowhere in that paper, which classifies by named bug
/// class. CWE is what a commit history yields mechanically and a
/// named-class taxonomy is not, so the translation is deliberate —
/// but it is a translation, with judgement in it, and it diverges
/// from their labels in both directions:
///
/// - More generous than they are: they put null dereference (0/17/0),
///   integer arithmetic (0/6/0) and buffer overflow (0/44/1) in
///   "Yes+P", needing the programmer to reach for the checked
///   operation; this table eliminates them outright.
/// - More conservative: they eliminate 41 of 42 race conditions
///   outright, their largest "Yes" group and the bulk of the 34.2%
///   threshold, while CWE-362 here is unaffected. Likewise missing
///   return value check (15/0/0), which they eliminate.
/// - Anything unlisted falls to unaffected, which is the conservative
///   direction: it can only lower the elimination rate.
///
/// Changing any of this moves the gate, so it is stated rather than
/// silently corrected.
const ACSAC_TAXONOMY: [(&str, &str); 9] = [
    ("CWE-787", "auto_eliminated"),  // out-of-bounds write
    ("CWE-416", "auto_eliminated"),  // use-after-free
    ("CWE-415", "auto_eliminated"),  // double free
    ("CWE-476", "auto_eliminated"),  // null pointer dereference
    ("CWE-457", "auto_eliminated"),  // uninitialized variable
    ("CWE-190", "auto_eliminated"),  // integer overflow
    ("CWE-401", "needs_discipline"), // memory leak (Drop required)
    ("CWE-252", "needs_discipline"), // missing error check (Result helps)
    ("CWE-362", "unaffected"),       // race / deadlock
];

const ACSAC_CLASSES: [&str; 3] = ["auto_eliminated", "needs_discipline", "unaffected"];

fn acsac_examples(class: &str) -> Vec<&'static str> {
    match class {
        "auto_eliminated" => vec![
            "buffer overflow",
            "use-after-free",
            "double free",
            "null deref",
            "uninitialized",
            "integer overflow",
        ],
        "needs_discipline" => vec!["memory leak (Drop)", "missing error check (Result)"],
        _ => vec!["race condition", "deadlock", "logic error"],
    }
}

fn acsac_class(cwe: &str) -> &'static str {
    ACSAC_TAXONOMY
        .iter()
        .find(|(known, _)| *known == cwe)
        .map_or("unaffected", |(_, class)| *class)
}

pub(super) type Row = BTreeMap<String, String>;

/// Quote-aware CSV reader over the whole file (fields may embed
/// commas, doubled quotes, and newlines). Missing file = no rows,
/// matching v1 read_csv.
/// A line that held nothing at all: one field, empty, never quoted.
/// `""` on its own line is a real record of one empty field.
fn blank(record: &[String], quoted_seen: bool) -> bool {
    !quoted_seen && record.len() == 1 && record[0].is_empty()
}

pub(super) fn read_csv(path: &Path) -> Vec<Row> {
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    // Whether this record ever opened a quote, which is what separates
    // a line holding one explicitly empty field ("") from a blank line.
    let mut quoted_seen = false;
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => quoted = false,
                other => field.push(other),
            }
        } else {
            match ch {
                '"' => {
                    quoted = true;
                    quoted_seen = true;
                }
                ',' => record.push(std::mem::take(&mut field)),
                '\n' => {
                    record.push(std::mem::take(&mut field));
                    // The csv crate that writes these files skips empty
                    // lines; the reader has to agree, or an editor's
                    // stray blank line in a hand-validated artifact
                    // becomes a row of empty fields and inflates every
                    // count derived from row totals.
                    if blank(&record, quoted_seen) {
                        record.clear();
                    } else {
                        records.push(std::mem::take(&mut record));
                    }
                    quoted_seen = false;
                }
                '\r' => {}
                other => field.push(other),
            }
        }
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        if !blank(&record, quoted_seen) {
            records.push(record);
        }
    }

    let mut rows = Vec::new();
    let mut header: Option<Vec<String>> = None;
    for record in records {
        match &header {
            None => header = Some(record),
            Some(columns) => {
                let mut row = Row::new();
                for (index, column) in columns.iter().enumerate() {
                    row.insert(
                        column.clone(),
                        record.get(index).cloned().unwrap_or_default(),
                    );
                }
                rows.push(row);
            }
        }
    }
    rows
}

pub(super) fn get<'a>(row: &'a Row, key: &str) -> &'a str {
    row.get(key).map_or("", String::as_str)
}

pub(super) fn number(row: &Row, key: &str) -> u64 {
    get(row, key).trim().parse().unwrap_or(0)
}

/// Validated CWE wins over the automatic one (v1 effective_cwe).
fn effective_cwe(commit: &Row) -> &str {
    let manual = get(commit, "manual_cwe").trim();
    if manual.is_empty() {
        get(commit, "auto_cwe").trim()
    } else {
        manual
    }
}

struct CBaseline {
    json: serde_json::Value,
    acsac_counts: BTreeMap<&'static str, u64>,
}

fn analyze_c_baseline(static_dir: &Path) -> CBaseline {
    let functions = read_csv(&static_dir.join("functions.csv"));
    let densities = read_csv(&static_dir.join("unsafe_density.csv"));
    let commits = read_csv(&static_dir.join("commits.csv"));

    let total_lines: u64 = functions.iter().map(|row| number(row, "line_count")).sum();

    let mut acsac_counts: BTreeMap<&'static str, u64> =
        ACSAC_CLASSES.iter().map(|class| (*class, 0)).collect();
    let mut classified_cwes: BTreeMap<String, u64> = BTreeMap::new();
    for commit in &commits {
        let cwe = effective_cwe(commit);
        if cwe.is_empty() {
            continue;
        }
        *acsac_counts.get_mut(acsac_class(cwe)).unwrap() += 1;
        *classified_cwes.entry(cwe.to_string()).or_insert(0) += 1;
    }

    let implicit_unsafe_ops: u64 = densities
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

    let safety_commits = commits
        .iter()
        .filter(|commit| {
            get(commit, "safety_related") == "true" || !effective_cwe(commit).is_empty()
        })
        .count();

    let by_class: serde_json::Value = ACSAC_CLASSES
        .iter()
        .map(|class| {
            let cwes: Vec<&String> = classified_cwes
                .keys()
                .filter(|cwe| acsac_class(cwe) == *class)
                .collect();
            (
                class.to_string(),
                json!({
                    "count": acsac_counts[class],
                    "cwes": cwes,
                    "examples": acsac_examples(class),
                }),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    CBaseline {
        json: json!({
            "total_functions": functions.len(),
            "total_lines": total_lines,
            "implicit_unsafe_surface": "100% (all C code is implicitly unsafe)",
            "total_commits": commits.len(),
            "safety_related_commits": safety_commits,
            "implicit_unsafe_operations": implicit_unsafe_ops,
            "vulnerability_history": {
                "total_safety_commits": safety_commits,
                "by_acsac_class": by_class,
            },
        }),
        acsac_counts,
    }
}

struct RsCurrent {
    json: serde_json::Value,
    driver_unsafe: u64,
    abstraction_unsafe: u64,
}

fn analyze_rs_current(static_dir: &Path) -> RsCurrent {
    let functions = read_csv(&static_dir.join("functions.csv"));
    let unsafe_sites = read_csv(&static_dir.join("unsafe_sites.csv"));
    let densities = read_csv(&static_dir.join("unsafe_density.csv"));

    let total_functions = functions.len() as u64;
    let total_lines: u64 = functions.iter().map(|row| number(row, "line_count")).sum();
    let unsafe_blocks: u64 = densities
        .iter()
        .map(|row| number(row, "unsafe_blocks"))
        .sum();
    let unsafe_fns: u64 = densities.iter().map(|row| number(row, "unsafe_fns")).sum();

    // Driver vs abstraction split (v1 density_source_tag).
    let density_source = |row: &Row| -> &'static str {
        let driver = get(row, "driver");
        let file = get(row, "file");
        if driver.ends_with("_abstractions")
            || file.contains("/rust/kernel/")
            || file.starts_with("rust/kernel/")
        {
            "abstraction"
        } else {
            "driver"
        }
    };
    let mut by_source = serde_json::Map::new();
    let mut split = BTreeMap::new();
    for source in ["driver", "abstraction"] {
        let sites = unsafe_sites
            .iter()
            .filter(|row| get(row, "source") == source)
            .count() as u64;
        let source_fns: u64 = densities
            .iter()
            .filter(|row| density_source(row) == source)
            .map(|row| number(row, "total_functions"))
            .sum();
        by_source.insert(
            source.to_string(),
            json!({
                "unsafe_sites": sites,
                "density": if source_fns > 0 {
                    round(sites as f64 / source_fns as f64, 4)
                } else {
                    0.0
                },
            }),
        );
        split.insert(source, sites);
    }

    // v1 read classify.csv's auto_purpose; the v2 static phase folds
    // the purpose into unsafe_sites.csv directly.
    let mut classifications: BTreeMap<String, u64> = BTreeMap::new();
    for site in &unsafe_sites {
        let purpose = get(site, "purpose");
        let purpose = if purpose.is_empty() {
            "unknown"
        } else {
            purpose
        };
        *classifications.entry(purpose.to_string()).or_insert(0) += 1;
    }

    let ratio = |count: u64| {
        if total_functions > 0 {
            round(count as f64 / total_functions as f64, 4)
        } else {
            0.0
        }
    };
    RsCurrent {
        json: json!({
            "total_functions": total_functions,
            "total_lines": total_lines,
            "unsafe_functions": unsafe_fns,
            "unsafe_fn_ratio": ratio(unsafe_fns),
            "unsafe_blocks": unsafe_blocks,
            "unsafe_ratio": ratio(unsafe_blocks),
            "by_source": serde_json::Value::Object(by_source),
            "classifications": classifications,
        }),
        driver_unsafe: split["driver"],
        abstraction_unsafe: split["abstraction"],
    }
}

pub fn compare_safety(
    p1_static: &Path,
    p2_static: &Path,
    opts: &CompareOpts,
    outdir: &Path,
) -> anyhow::Result<()> {
    let threshold = opts.safety_threshold;
    let c_baseline = analyze_c_baseline(p1_static);
    let rs_current = analyze_rs_current(p2_static);

    let auto_eliminated = c_baseline.acsac_counts["auto_eliminated"];
    let total_classified: u64 = c_baseline.acsac_counts.values().sum();
    let elimination_rate = if total_classified > 0 {
        auto_eliminated as f64 / total_classified as f64
    } else {
        0.0
    };
    let total_rs_unsafe = rs_current.driver_unsafe + rs_current.abstraction_unsafe;
    let abstraction_ratio = if total_rs_unsafe > 0 {
        rs_current.abstraction_unsafe as f64 / total_rs_unsafe as f64
    } else {
        0.0
    };
    let passed = elimination_rate >= threshold / 100.0;

    let commits = read_csv(&p1_static.join("commits.csv"));
    let quality = if commits
        .iter()
        .any(|commit| !get(commit, "manual_cwe").trim().is_empty())
    {
        "manually_validated"
    } else {
        "inferred"
    };

    let comparison = json!({
        "elimination_rate": round(elimination_rate, 4),
        "elimination_detail": format!(
            "{auto_eliminated} of {total_classified} CWE-classified fix commits \
             eliminated by Rust type system"
        ),
        "abstraction_ratio": round(abstraction_ratio, 4),
        "abstraction_detail": format!(
            "{:.0}% of Rust unsafe is in rust/kernel/ abstractions, not driver code",
            abstraction_ratio * 100.0
        ),
        "residual_unsafe_driver": rs_current.driver_unsafe,
        "residual_unsafe_total": total_rs_unsafe,
    });
    let result = json!({
        "methodology": "ACSAC 2024 (Li et al.) super-classes over a CWE encoding of our \
                        own + Evans et al. density metrics + USENIX ATC 2024 abstraction \
                        accounting",
        "data_quality": {"status": quality},
        "c_baseline": c_baseline.json,
        "rs_current": rs_current.json,
        "comparison": comparison,
        "verdict": {
            "pass": passed,
            "criterion": format!("elimination_rate >= {threshold}%"),
            "threshold": threshold,
            "actual": round(elimination_rate, 4),
        },
    });
    fs::write(
        outdir.join("safety.json"),
        serde_json::to_string_pretty(&result)?,
    )?;
    fs::write(outdir.join("safety.csv"), safety_csv(&result))?;

    info!(
        "safety gate: elimination_rate={:.1}% threshold={threshold}% -> {}",
        elimination_rate * 100.0,
        if passed { "PASS" } else { "FAIL" }
    );
    Ok(())
}

/// v1 safety.csv: flat driver,metric,value rows for the appendix.
fn safety_csv(result: &serde_json::Value) -> String {
    let c = &result["c_baseline"];
    let rs = &result["rs_current"];
    let comparison = &result["comparison"];
    let vuln = &c["vulnerability_history"]["by_acsac_class"];
    let mut rows: Vec<(&str, String, &serde_json::Value)> = vec![
        ("C", "total_functions".into(), &c["total_functions"]),
        ("C", "total_lines".into(), &c["total_lines"]),
        (
            "C",
            "safety_related_commits".into(),
            &c["safety_related_commits"],
        ),
        (
            "C",
            "implicit_unsafe_operations".into(),
            &c["implicit_unsafe_operations"],
        ),
    ];
    for class in ACSAC_CLASSES {
        rows.push(("C", format!("acsac_{class}"), &vuln[class]["count"]));
    }
    for metric in [
        "total_functions",
        "total_lines",
        "unsafe_functions",
        "unsafe_fn_ratio",
        "unsafe_blocks",
        "unsafe_ratio",
    ] {
        rows.push(("Rust", metric.into(), &rs[metric]));
    }
    for source in ["driver", "abstraction"] {
        rows.push((
            "Rust",
            format!("unsafe_sites_{source}"),
            &rs["by_source"][source]["unsafe_sites"],
        ));
    }
    for metric in ["elimination_rate", "abstraction_ratio"] {
        rows.push(("comparison", metric.into(), &comparison[metric]));
    }

    csv_text(|out| {
        out.write_record(["driver", "metric", "value"])?;
        for (driver, metric, value) in rows {
            let value = match value {
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            out.write_record([driver, metric.as_str(), value.as_str()])?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(name), content).unwrap();
    }

    fn fake_static_dirs() -> (std::path::PathBuf, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!("koxi-safety-{}", std::process::id()));
        let c_dir = base.join("c");
        let rs_dir = base.join("rs");
        fs::create_dir_all(&c_dir).unwrap();
        fs::create_dir_all(&rs_dir).unwrap();

        write(
            &c_dir,
            "functions.csv",
            "driver,file,function_name,start_line,end_line,line_count,complexity\n\
             null_blk,main.c,alpha,1,10,10,1\n\
             null_blk,main.c,beta,12,31,20,2\n",
        );
        write(
            &c_dir,
            "unsafe_density.csv",
            "driver,file,language,total_functions,unsafe_blocks,unsafe_fns,unsafe_impls,\
             ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\n\
             null_blk,main.c,C,2,0,0,0,100,3,9,4,4\n",
        );
        // Subject with an embedded comma exercises the quote-aware
        // parser; one validated CWE overrides the automatic one.
        write(
            &c_dir,
            "commits.csv",
            "hash,date,author,subject,driver,safety_related,auto_cwe,manual_cwe,validator,\
             validation_date\n\
             aaa,2026-01-01,dev,\"fix: leak, again\",null_blk,true,CWE-401,CWE-416,gui,2026-09-06\n\
             bbb,2026-01-02,dev,fix oob write,null_blk,true,CWE-787,,,\n\
             ccc,2026-01-03,dev,race fix,null_blk,true,CWE-362,,,\n\
             ddd,2026-01-04,dev,docs,null_blk,false,,,,\n",
        );

        write(
            &rs_dir,
            "functions.csv",
            "driver,file,function_name,start_line,end_line,line_count,complexity\n\
             rnull,rnull.rs,queue_rq,1,20,20,1\n\
             rnull_abstractions,rust/kernel/block.rs,helper,1,5,5,1\n",
        );
        write(
            &rs_dir,
            "unsafe_density.csv",
            "driver,file,language,total_functions,unsafe_blocks,unsafe_fns,unsafe_impls,\
             ptr_derefs,alloc_calls,free_calls,memop_calls,cast_exprs\n\
             rnull,rnull.rs,Rust,1,1,0,0,0,0,0,0,0\n\
             rnull_abstractions,rust/kernel/block.rs,Rust,1,2,0,1,0,0,0,0,0\n",
        );
        write(
            &rs_dir,
            "unsafe_sites.csv",
            "source,file,line,end_line,node_type,contents_preview,purpose\n\
             driver,rnull.rs,3,3,unsafe_block,\"unsafe { a, b }\",ffi\n\
             abstraction,rust/kernel/block.rs,10,10,unsafe_block,unsafe { x },ffi\n\
             abstraction,rust/kernel/block.rs,20,20,unsafe_impl,unsafe impl Send,invariant\n",
        );
        (c_dir, rs_dir)
    }

    #[test]
    fn safety_comparison_matches_v1_semantics() {
        let (c_dir, rs_dir) = fake_static_dirs();
        let c_baseline = analyze_c_baseline(&c_dir);

        // Validated CWE-416 (auto-eliminated) overrides auto CWE-401
        // (needs discipline): 2 auto_eliminated, 0 discipline, 1
        // unaffected.
        assert_eq!(c_baseline.acsac_counts["auto_eliminated"], 2);
        assert_eq!(c_baseline.acsac_counts["needs_discipline"], 0);
        assert_eq!(c_baseline.acsac_counts["unaffected"], 1);
        assert_eq!(c_baseline.json["safety_related_commits"], 3);
        assert_eq!(c_baseline.json["implicit_unsafe_operations"], 120);
        assert_eq!(c_baseline.json["total_lines"], 30);

        let rs_current = analyze_rs_current(&rs_dir);
        assert_eq!(rs_current.driver_unsafe, 1);
        assert_eq!(rs_current.abstraction_unsafe, 2);
        assert_eq!(rs_current.json["unsafe_blocks"], 3);
        assert_eq!(rs_current.json["classifications"]["ffi"], 2);
        assert_eq!(rs_current.json["by_source"]["abstraction"]["density"], 2.0);

        fs::remove_dir_all(c_dir.parent().unwrap()).unwrap();
    }

    #[test]
    fn quoted_csv_fields_survive_commas_and_quotes() {
        let dir = std::env::temp_dir().join(format!("koxi-csv-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.csv");
        fs::write(&path, "a,b\n\"x, y\",\"say \"\"hi\"\"\"\nplain,2\n").unwrap();
        let rows = read_csv(&path);
        assert_eq!(rows[0]["a"], "x, y");
        assert_eq!(rows[0]["b"], "say \"hi\"");
        assert_eq!(rows[1]["a"], "plain");
        assert!(read_csv(&dir.join("missing.csv")).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// safety.csv is a v1 artifact shape: the appendix tables read
    /// these rows in this order.
    #[test]
    fn safety_csv_pins_the_v1_rows() {
        let result = json!({
            "c_baseline": {
                "total_functions": 2,
                "total_lines": 30,
                "safety_related_commits": 3,
                "implicit_unsafe_operations": 120,
                "vulnerability_history": {"by_acsac_class": {
                    "auto_eliminated": {"count": 2},
                    "needs_discipline": {"count": 0},
                    "unaffected": {"count": 1},
                }},
            },
            "rs_current": {
                "total_functions": 2,
                "total_lines": 25,
                "unsafe_functions": 0,
                "unsafe_fn_ratio": 0.0,
                "unsafe_blocks": 3,
                "unsafe_ratio": 1.5,
                "by_source": {
                    "driver": {"unsafe_sites": 1},
                    "abstraction": {"unsafe_sites": 2},
                },
            },
            "comparison": {"elimination_rate": 0.6667, "abstraction_ratio": 0.6667},
        });
        let csv = safety_csv(&result);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "driver,metric,value");
        assert_eq!(lines[1], "C,total_functions,2");
        assert_eq!(lines[4], "C,implicit_unsafe_operations,120");
        assert_eq!(lines[5], "C,acsac_auto_eliminated,2");
        assert_eq!(lines[8], "Rust,total_functions,2");
        assert_eq!(lines[11], "Rust,unsafe_fn_ratio,0.0");
        assert_eq!(lines[14], "Rust,unsafe_sites_driver,1");
        assert_eq!(lines[16], "comparison,elimination_rate,0.6667");
        assert_eq!(lines.len(), 18);
        assert!(csv.ends_with('\n'));
    }

    /// The artifacts are written with the `csv` crate (`util::csv_text`)
    /// and read back by the hand-rolled reader above. commits.csv
    /// carries free-text commit subjects and unsafe_sites.csv carries
    /// source snippets, so the two have to agree on quoting for every
    /// byte a kernel commit can contain.
    #[test]
    fn csv_round_trips_through_the_writer_the_artifacts_use() {
        let nasty = [
            "plain",
            "with, comma",
            "with \"quotes\"",
            "with\nembedded newline",
            "trailing space ",
            "",
            "unicode \u{2713} accent",
            "semi;colon\ttab",
            "unsafe { a, b }",
        ];
        let text = crate::util::csv_text(|out| {
            out.write_record(["idx", "value"])?;
            for (index, value) in nasty.iter().enumerate() {
                out.write_record([index.to_string().as_str(), value])?;
            }
            Ok(())
        });
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("round.csv");
        fs::write(&path, &text).unwrap();

        let rows = read_csv(&path);
        assert_eq!(rows.len(), nasty.len(), "one row per written record");
        for (index, value) in nasty.iter().enumerate() {
            assert_eq!(rows[index]["value"], *value, "field {index} round-tripped");
            assert_eq!(rows[index]["idx"], index.to_string());
        }
    }

    /// A hand-edited artifact (manual_cwe review) can pick up a blank
    /// line. It must not become a phantom row: row counts feed
    /// total_functions and the commit totals.
    #[test]
    fn blank_lines_are_not_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blank.csv");
        fs::write(&path, "a,b\n1,2\n\n3,4\n\n").unwrap();
        let rows = read_csv(&path);
        assert_eq!(rows.len(), 2, "blank lines are not records");
        assert_eq!(rows[0]["a"], "1");
        assert_eq!(rows[1]["a"], "3");
    }
}
