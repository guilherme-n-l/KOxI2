//! Commit mining and classification (v1 `static/commits` +
//! `commit_analysis`). v1 paged the GitHub API against a moving
//! HEAD with a floating "4 years ago" window; here history comes
//! from the locked linux-meta mirror at its pinned rev with an
//! absolute `[block.static].since` bound — offline and reproducible.
//! Classification rules live in the `static/classify.toml` asset
//! (sha-recorded in the result identity), and the audited
//! `--validated-cwe` overrides keep the paper's manual-review trail.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use crate::util;
use regex::RegexBuilder;
use serde::Deserialize;

/// Parsed `static/classify.toml`.
pub struct Rules {
    safety: regex::Regex,
    cwe: Vec<(regex::Regex, String)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RulesFile {
    safety_signal: String,
    #[serde(default)]
    cwe: Vec<CweRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CweRule {
    pattern: String,
    cwe: String,
}

impl Rules {
    pub fn parse(contents: &str) -> Result<Self, Error> {
        let file: RulesFile = toml::from_str(contents)?;
        let build = |pattern: &str| {
            RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|err| Error::Regex(pattern.to_owned(), err))
        };
        Ok(Self {
            safety: build(&file.safety_signal)?,
            cwe: file
                .cwe
                .iter()
                .map(|rule| Ok((build(&rule.pattern)?, rule.cwe.clone())))
                .collect::<Result<_, Error>>()?,
        })
    }

    /// First matching CWE rule for a safety-related subject.
    fn classify(&self, subject: &str) -> String {
        for (pattern, cwe) in &self.cwe {
            if pattern.is_match(subject) {
                return cwe.clone();
            }
        }
        String::new()
    }
}

/// One mined commit with its classification and audit fields
/// (v1 commits.csv row).
#[derive(Debug, Clone)]
pub struct CommitRow {
    pub hash: String,
    pub date: String,
    pub author: String,
    pub subject: String,
    pub driver: String,
    pub safety_related: bool,
    pub auto_cwe: String,
    pub manual_cwe: String,
    pub validator: String,
    pub validation_date: String,
}

/// commits.csv columns (v1 field order; manual_cwe stays the
/// human's column).
const COLUMNS: [&str; 10] = [
    "hash",
    "date",
    "author",
    "subject",
    "driver",
    "safety_related",
    "auto_cwe",
    "manual_cwe",
    "validator",
    "validation_date",
];

/// `git log` over the blobless linux-meta mirror at the pinned rev.
pub fn mine(
    mirror: &Path,
    rev: &str,
    since: Option<&str>,
    gitpath: &Path,
    driver: &str,
    rules: &Rules,
) -> Result<Vec<CommitRow>, Error> {
    let mut git = Command::new("git");
    git.arg("-C")
        .arg(mirror)
        .arg("log")
        .arg("--format=%H%x01%aI%x01%an%x01%s");
    if let Some(since) = since {
        git.arg(format!("--since={since}"));
    }
    git.arg(rev).arg("--").arg(gitpath);
    let output = git.output().map_err(Error::Git)?;
    if !output.status.success() {
        return Err(Error::GitFailed(
            output.status,
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }

    let mut rows = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.splitn(4, '\u{1}');
        let (Some(hash), Some(date), Some(author), Some(subject)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let safety_related = rules.safety.is_match(subject);
        rows.push(CommitRow {
            hash: hash.to_owned(),
            date: date.to_owned(),
            author: author.to_owned(),
            subject: subject.to_owned(),
            driver: driver.to_owned(),
            safety_related,
            auto_cwe: if safety_related {
                rules.classify(subject)
            } else {
                String::new()
            },
            manual_cwe: String::new(),
            validator: String::new(),
            validation_date: String::new(),
        });
    }
    Ok(rows)
}

/// Fold in the audited overrides (commit_sha,cwe,validator,date CSV;
/// v1 --validated-cwe). A validated CWE marks the commit
/// safety-related regardless of the regex.
pub fn apply_validated(rows: &mut [CommitRow], csv: &str) {
    for line in csv.lines().skip(1) {
        let mut fields = line.split(',');
        let (Some(sha), cwe, validator, date) = (
            fields.next().map(str::trim),
            fields.next().map(str::trim).unwrap_or_default(),
            fields.next().map(str::trim).unwrap_or_default(),
            fields.next().map(str::trim).unwrap_or_default(),
        ) else {
            continue;
        };
        if sha.is_empty() {
            continue;
        }
        for row in rows.iter_mut() {
            if row.hash.starts_with(sha) {
                cwe.clone_into(&mut row.manual_cwe);
                validator.clone_into(&mut row.validator);
                date.clone_into(&mut row.validation_date);
                if !row.manual_cwe.is_empty() {
                    row.safety_related = true;
                }
            }
        }
    }
}

/// commits.csv, one row per mined commit in [`COLUMNS`] order.
pub fn commits_csv(rows: &[CommitRow]) -> String {
    util::csv_text(|out| {
        out.write_record(COLUMNS)?;
        for row in rows {
            let fields: [&str; 10] = [
                &row.hash,
                &row.date,
                &row.author,
                &row.subject,
                &row.driver,
                if row.safety_related { "true" } else { "false" },
                &row.auto_cwe,
                &row.manual_cwe,
                &row.validator,
                &row.validation_date,
            ];
            out.write_record(fields)?;
        }
        Ok(())
    })
}

/// commits_summary.csv (v1 shape: totals then per-CWE counts, with
/// manual classifications taking precedence).
pub fn summary_csv(rows: &[CommitRow]) -> String {
    let total = rows.len();
    let safety = rows.iter().filter(|row| row.safety_related).count();
    let safety_pct = if total > 0 {
        format!("{:.1}", safety as f64 * 100.0 / total as f64)
    } else {
        "N/A".to_owned()
    };
    let mut counts = BTreeMap::new();
    for row in rows {
        let cwe = if row.manual_cwe.is_empty() {
            &row.auto_cwe
        } else {
            &row.manual_cwe
        };
        if !cwe.is_empty() {
            *counts.entry(cwe.clone()).or_insert(0u32) += 1;
        }
    }
    util::csv_text(|out| {
        out.write_record(["metric", "value"])?;
        out.write_record(["total_commits", &total.to_string()])?;
        out.write_record(["safety_related", &safety.to_string()])?;
        out.write_record(["safety_pct", &safety_pct])?;
        for (cwe, count) in &counts {
            out.write_record([format!("{cwe}_count"), count.to_string()])?;
        }
        Ok(())
    })
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("parsing classify rules: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("classify rule /{0}/: {1}")]
    Regex(String, #[source] regex::Error),
    #[error("running git log: {0}")]
    Git(#[source] std::io::Error),
    #[error("git log failed ({0}): {1}")]
    GitFailed(std::process::ExitStatus, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        let embedded = crate::assets::ASSETS
            .iter()
            .find(|asset| asset.name == "static/classify.toml")
            .expect("classify rules are embedded");
        Rules::parse(embedded.contents).unwrap()
    }

    fn row(hash: &str, subject: &str, rules: &Rules) -> CommitRow {
        let safety_related = rules.safety.is_match(subject);
        CommitRow {
            hash: hash.to_owned(),
            date: "2024-01-01T00:00:00+00:00".to_owned(),
            author: "Dev, Some".to_owned(),
            subject: subject.to_owned(),
            driver: "null_blk".to_owned(),
            safety_related,
            auto_cwe: if safety_related {
                rules.classify(subject)
            } else {
                String::new()
            },
            manual_cwe: String::new(),
            validator: String::new(),
            validation_date: String::new(),
        }
    }

    #[test]
    fn classification_matches_v1_rules() {
        let rules = rules();
        let uaf = row("a1", "null_blk: fix use-after-free in timer path", &rules);
        assert!(uaf.safety_related);
        assert_eq!(uaf.auto_cwe, "CWE-416");

        let leak = row("a2", "null_blk: plug memory leak on configfs error", &rules);
        assert_eq!(leak.auto_cwe, "CWE-401");

        // The driver's own name must not read as a safety signal
        // (v1's bare "null" token counted every null_blk: subject).
        let feature = row("a3", "null_blk: add poll queue support", &rules);
        assert!(!feature.safety_related);
        assert_eq!(feature.auto_cwe, "");
        let debugfs = row("a5", "null_blk: expose debugfs knobs", &rules);
        assert!(!debugfs.safety_related, "debug is not bug");
        let tracing = row("a6", "null_blk: add tracepoints", &rules);
        assert!(!tracing.safety_related, "tracepoints are not races");
        let nullderef = row("a7", "null_blk: avoid null deref on setup", &rules);
        assert!(nullderef.safety_related);
        assert_eq!(nullderef.auto_cwe, "CWE-476");

        // First match wins: "leak" also matches the CWE-401 rule but
        // use-after-free is tested first.
        let both = row("a4", "fix leak and use-after-free", &rules);
        assert_eq!(both.auto_cwe, "CWE-416");
    }

    #[test]
    fn validated_overrides_take_precedence() {
        let rules = rules();
        let mut rows = vec![
            row("d301f16aaaaa", "null_blk: fix sector_t truncation", &rules),
            row("aaaa11112222", "null_blk: refactor helpers", &rules),
        ];
        apply_validated(
            &mut rows,
            "commit_sha,cwe,validator,date\naaaa1111,CWE-843,reviewer,2026-01-01\n",
        );
        assert_eq!(rows[1].manual_cwe, "CWE-843");
        assert!(rows[1].safety_related, "manual CWE marks safety-related");
        assert_eq!(rows[1].validator, "reviewer");
        assert_eq!(rows[0].manual_cwe, "");

        let csv = commits_csv(&rows);
        assert!(
            csv.contains("\"Dev, Some\""),
            "authors with commas are quoted"
        );
        let summary = summary_csv(&rows);
        assert!(summary.contains("total_commits,2"));
        assert!(summary.contains("safety_related,2"));
        assert!(
            summary.contains("CWE-190_count,1"),
            "truncation -> CWE-190: {summary}"
        );
        assert!(summary.contains("CWE-843_count,1"));
    }

    #[test]
    fn csv_output_keeps_the_v1_shape_and_quotes_only_when_needed() {
        let rules = rules();
        let header = COLUMNS.join(",");
        assert_eq!(commits_csv(&[]), format!("{header}\n"));

        let mut awkward = row("b1", "null_blk: fix \"double\" free, again", &rules);
        awkward.auto_cwe = "CWE-415".to_owned();
        awkward.validator = "line\nbreak".to_owned();
        let csv = commits_csv(&[awkward]);
        let mut lines = csv.lines();
        assert_eq!(lines.next(), Some(header.as_str()));
        assert_eq!(
            lines.next(),
            Some(
                "b1,2024-01-01T00:00:00+00:00,\"Dev, Some\",\"null_blk: fix \"\"double\"\" free, \
                 again\",null_blk,true,CWE-415,,\"line"
            ),
            "quotes double, commas quote, newlines quote: {csv}"
        );
        assert_eq!(lines.next(), Some("break\","));

        assert_eq!(
            summary_csv(&[]),
            "metric,value\ntotal_commits,0\nsafety_related,0\nsafety_pct,N/A\n"
        );
    }
}
