//! Commit mining and classification (v1 `static/commits` +
//! `commit_analysis`). v1 paged the GitHub API against a moving
//! HEAD with a floating "4 years ago" window; here history comes
//! from the locked linux-meta mirror at its pinned rev with an
//! absolute `[block.static].since` bound — offline and reproducible.
//! Classification rules live in the `static/classify.toml` asset
//! (sha-recorded in the result identity), and the audited
//! `--validated-cwe` overrides keep the paper's manual-review trail.

use std::fmt;
use std::path::Path;
use std::process::Command;

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
        let file: RulesFile = toml::from_str(contents).map_err(Error::Toml)?;
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
                row.manual_cwe = cwe.to_owned();
                row.validator = validator.to_owned();
                row.validation_date = date.to_owned();
                if !row.manual_cwe.is_empty() {
                    row.safety_related = true;
                }
            }
        }
    }
}

/// commits.csv (v1 field order; manual_cwe stays the human's column).
pub fn commits_csv(rows: &[CommitRow]) -> String {
    let mut out = String::from(
        "hash,date,author,subject,driver,safety_related,auto_cwe,manual_cwe,validator,validation_date\n",
    );
    for row in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            row.hash,
            csv_field(&row.date),
            csv_field(&row.author),
            csv_field(&row.subject),
            csv_field(&row.driver),
            row.safety_related,
            row.auto_cwe,
            row.manual_cwe,
            csv_field(&row.validator),
            csv_field(&row.validation_date),
        ));
    }
    out
}

/// commits_summary.csv (v1 shape: totals then per-CWE counts, with
/// manual classifications taking precedence).
pub fn summary_csv(rows: &[CommitRow]) -> String {
    let total = rows.len();
    let safety = rows.iter().filter(|row| row.safety_related).count();
    let mut out = String::from("metric,value\n");
    out.push_str(&format!("total_commits,{total}\n"));
    out.push_str(&format!("safety_related,{safety}\n"));
    if total > 0 {
        out.push_str(&format!(
            "safety_pct,{:.1}\n",
            safety as f64 * 100.0 / total as f64
        ));
    } else {
        out.push_str("safety_pct,N/A\n");
    }
    let mut counts = std::collections::BTreeMap::new();
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
    for (cwe, count) in counts {
        out.push_str(&format!("{cwe}_count,{count}\n"));
    }
    out
}

fn csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_owned()
    }
}

#[derive(Debug)]
pub enum Error {
    Toml(toml::de::Error),
    Regex(String, regex::Error),
    Git(std::io::Error),
    GitFailed(std::process::ExitStatus, String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Toml(err) => write!(f, "parsing classify rules: {err}"),
            Error::Regex(pattern, err) => write!(f, "classify rule /{pattern}/: {err}"),
            Error::Git(err) => write!(f, "running git log: {err}"),
            Error::GitFailed(status, stderr) => {
                write!(f, "git log failed ({status}): {stderr}")
            }
        }
    }
}

impl std::error::Error for Error {}

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
}
