//! Statistical core for the compare phase — the scipy replacement.
//!
//! The surface is deliberately small and closed: Mann-Whitney U with
//! scipy's `method="auto"` semantics (exact distribution for small
//! untied samples, tie-corrected continuity-corrected normal
//! approximation otherwise), Vargha-Delaney A12 with v1's effect
//! labels, numpy-style descriptives, the scipy-percentile bootstrap
//! CI for the independent-sample median delta, and v1's
//! Holm-Bonferroni. Every deterministic procedure is validated
//! against scipy/numpy golden fixtures
//! (tests/fixtures/stats_scipy.json, regenerable under the pinned
//! nixpkgs python) so `cargo test` re-checks parity on every run;
//! the seeded bootstrap is checked for method properties instead,
//! since RNG streams cannot match across implementations.

use std::collections::HashMap;
use std::fmt;

use statrs::distribution::{ContinuousCDF, Normal};

pub const ALPHA: f64 = 0.05;
pub const A12_SMALL: f64 = 0.56;
pub const A12_MEDIUM: f64 = 0.64;
pub const A12_LARGE: f64 = 0.71;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alternative {
    TwoSided,
    Greater,
    Less,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// scipy's rule: exact when min(n) <= 8 and there are no ties.
    Auto,
    Exact,
    Asymptotic,
}

#[derive(Debug, Clone)]
pub struct MannWhitney {
    /// U statistic of the first sample (scipy's convention).
    pub u1: f64,
    /// NaN when the variance degenerates (all observations tied) —
    /// scipy returns NaN there too; NaN never counts as significant.
    pub p: f64,
    pub method: &'static str,
}

/// scipy.stats.mannwhitneyu parity (validated by golden fixtures).
pub fn mann_whitney(
    x: &[f64],
    y: &[f64],
    alternative: Alternative,
    method: Method,
) -> Result<MannWhitney, Error> {
    if x.is_empty() || y.is_empty() {
        return Err(Error::EmptySample);
    }
    let n1 = x.len() as f64;
    let n2 = y.len() as f64;

    // Midranks over the pooled sample + the tie correction term.
    let mut pooled: Vec<(f64, bool)> = x
        .iter()
        .map(|&value| (value, true))
        .chain(y.iter().map(|&value| (value, false)))
        .collect();
    pooled.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut rank_sum_x = 0.0;
    let mut tie_term = 0.0;
    let mut ties = false;
    let mut index = 0;
    while index < pooled.len() {
        let mut end = index;
        while end + 1 < pooled.len() && pooled[end + 1].0 == pooled[index].0 {
            end += 1;
        }
        let count = (end - index + 1) as f64;
        if end > index {
            ties = true;
            tie_term += count * count * count - count;
        }
        let rank = ((index + 1) + (end + 1)) as f64 / 2.0;
        for &(_, from_x) in &pooled[index..=end] {
            if from_x {
                rank_sum_x += rank;
            }
        }
        index = end + 1;
    }
    let u1 = rank_sum_x - n1 * (n1 + 1.0) / 2.0;

    // scipy's exact method runs even with ties (no correction: the
    // midrank U is evaluated against the untied distribution); auto
    // simply avoids that regime.
    let resolved = match method {
        Method::Exact => Method::Exact,
        Method::Asymptotic => Method::Asymptotic,
        Method::Auto => {
            if !ties && n1.min(n2) <= 8.0 {
                Method::Exact
            } else {
                Method::Asymptotic
            }
        }
    };

    let p = match resolved {
        Method::Exact => exact_p(u1, x.len(), y.len(), alternative),
        _ => asymptotic_p(u1, n1, n2, tie_term, alternative)?,
    };
    Ok(MannWhitney {
        u1,
        p,
        method: match resolved {
            Method::Exact => "exact",
            _ => "asymptotic",
        },
    })
}

/// Tie-corrected variance, 0.5 continuity correction toward each
/// tail. All-tied input leaves zero variance: scipy 1.18's signed
/// correction makes the two-sided z 0/0 (NaN) while the one-sided
/// tails evaluate the SF at an infinity (1.0).
fn asymptotic_p(
    u1: f64,
    n1: f64,
    n2: f64,
    tie_term: f64,
    alternative: Alternative,
) -> Result<f64, Error> {
    let total = n1 + n2;
    let mean = n1 * n2 / 2.0;
    let variance = (n1 * n2 / 12.0) * ((total + 1.0) - tie_term / (total * (total - 1.0)));
    if variance <= 0.0 {
        return Ok(match alternative {
            Alternative::TwoSided => f64::NAN,
            _ => 1.0,
        });
    }
    let sigma = variance.sqrt();
    let normal = Normal::new(0.0, 1.0).expect("standard normal");
    Ok(match alternative {
        Alternative::Greater => 1.0 - normal.cdf((u1 - mean - 0.5) / sigma),
        Alternative::Less => normal.cdf((u1 - mean + 0.5) / sigma),
        Alternative::TwoSided => {
            (2.0 * (1.0 - normal.cdf(((u1 - mean).abs() - 0.5) / sigma))).min(1.0)
        }
    })
}

/// Exact U distribution via the Gaussian-binomial recurrence
/// N(u; m, n) = N(u-n; m-1, n) + N(u; m, n-1).
fn exact_counts(m: usize, n: usize, memo: &mut HashMap<(usize, usize), Vec<f64>>) -> Vec<f64> {
    if m == 0 || n == 0 {
        return vec![1.0];
    }
    if let Some(counts) = memo.get(&(m, n)) {
        return counts.clone();
    }
    let left = exact_counts(m - 1, n, memo);
    let right = exact_counts(m, n - 1, memo);
    let mut counts = vec![0.0; m * n + 1];
    for (u, count) in left.iter().enumerate() {
        counts[u + n] += count;
    }
    for (u, count) in right.iter().enumerate() {
        counts[u] += count;
    }
    memo.insert((m, n), counts.clone());
    counts
}

fn exact_p(u1: f64, m: usize, n: usize, alternative: Alternative) -> f64 {
    let mut memo = HashMap::new();
    let counts = exact_counts(m, n, &mut memo);
    let total: f64 = counts.iter().sum();
    let cdf = |k: f64| -> f64 {
        if k < 0.0 {
            return 0.0;
        }
        let k = (k as usize).min(counts.len() - 1); // floor
        counts[..=k].iter().sum::<f64>() / total
    };
    // P(U >= k); ceil handles the half-integer U midranks produce.
    let sf_inclusive = |k: f64| 1.0 - cdf(k.ceil() - 1.0);
    match alternative {
        Alternative::Greater => sf_inclusive(u1),
        Alternative::Less => cdf(u1),
        Alternative::TwoSided => {
            let bigger = u1.max(m as f64 * n as f64 - u1);
            (2.0 * sf_inclusive(bigger)).min(1.0)
        }
    }
}

/// Vargha-Delaney A12: P(X > Y) + 0.5 P(X = Y) by direct counting
/// (v1 stats_common; 0.5 on an empty side).
pub fn vargha_delaney_a12(x: &[f64], y: &[f64]) -> f64 {
    if x.is_empty() || y.is_empty() {
        return 0.5;
    }
    let mut more = 0.0;
    let mut equal = 0.0;
    for &xi in x {
        for &yj in y {
            if xi > yj {
                more += 1.0;
            } else if xi == yj {
                equal += 1.0;
            }
        }
    }
    (more + 0.5 * equal) / (x.len() as f64 * y.len() as f64)
}

/// v1's effect-size buckets, folded around 0.5.
pub fn a12_label(a12: f64) -> &'static str {
    let folded = (a12 - 0.5).abs() + 0.5;
    if folded < A12_SMALL {
        "negligible"
    } else if folded < A12_MEDIUM {
        "small"
    } else if folded < A12_LARGE {
        "medium"
    } else {
        "large"
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Descriptive {
    pub median: f64,
    pub mean: f64,
    /// Sample standard deviation (ddof=1); 0 for fewer than 2 values.
    pub std: f64,
    pub p25: f64,
    pub p75: f64,
}

/// numpy-parity descriptives (median/percentiles use numpy's default
/// linear interpolation).
pub fn descriptive(values: &[f64]) -> Result<Descriptive, Error> {
    if values.is_empty() {
        return Err(Error::EmptySample);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let std = if values.len() > 1 {
        (values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / (values.len() as f64 - 1.0))
            .sqrt()
    } else {
        0.0
    };
    Ok(Descriptive {
        median: percentile(&sorted, 50.0),
        mean,
        std,
        p25: percentile(&sorted, 25.0),
        p75: percentile(&sorted, 75.0),
    })
}

/// numpy 'linear' percentile over a pre-sorted slice.
fn percentile(sorted: &[f64], q: f64) -> f64 {
    let position = (sorted.len() - 1) as f64 * q / 100.0;
    let low = position.floor() as usize;
    let high = position.ceil() as usize;
    sorted[low] + (sorted[high] - sorted[low]) * (position - low as f64)
}

/// v1 perf_compare's Holm-Bonferroni, ported verbatim: step-down
/// adjusted p-values with a running max, and the significance chain
/// that stops at the first failure. NaN p-values sort last and are
/// never significant.
pub fn holm_bonferroni(p_values: &[f64], alpha: f64) -> (Vec<f64>, Vec<bool>) {
    let m = p_values.len();
    let mut order: Vec<usize> = (0..m).collect();
    order.sort_by(|&a, &b| p_values[a].total_cmp(&p_values[b]));

    let mut adjusted = vec![1.0; m];
    let mut significant = vec![false; m];
    let mut running_max = 0.0f64;
    for (rank, &index) in order.iter().enumerate() {
        let candidate = (m - rank) as f64 * p_values[index];
        running_max = running_max.max(candidate);
        adjusted[index] = running_max.min(1.0);
    }
    let mut keep = true;
    for (rank, &index) in order.iter().enumerate() {
        let threshold = alpha / (m - rank) as f64;
        if keep && p_values[index] <= threshold {
            significant[index] = true;
        } else {
            keep = false;
        }
    }
    (adjusted, significant)
}

/// Percentile bootstrap 95% CI for the independent-sample median
/// delta percentage: (median(rs) - median(c)) / median(c) × 100 (v1
/// bootstrap_delta_ci via scipy.stats.bootstrap, method
/// "percentile"). Deterministic under `seed` (splitmix64
/// resampling); the method matches scipy, the stream cannot, so
/// tests assert properties rather than fixture values.
pub fn bootstrap_median_delta_ci(
    c: &[f64],
    rs: &[f64],
    resamples: u64,
    seed: u64,
) -> Result<(f64, f64), Error> {
    if c.is_empty() || rs.is_empty() {
        return Err(Error::EmptySample);
    }
    let mut state = seed;
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };

    let mut c_sample = vec![0.0; c.len()];
    let mut rs_sample = vec![0.0; rs.len()];
    let mut replicates = Vec::with_capacity(resamples as usize);
    for _ in 0..resamples {
        for slot in c_sample.iter_mut() {
            *slot = c[(next() % c.len() as u64) as usize];
        }
        for slot in rs_sample.iter_mut() {
            *slot = rs[(next() % rs.len() as u64) as usize];
        }
        c_sample.sort_by(|a, b| a.total_cmp(b));
        rs_sample.sort_by(|a, b| a.total_cmp(b));
        let c_median = percentile(&c_sample, 50.0);
        let rs_median = percentile(&rs_sample, 50.0);
        replicates.push((rs_median - c_median) / c_median * 100.0);
    }
    replicates.sort_by(|a, b| a.total_cmp(b));
    Ok((percentile(&replicates, 2.5), percentile(&replicates, 97.5)))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    EmptySample,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EmptySample => write!(f, "statistics need non-empty samples"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/stats_scipy.json"))
            .expect("fixture parses")
    }

    fn floats(value: &serde_json::Value) -> Vec<f64> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect()
    }

    fn assert_close(actual: f64, expected: f64, context: &str) {
        let tolerance = 1e-9 * expected.abs().max(1.0);
        assert!(
            (actual - expected).abs() <= tolerance,
            "{context}: got {actual}, scipy says {expected}"
        );
    }

    #[test]
    fn mann_whitney_matches_scipy_fixtures() {
        let fixture = fixture();
        for case in fixture["mwu"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let x = floats(&case["x"]);
            let y = floats(&case["y"]);
            for (alt_name, alternative) in [
                ("two-sided", Alternative::TwoSided),
                ("greater", Alternative::Greater),
                ("less", Alternative::Less),
            ] {
                for (method_name, method) in [
                    ("auto", Method::Auto),
                    ("exact", Method::Exact),
                    ("asymptotic", Method::Asymptotic),
                ] {
                    let expected = &case["alternatives"][alt_name][method_name];
                    let context = format!("{name} / {alt_name} / {method_name}");
                    let result = mann_whitney(&x, &y, alternative, method);
                    if expected.get("error").is_some() {
                        assert!(result.is_err(), "{context}: scipy errored, we did not");
                        continue;
                    }
                    let result = result.unwrap_or_else(|err| panic!("{context}: {err}"));
                    assert_close(result.u1, expected["u1"].as_f64().unwrap(), &context);
                    assert_close(result.p, expected["p"].as_f64().unwrap(), &context);
                }
            }
        }
    }

    #[test]
    fn all_tied_input_matches_scipy_per_alternative() {
        let fixture = fixture();
        let case = &fixture["mwu_all_tied"];
        let x = floats(&case["x"]);
        let y = floats(&case["y"]);
        for (alt_name, alternative) in [
            ("two-sided", Alternative::TwoSided),
            ("greater", Alternative::Greater),
            ("less", Alternative::Less),
        ] {
            let expected = &case["asymptotic"][alt_name];
            let result = mann_whitney(&x, &y, alternative, Method::Asymptotic).unwrap();
            assert_eq!(result.u1, expected["u1"].as_f64().unwrap());
            match expected["p"].as_f64() {
                // scipy's signed continuity correction: two-sided is
                // 0/0 (fixture null = NaN), one-sided tails hit an
                // infinity and give 1.0.
                None => {
                    assert!(result.p.is_nan(), "{alt_name}: scipy returns NaN");
                    assert_eq!(result.p.partial_cmp(&ALPHA), None);
                }
                Some(expected) => assert_close(result.p, expected, alt_name),
            }
        }
    }

    #[test]
    fn a12_matches_fixtures_and_labels_fold() {
        let fixture = fixture();
        for case in fixture["a12"].as_array().unwrap() {
            let context = case["name"].as_str().unwrap();
            let a12 = vargha_delaney_a12(&floats(&case["x"]), &floats(&case["y"]));
            assert_close(a12, case["a12"].as_f64().unwrap(), context);
        }
        assert_eq!(a12_label(0.5), "negligible");
        assert_eq!(a12_label(0.45), "negligible");
        assert_eq!(a12_label(0.6), "small");
        assert_eq!(a12_label(0.36), "medium");
        assert_eq!(a12_label(0.29), "large");
        assert_eq!(a12_label(0.71), "large");
        assert_eq!(vargha_delaney_a12(&[], &[1.0]), 0.5);
    }

    #[test]
    fn descriptives_match_numpy_fixtures() {
        let fixture = fixture();
        for case in fixture["descriptive"].as_array().unwrap() {
            let context = case["name"].as_str().unwrap();
            let desc = descriptive(&floats(&case["values"])).unwrap();
            assert_close(desc.median, case["median"].as_f64().unwrap(), context);
            assert_close(desc.mean, case["mean"].as_f64().unwrap(), context);
            assert_close(desc.std, case["std_ddof1"].as_f64().unwrap(), context);
            assert_close(desc.p25, case["p25"].as_f64().unwrap(), context);
            assert_close(desc.p75, case["p75"].as_f64().unwrap(), context);
        }
        assert!(descriptive(&[]).is_err());
    }

    #[test]
    fn holm_matches_the_v1_port_fixtures() {
        let fixture = fixture();
        for case in fixture["holm"].as_array().unwrap() {
            let context = case["name"].as_str().unwrap();
            let p_values = floats(&case["p_values"]);
            let alpha = case["alpha"].as_f64().unwrap();
            let (adjusted, significant) = holm_bonferroni(&p_values, alpha);
            let expected_adjusted = floats(&case["adjusted"]);
            for (index, expected) in expected_adjusted.iter().enumerate() {
                assert_close(adjusted[index], *expected, context);
            }
            let expected_significant: Vec<bool> = case["significant"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_bool().unwrap())
                .collect();
            assert_eq!(significant, expected_significant, "{context}");
        }
    }

    #[test]
    fn bootstrap_is_deterministic_and_sane() {
        let c = [100.0, 102.0, 98.0, 101.0, 99.0, 100.5, 97.5, 103.0];
        let rs = [85.0, 88.0, 84.0, 86.0, 87.0, 85.5, 83.5, 88.5];
        let first = bootstrap_median_delta_ci(&c, &rs, 2000, 42).unwrap();
        let second = bootstrap_median_delta_ci(&c, &rs, 2000, 42).unwrap();
        assert_eq!(first, second, "same seed, same interval");
        let other = bootstrap_median_delta_ci(&c, &rs, 2000, 43).unwrap();
        assert_ne!(first, other, "different seed resamples differently");

        let (lo, hi) = first;
        assert!(lo <= hi);
        // Point estimate ~ -14.6%; the interval must bracket a clear
        // regression and stay well away from zero.
        assert!(lo < -10.0 && hi < -10.0, "interval {lo}..{hi}");

        // Degenerate: constant samples pin the interval to the point.
        let (lo, hi) = bootstrap_median_delta_ci(&[100.0; 5], &[90.0; 5], 100, 7).unwrap();
        assert_eq!((lo, hi), (-10.0, -10.0));
        assert!(bootstrap_median_delta_ci(&[], &rs, 10, 1).is_err());
    }
}
