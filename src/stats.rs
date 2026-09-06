//! Statistical core for the compare phase — the scipy replacement.
//!
//! The surface is deliberately small and closed: Mann-Whitney U with
//! scipy's `method="auto"` semantics (exact distribution for small
//! untied samples, tie-corrected continuity-corrected normal
//! approximation otherwise), the Hodges-Lehmann shift estimate with
//! the Moses order-statistic CI (R `wilcox.test conf.int` exact
//! branch), Wilcoxon signed-rank with scipy's auto semantics,
//! Vargha-Delaney A12 with v1's effect labels and the DeLong CI
//! (pROC `ci.auc` parity), numpy-style descriptives, the
//! scipy-percentile bootstrap CI for the independent-sample median
//! delta, and v1's Holm-Bonferroni. Every deterministic procedure is
//! validated against golden fixtures (tests/fixtures/stats_scipy.json
//! from scipy/numpy, tests/fixtures/stats_r.json from R wilcox.test +
//! pROC, both regenerable under the pinned nixpkgs interpreters) so
//! `cargo test` re-checks parity on every run; the seeded bootstrap
//! is checked for method properties instead, since RNG streams cannot
//! match across implementations.

use std::collections::HashMap;
use std::fmt;

use statrs::distribution::{Beta, ContinuousCDF, Gamma, Normal};

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

#[derive(Debug, Clone)]
pub struct HodgesLehmann {
    /// Median of the m*n pairwise differences x_i - y_j.
    pub estimate: f64,
    pub lo: f64,
    pub hi: f64,
}

/// Hodges-Lehmann shift estimate for x - y with the Moses
/// order-statistic confidence interval, matching R
/// `wilcox.test(x, y, conf.int=TRUE, exact=TRUE)`
/// (.wilcox_test_two_cint_exact, two-sided): both CI endpoints are
/// order statistics of the pairwise differences, picked by the
/// qwilcox(alpha/2) critical rank with R's boundary bump; when even
/// the widest interval cannot reach the requested level the bounds
/// are infinite, exactly as R reports. The critical rank comes from
/// the untied null U distribution (R refuses exact CIs on tied data
/// and inverts a normal approximation instead; the order-statistic
/// construction is kept here — ties are measure-zero on continuous
/// metrics). Past 5000 pairwise products the rank falls back to the
/// normal approximation of U.
pub fn hodges_lehmann_ci(x: &[f64], y: &[f64], conf_level: f64) -> Result<HodgesLehmann, Error> {
    if x.is_empty() || y.is_empty() {
        return Err(Error::EmptySample);
    }
    let mut diffs: Vec<f64> = x
        .iter()
        .flat_map(|&xi| y.iter().map(move |&yj| xi - yj))
        .collect();
    diffs.sort_by(|a, b| a.total_cmp(b));
    let estimate = percentile(&diffs, 50.0);

    let target = (1.0 - conf_level) / 2.0;
    let (mut qu, cdf_at_qu) = qwilcox(target, x.len(), y.len());
    if cdf_at_qu <= target + 10.0 * f64::EPSILON {
        qu += 1;
    }
    if qu == 0 {
        return Ok(HodgesLehmann {
            estimate,
            lo: f64::NEG_INFINITY,
            hi: f64::INFINITY,
        });
    }
    let ql = x.len() * y.len() - qu;
    Ok(HodgesLehmann {
        estimate,
        lo: diffs[qu - 1],
        hi: diffs[ql],
    })
}

/// R qwilcox: smallest k with P(U <= k) >= p under the exact null,
/// returned with the cdf at that k (for the boundary bump above).
fn qwilcox(p: f64, m: usize, n: usize) -> (usize, f64) {
    let products = m * n;
    if products <= 5000 {
        let mut memo = HashMap::new();
        let counts = exact_counts(m, n, &mut memo);
        let total: f64 = counts.iter().sum();
        let mut acc = 0.0;
        for (k, count) in counts.iter().enumerate() {
            acc += count;
            if acc / total >= p {
                return (k, acc / total);
            }
        }
        (products, 1.0)
    } else {
        let normal = Normal::new(0.0, 1.0).expect("standard normal");
        let mu = products as f64 / 2.0;
        let sigma = (products as f64 * (m + n + 1) as f64 / 12.0).sqrt();
        let k = (mu - 0.5 + sigma * normal.inverse_cdf(p)).ceil().max(0.0) as usize;
        (k, normal.cdf((k as f64 + 0.5 - mu) / sigma))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedRank {
    /// scipy's convention: min(T+, T-) two-sided, T+ one-sided.
    pub statistic: f64,
    pub p: f64,
    pub method: &'static str,
}

/// scipy.stats.wilcoxon parity under scipy's defaults
/// (zero_method="wilcox": zero differences dropped;
/// correction=False), validated by golden fixtures. `Method::Auto`
/// follows scipy 1.18's resolution over the pre-drop length: above
/// 50 pairs the normal approximation; untied zero-free samples the
/// exact null; otherwise the sign-flip permutation, deterministic
/// while 2^n fits scipy's 9999-resample budget (n <= 13). Beyond
/// that scipy draws random permutations — we use the normal
/// approximation there, the one branch where auto parity is
/// statistical rather than exact.
pub fn wilcoxon_signed_rank(
    x: &[f64],
    y: &[f64],
    alternative: Alternative,
    method: Method,
) -> Result<SignedRank, Error> {
    if x.len() != y.len() {
        return Err(Error::UnpairedSamples);
    }
    if x.is_empty() {
        return Err(Error::EmptySample);
    }
    let full_len = x.len();
    let diffs: Vec<f64> = x
        .iter()
        .zip(y)
        .map(|(a, b)| a - b)
        .filter(|d| *d != 0.0)
        .collect();
    if diffs.is_empty() {
        return Err(Error::AllZeroDifferences);
    }
    let zeros = full_len - diffs.len();
    let n = diffs.len();

    // Midranks of |d| and the tie term sum(t^3 - t).
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| diffs[a].abs().total_cmp(&diffs[b].abs()));
    let mut ranks = vec![0.0; n];
    let mut tie_term = 0.0;
    let mut ties = false;
    let mut index = 0;
    while index < n {
        let mut end = index;
        while end + 1 < n && diffs[order[end + 1]].abs() == diffs[order[index]].abs() {
            end += 1;
        }
        let count = (end - index + 1) as f64;
        if end > index {
            ties = true;
            tie_term += count * count * count - count;
        }
        let rank = ((index + 1) + (end + 1)) as f64 / 2.0;
        for &original in &order[index..=end] {
            ranks[original] = rank;
        }
        index = end + 1;
    }
    let r_plus: f64 = diffs
        .iter()
        .zip(&ranks)
        .filter(|(d, _)| **d > 0.0)
        .map(|(_, rank)| rank)
        .sum();
    let r_minus = n as f64 * (n as f64 + 1.0) / 2.0 - r_plus;

    enum Resolved {
        Exact,
        Approx,
        Permutation,
    }
    let resolved = match method {
        Method::Exact => Resolved::Exact,
        Method::Asymptotic => Resolved::Approx,
        Method::Auto => {
            if full_len > 50 {
                Resolved::Approx
            } else if !ties && zeros == 0 {
                Resolved::Exact
            } else if full_len <= 13 {
                Resolved::Permutation
            } else {
                Resolved::Approx
            }
        }
    };

    let (p, method_name) = match resolved {
        Resolved::Exact => {
            // Midranks can make T+ non-integral against the untied
            // null; scipy rounds conservatively (gh-19872): less
            // takes cdf(ceil), greater the inclusive sf(floor).
            let counts = signed_rank_counts(n);
            let total = counts.iter().sum::<f64>();
            let cdf = |k: f64| -> f64 {
                if k < 0.0 {
                    return 0.0;
                }
                let k = (k as usize).min(counts.len() - 1);
                counts[..=k].iter().sum::<f64>() / total
            };
            let p_less = cdf(r_plus.ceil());
            let p_greater = 1.0 - cdf(r_plus.floor() - 1.0);
            let p = match alternative {
                Alternative::Less => p_less,
                Alternative::Greater => p_greater,
                Alternative::TwoSided => (2.0 * p_less.min(p_greater)).min(1.0),
            };
            (p, "exact")
        }
        Resolved::Approx => {
            let count = n as f64;
            let mean = count * (count + 1.0) / 4.0;
            let sigma =
                ((count * (count + 1.0) * (2.0 * count + 1.0) - tie_term / 2.0) / 24.0).sqrt();
            let z = (r_plus - mean) / sigma;
            let normal = Normal::new(0.0, 1.0).expect("standard normal");
            let p = match alternative {
                Alternative::Greater => 1.0 - normal.cdf(z),
                Alternative::Less => normal.cdf(z),
                Alternative::TwoSided => 2.0 * (1.0 - normal.cdf(z.abs())),
            };
            (p, "approx")
        }
        Resolved::Permutation => {
            // Doubled ranks are exact integers, so the enumeration
            // over the 2^n sign assignments needs no tolerance.
            // Flipping a dropped zero never changes the statistic,
            // so enumerating the non-zero part matches scipy's
            // enumeration over the full vector.
            let ranks2: Vec<u64> = ranks
                .iter()
                .map(|rank| (rank * 2.0).round() as u64)
                .collect();
            let observed2 = (r_plus * 2.0).round() as u64;
            let total = 1u64 << n;
            let mut greater_eq = 0u64;
            let mut less_eq = 0u64;
            for mask in 0..total {
                let mut t2 = 0u64;
                for (bit, rank2) in ranks2.iter().enumerate() {
                    if mask >> bit & 1 == 1 {
                        t2 += rank2;
                    }
                }
                if t2 >= observed2 {
                    greater_eq += 1;
                }
                if t2 <= observed2 {
                    less_eq += 1;
                }
            }
            let p_greater = greater_eq as f64 / total as f64;
            let p_less = less_eq as f64 / total as f64;
            let p = match alternative {
                Alternative::Greater => p_greater,
                Alternative::Less => p_less,
                Alternative::TwoSided => (2.0 * p_less.min(p_greater)).min(1.0),
            };
            (p, "permutation")
        }
    };

    Ok(SignedRank {
        statistic: match alternative {
            Alternative::TwoSided => r_plus.min(r_minus),
            _ => r_plus,
        },
        p,
        method: method_name,
    })
}

/// Counts of subsets of {1..n} by rank sum (the exact null of T+).
fn signed_rank_counts(n: usize) -> Vec<f64> {
    let max = n * (n + 1) / 2;
    let mut counts = vec![0.0; max + 1];
    counts[0] = 1.0;
    for rank in 1..=n {
        for sum in (rank..=max).rev() {
            counts[sum] += counts[sum - rank];
        }
    }
    counts
}

#[derive(Debug, Clone)]
pub struct A12Interval {
    pub a12: f64,
    pub lo: f64,
    pub hi: f64,
}

/// DeLong CI for A12 (the AUC of x against y), matching pROC
/// `ci.auc(..., method="delong")`: Wald interval on the placement
/// variance, clipped to [0, 1]. Degenerate data (perfect separation,
/// all tied) collapses the interval to the point. A singleton side
/// contributes zero placement variance (pROC propagates NA there;
/// callers with real samples never hit it).
pub fn a12_delong_ci(x: &[f64], y: &[f64], conf_level: f64) -> Result<A12Interval, Error> {
    if x.is_empty() || y.is_empty() {
        return Err(Error::EmptySample);
    }
    let m = x.len() as f64;
    let n = y.len() as f64;
    let mut x_placements = vec![0.0; x.len()];
    let mut y_placements = vec![0.0; y.len()];
    for (i, &xi) in x.iter().enumerate() {
        for (j, &yj) in y.iter().enumerate() {
            let score = if xi > yj {
                1.0
            } else if xi == yj {
                0.5
            } else {
                0.0
            };
            x_placements[i] += score;
            y_placements[j] += score;
        }
    }
    for placement in x_placements.iter_mut() {
        *placement /= n;
    }
    for placement in y_placements.iter_mut() {
        *placement /= m;
    }
    let a12 = x_placements.iter().sum::<f64>() / m;
    let variance = sample_variance(&x_placements) / m + sample_variance(&y_placements) / n;
    let normal = Normal::new(0.0, 1.0).expect("standard normal");
    let half = normal.inverse_cdf(1.0 - (1.0 - conf_level) / 2.0) * variance.sqrt();
    Ok(A12Interval {
        a12,
        lo: (a12 - half).max(0.0),
        hi: (a12 + half).min(1.0),
    })
}

/// ddof=1 variance; 0 below two values.
fn sample_variance(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / (values.len() as f64 - 1.0)
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

/// Exact binomial upper tail P(X >= k) for X ~ Bin(n, p), matching
/// scipy binomtest(alternative="greater").
pub fn binomial_sf(k: u64, n: u64, p: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > n {
        return 0.0;
    }
    // P(X >= k) = I_p(k, n - k + 1), the regularized incomplete beta.
    Beta::new(k as f64, (n - k + 1) as f64)
        .expect("valid beta parameters")
        .cdf(p)
}

/// Clopper-Pearson (exact) two-sided binomial CI, matching scipy
/// binomtest().proportion_ci(method="exact"). The one-sided
/// 1 - alpha bound is the corresponding side of the 1 - 2*alpha
/// interval.
pub fn clopper_pearson(k: u64, n: u64, conf_level: f64) -> (f64, f64) {
    let tail = (1.0 - conf_level) / 2.0;
    let lo = if k == 0 {
        0.0
    } else {
        Beta::new(k as f64, (n - k + 1) as f64)
            .expect("valid beta parameters")
            .inverse_cdf(tail)
    };
    let hi = if k >= n {
        1.0
    } else {
        Beta::new((k + 1) as f64, (n - k) as f64)
            .expect("valid beta parameters")
            .inverse_cdf(1.0 - tail)
    };
    (lo, hi)
}

/// Exact Poisson upper confidence bound on the mean given an
/// observed count (gamma quantile; k = 0 at 95% is the rule of
/// three, 2.9957). Divide by the exposure for a rate bound.
pub fn poisson_upper(k: u64, level: f64) -> f64 {
    Gamma::new((k + 1) as f64, 1.0)
        .expect("valid gamma parameters")
        .inverse_cdf(level)
}

/// Analytic minimum detectable effect for the exact conditional
/// rate-ratio test. Conditional on `total` events split between the
/// rs side (exposure `t_rs`) and the c side (`t_c`), the rs count is
/// Bin(total, p(rho)) with p(rho) = rho*t_rs / (rho*t_rs + t_c).
/// Returns the smallest true ratio rho >= 1 the one-sided level-alpha
/// test rejects with probability >= `power` — None when the test can
/// never reject at this total (too few events).
pub fn binomial_mde_ratio(total: u64, t_c: f64, t_rs: f64, alpha: f64, power: f64) -> Option<f64> {
    if total == 0 || t_c <= 0.0 || t_rs <= 0.0 {
        return None;
    }
    let p_of = |rho: f64| rho * t_rs / (rho * t_rs + t_c);
    let p0 = p_of(1.0);
    let critical = (0..=total).find(|&k| binomial_sf(k, total, p0) <= alpha)?;
    let achieves = |rho: f64| binomial_sf(critical, total, p_of(rho)) >= power;
    let mut hi = 1.0f64;
    loop {
        if achieves(hi) {
            break;
        }
        hi *= 2.0;
        if hi > 1e9 {
            return None;
        }
    }
    let mut lo = 1.0f64;
    for _ in 0..200 {
        let mid = (lo + hi) / 2.0;
        if achieves(mid) {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    Some(hi)
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
    UnpairedSamples,
    AllZeroDifferences,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EmptySample => write!(f, "statistics need non-empty samples"),
            Error::UnpairedSamples => write!(f, "paired statistics need equal-length samples"),
            Error::AllZeroDifferences => {
                write!(f, "signed-rank is undefined when every difference is zero")
            }
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

    fn r_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/fixtures/stats_r.json"))
            .expect("R fixture parses")
    }

    /// jsonlite writes R's infinities as strings.
    fn r_f64(value: &serde_json::Value) -> f64 {
        match value.as_str() {
            Some("Inf") => f64::INFINITY,
            Some("-Inf") => f64::NEG_INFINITY,
            Some(other) => panic!("unexpected fixture string {other:?}"),
            None => value.as_f64().unwrap(),
        }
    }

    fn assert_close_or_inf(actual: f64, expected: f64, context: &str) {
        if expected.is_infinite() {
            assert_eq!(actual, expected, "{context}");
        } else {
            assert_close(actual, expected, context);
        }
    }

    #[test]
    fn hodges_lehmann_matches_r_wilcox_test() {
        let fixture = r_fixture();
        for case in fixture["hodges_lehmann"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let x = floats(&case["x"]);
            let y = floats(&case["y"]);
            for (level_name, conf_level) in [("0.90", 0.90), ("0.95", 0.95)] {
                let expected = &case["levels"][level_name];
                let context = format!("{name} @ {level_name}");
                let hl = hodges_lehmann_ci(&x, &y, conf_level).unwrap();
                assert_close(hl.estimate, r_f64(&expected["estimate"]), &context);
                assert_close_or_inf(hl.lo, r_f64(&expected["lo"]), &context);
                assert_close_or_inf(hl.hi, r_f64(&expected["hi"]), &context);
            }
        }
        assert!(hodges_lehmann_ci(&[], &[1.0], 0.90).is_err());

        // 1v1: one pairwise difference can never reach 90% coverage;
        // R reports infinite bounds around the point estimate.
        let hl = hodges_lehmann_ci(&[3.0], &[1.0], 0.90).unwrap();
        assert_eq!(hl.estimate, 2.0);
        assert_eq!((hl.lo, hl.hi), (f64::NEG_INFINITY, f64::INFINITY));
    }

    #[test]
    fn signed_rank_matches_scipy_fixtures() {
        let fixture = fixture();
        for case in fixture["wilcoxon_signed_rank"].as_array().unwrap() {
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
                    ("approx", Method::Asymptotic),
                ] {
                    let expected = &case["alternatives"][alt_name][method_name];
                    let context = format!("{name} / {alt_name} / {method_name}");
                    let result = wilcoxon_signed_rank(&x, &y, alternative, method);
                    if expected.get("error").is_some() {
                        assert!(result.is_err(), "{context}: scipy errored, we did not");
                        continue;
                    }
                    let result = result.unwrap_or_else(|err| panic!("{context}: {err}"));
                    assert_close(result.statistic, expected["w"].as_f64().unwrap(), &context);
                    assert_close(result.p, expected["p"].as_f64().unwrap(), &context);
                }
            }
        }
    }

    #[test]
    fn signed_rank_rejects_degenerate_input() {
        assert_eq!(
            wilcoxon_signed_rank(&[1.0], &[1.0, 2.0], Alternative::TwoSided, Method::Auto),
            Err(Error::UnpairedSamples)
        );
        assert_eq!(
            wilcoxon_signed_rank(&[], &[], Alternative::TwoSided, Method::Auto),
            Err(Error::EmptySample)
        );
        assert_eq!(
            wilcoxon_signed_rank(
                &[1.0, 2.0],
                &[1.0, 2.0],
                Alternative::TwoSided,
                Method::Auto
            ),
            Err(Error::AllZeroDifferences)
        );
    }

    #[test]
    fn delong_ci_matches_proc_fixtures() {
        let fixture = r_fixture();
        for case in fixture["delong_auc"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let x = floats(&case["x"]);
            let y = floats(&case["y"]);
            let interval = a12_delong_ci(&x, &y, 0.95).unwrap();
            assert_close(interval.a12, case["auc"].as_f64().unwrap(), name);
            assert_close(interval.lo, case["lo"].as_f64().unwrap(), name);
            assert_close(interval.hi, case["hi"].as_f64().unwrap(), name);
            // The point estimate is the same quantity A12 counts.
            assert_close(interval.a12, vargha_delaney_a12(&x, &y), name);
        }
        // All-tied data: zero placement variance collapses the CI.
        let interval = a12_delong_ci(&[2.0, 2.0], &[2.0, 2.0], 0.95).unwrap();
        assert_eq!((interval.a12, interval.lo, interval.hi), (0.5, 0.5, 0.5));
        assert!(a12_delong_ci(&[], &[1.0], 0.95).is_err());
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
    fn count_statistics_match_scipy_fixtures() {
        let fixture = fixture();
        let counts = &fixture["counts"];
        for case in counts["binom_sf"].as_array().unwrap() {
            let (k, n) = (case["k"].as_u64().unwrap(), case["n"].as_u64().unwrap());
            let p = case["p"].as_f64().unwrap();
            let context = format!("binom_sf k={k} n={n} p={p}");
            assert_close(binomial_sf(k, n, p), case["sf"].as_f64().unwrap(), &context);
        }
        for case in counts["clopper_pearson"].as_array().unwrap() {
            let (k, n) = (case["k"].as_u64().unwrap(), case["n"].as_u64().unwrap());
            let level = case["level"].as_f64().unwrap();
            let context = format!("clopper_pearson k={k} n={n} level={level}");
            let (lo, hi) = clopper_pearson(k, n, level);
            assert_close(lo, case["lo"].as_f64().unwrap(), &context);
            assert_close(hi, case["hi"].as_f64().unwrap(), &context);
        }
        for case in counts["poisson_upper"].as_array().unwrap() {
            let k = case["k"].as_u64().unwrap();
            let level = case["level"].as_f64().unwrap();
            let context = format!("poisson_upper k={k} level={level}");
            assert_close(
                poisson_upper(k, level),
                case["upper"].as_f64().unwrap(),
                &context,
            );
        }
    }

    #[test]
    fn mde_ratio_is_analytic_and_monotone() {
        // Too few events: the one-sided exact test can never reject.
        assert_eq!(binomial_mde_ratio(0, 10.0, 10.0, 0.05, 0.8), None);
        assert_eq!(binomial_mde_ratio(2, 10.0, 10.0, 0.05, 0.8), None);

        // With enough events an MDE exists, shrinks as events grow,
        // and self-verifies: power at the MDE clears 0.8, power just
        // below it does not.
        let mde_20 = binomial_mde_ratio(20, 10.0, 10.0, 0.05, 0.8).unwrap();
        let mde_80 = binomial_mde_ratio(80, 10.0, 10.0, 0.05, 0.8).unwrap();
        assert!(mde_20 > mde_80 && mde_80 > 1.0, "{mde_20} vs {mde_80}");
        // Same arithmetic as the implementation — the bisection stops
        // at the boundary, where an ulp of difference flips the tail.
        let p_of = |rho: f64| rho * 10.0 / (rho * 10.0 + 10.0);
        let critical = (0..=20)
            .find(|&k| binomial_sf(k, 20, p_of(1.0)) <= 0.05)
            .unwrap();
        assert!(binomial_sf(critical, 20, p_of(mde_20)) >= 0.8);
        assert!(binomial_sf(critical, 20, p_of(mde_20 * 0.98)) < 0.8);
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
