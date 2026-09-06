#!/usr/bin/env python3
"""Golden fixtures for koxi's stats module, generated with scipy/numpy.

Every expected value in tests/fixtures/stats_scipy.json traces to
this script. Regenerate (and lint) under the flake-locked scipy:

    nix run .#gen-stats-fixtures
"""

import json
import math
import sys

import numpy as np
from scipy import stats

FIO_LIKE_C = [
    30236.4,
    29873.1,
    30412.9,
    29954.2,
    30102.7,
    29873.1,
    30236.4,
    29788.5,
    30051.3,
    29912.8,
    30187.6,
    29873.1,
    30298.4,
    29954.2,
    30022.1,
    29841.9,
    30144.5,
    29788.5,
    30260.3,
    29912.8,
]
FIO_LIKE_RS = [
    25911.2,
    25640.8,
    26023.5,
    25733.1,
    25911.2,
    25580.4,
    25866.7,
    25733.1,
    25989.0,
    25640.8,
    25911.2,
    25802.6,
    25580.4,
    26051.9,
    25733.1,
    25866.7,
    25911.2,
    25698.3,
    25989.0,
    25640.8,
]

MWU_CASES = [
    ("small untied", [1.0, 4.0, 6.0, 9.0], [2.0, 3.0, 5.0, 7.0, 8.0]),
    (
        "both eight untied",
        [12.0, 5.0, 9.0, 1.0, 14.0, 3.0, 8.0, 11.0],
        [2.0, 6.0, 4.0, 13.0, 7.0, 10.0, 15.0, 16.0],
    ),
    (
        "auto probe 3 vs 12 untied",
        [10.5, 20.5, 30.5],
        [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 11.0, 12.0, 13.0],
    ),
    ("small tied", [1.0, 2.0, 2.0, 3.0], [2.0, 3.0, 3.0, 4.0, 5.0]),
    ("fio like ties", FIO_LIKE_C, FIO_LIKE_RS),
    ("quick reps three", [30236.4, 29873.1, 30412.9], [25911.2, 25640.8, 26023.5]),
    (
        "crash counts sparse",
        [0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        [0.0] * 10,
    ),
    (
        "nine vs nine untied",
        [1.0, 3.0, 5.0, 7.0, 9.0, 11.0, 13.0, 15.0, 17.0],
        [2.0, 4.0, 6.0, 8.0, 10.0, 12.0, 14.0, 16.0, 18.0],
    ),
]


def mwu_entry(name, x, y):
    entry = {"name": name, "x": x, "y": y, "alternatives": {}}
    for alt in ("two-sided", "greater", "less"):
        alt_out = {}
        for method in ("auto", "exact", "asymptotic"):
            try:
                res = stats.mannwhitneyu(x, y, alternative=alt, method=method)
                p = float(res.pvalue)
                alt_out[method] = {
                    "u1": float(res.statistic),
                    "p": None if math.isnan(p) else p,
                }
            except ValueError as err:
                alt_out[method] = {"error": str(err)}
        entry["alternatives"][alt] = alt_out
    return entry


def all_tied_entry():
    x = [0.0] * 10
    y = [0.0] * 10
    out = {}
    for alt in ("two-sided", "greater", "less"):
        try:
            res = stats.mannwhitneyu(x, y, alternative=alt, method="asymptotic")
            p = float(res.pvalue)
            out[alt] = {
                "u1": float(res.statistic),
                "p": None if math.isnan(p) else p,
            }
        except ValueError as err:  # record whatever scipy does
            out[alt] = {"error": f"{type(err).__name__}: {err}"}
    return {"name": "all tied", "x": x, "y": y, "asymptotic": out}


def vargha_delaney_a12(x, y):
    m, n = len(x), len(y)
    more = sum(1 for xi in x for yj in y if xi > yj)
    equal = sum(1 for xi in x for yj in y if xi == yj)
    return (more + 0.5 * equal) / (m * n)


A12_CASES = [
    ("clear separation", [5.0, 6.0, 7.0], [1.0, 2.0, 3.0]),
    ("overlap with ties", [1.0, 2.0, 2.0, 3.0], [2.0, 3.0, 3.0, 4.0]),
    ("identical", [2.0, 2.0], [2.0, 2.0]),
    ("fio like", FIO_LIKE_RS, FIO_LIKE_C),
]

DESC_CASES = [
    ("odd length", [3.0, 1.0, 4.0, 1.0, 5.0, 9.0, 2.0]),
    ("even length", [10.0, 20.0, 30.0, 40.0]),
    ("fio like", FIO_LIKE_C),
    ("two values", [1.5, 2.5]),
]


def desc_entry(name, values):
    arr = np.asarray(values)
    return {
        "name": name,
        "values": values,
        "median": float(np.median(arr)),
        "mean": float(np.mean(arr)),
        "std_ddof1": float(np.std(arr, ddof=1)) if len(values) > 1 else 0.0,
        "p25": float(np.percentile(arr, 25)),
        "p75": float(np.percentile(arr, 75)),
    }


# v1 block/compare/perf_compare holm_bonferroni, verbatim: the port
# must reproduce the adjusted values and the significance chain.
def holm_bonferroni(p_values, alpha=0.05):
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [1.0] * len(p_values)
    significant = [False] * len(p_values)
    running_max = 0.0
    m = len(p_values)
    for rank, (idx, p_value) in enumerate(indexed):
        candidate = (m - rank) * p_value
        running_max = max(running_max, candidate)
        adjusted[idx] = min(1.0, running_max)
    keep = True
    for rank, (idx, p_value) in enumerate(indexed):
        threshold = alpha / (m - rank)
        if keep and p_value <= threshold:
            significant[idx] = True
        else:
            keep = False
    return adjusted, significant


# Paired cases for scipy.stats.wilcoxon (zero_method="wilcox",
# correction=False — scipy defaults). Deltas engineered to cover:
# mixed signs, one-directional shift, zeros (dropped by wilcox),
# tied |d|, and both sides of the auto exact/approx cutoff.
WSR_CASES = [
    (
        "six untied mixed",
        [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
        [1.5, 1.2, 3.9, 3.1, 5.6, 5.2],
    ),
    (
        "eight one-directional",
        [10.1, 11.2, 12.3, 13.4, 14.5, 15.6, 16.7, 17.8],
        [9.0, 10.4, 11.1, 12.9, 13.2, 14.8, 15.9, 16.1],
    ),
    (
        "ten with zeros",
        [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0],
        [1.0, 2.5, 2.4, 4.0, 5.7, 5.3, 7.9, 7.2, 9.8, 9.1],
    ),
    (
        "twelve tied magnitudes",
        [5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0],
        [4.0, 7.0, 6.0, 9.0, 8.0, 11.0, 9.5, 13.5, 11.0, 16.0, 13.0, 18.0],
    ),
    (
        "thirty untied",
        [float(i) for i in range(1, 31)],
        [i + ((-1) ** i) * (0.1 + 0.013 * i) for i in range(1, 31)],
    ),
    (
        "fifty five untied",
        [float(i) for i in range(1, 56)],
        [i + ((-1) ** i) * (0.1 + 0.007 * i) for i in range(1, 56)],
    ),
    (
        "crash like mostly zero",
        [0.0, 0.0, 1.0, 0.0, 0.0, 2.0, 0.0, 0.0, 0.0, 1.0],
        [0.0] * 10,
    ),
]


def wsr_entry(name, x, y):
    entry = {"name": name, "x": x, "y": y, "alternatives": {}}
    for alt in ("two-sided", "greater", "less"):
        alt_out = {}
        for method in ("auto", "exact", "approx"):
            try:
                res = stats.wilcoxon(x, y, alternative=alt, method=method)
                p = float(res.pvalue)
                alt_out[method] = {
                    "w": float(res.statistic),
                    "p": None if math.isnan(p) else p,
                }
            except ValueError as err:
                alt_out[method] = {"error": str(err)}
        entry["alternatives"][alt] = alt_out
    return entry


HOLM_CASES = [
    ("mixed", [0.01, 0.04, 0.03, 0.005], 0.05),
    ("none significant", [0.2, 0.8, 0.5], 0.05),
    ("all significant", [0.001, 0.002, 0.003], 0.05),
    ("duplicates", [0.02, 0.02, 0.04], 0.05),
    ("single", [0.04], 0.05),
]


def holm_entry(name, p_values, alpha):
    adjusted, significant = holm_bonferroni(p_values, alpha)
    return {
        "name": name,
        "p_values": p_values,
        "alpha": alpha,
        "adjusted": adjusted,
        "significant": significant,
    }


# Count statistics for the fuzz rate-ratio gate: exact binomial tail
# (binomtest alternative="greater"), Clopper-Pearson interval
# (proportion_ci method="exact"), exact Poisson upper bound
# (gamma.ppf(level, k+1)).
BINOM_SF_CASES = [
    (0, 5, 0.5),
    (3, 5, 0.5),
    (5, 5, 0.9),
    (2, 10, 1.0 / 3.0),
    (7, 12, 0.5),
    (1, 20, 0.02),
    (4, 4, 0.25),
    (10, 100, 0.05),
]

CP_CASES = [(0, 6), (2, 10), (5, 5), (7, 40), (1, 3), (0, 1)]

POISSON_CASES = [(0, 0.95), (0, 0.975), (1, 0.95), (3, 0.95), (10, 0.975)]


def counts_section():
    return {
        "binom_sf": [
            {
                "k": k,
                "n": n,
                "p": p,
                "sf": float(stats.binomtest(k, n, p, alternative="greater").pvalue),
            }
            for k, n, p in BINOM_SF_CASES
        ],
        "clopper_pearson": [
            {
                "k": k,
                "n": n,
                "level": level,
                "lo": float(ci.low),
                "hi": float(ci.high),
            }
            for k, n in CP_CASES
            for level in (0.90, 0.95)
            for ci in [
                stats.binomtest(k, n).proportion_ci(
                    confidence_level=level, method="exact"
                )
            ]
        ],
        "poisson_upper": [
            {"k": k, "level": level, "upper": float(stats.gamma.ppf(level, k + 1))}
            for k, level in POISSON_CASES
        ],
    }


fixture = {
    "scipy": __import__("scipy").__version__,
    "numpy": np.__version__,
    "mwu": [mwu_entry(*case) for case in MWU_CASES],
    "mwu_all_tied": all_tied_entry(),
    "a12": [
        {"name": name, "x": x, "y": y, "a12": vargha_delaney_a12(x, y)}
        for name, x, y in A12_CASES
    ],
    "descriptive": [desc_entry(*case) for case in DESC_CASES],
    "holm": [holm_entry(*case) for case in HOLM_CASES],
    "wilcoxon_signed_rank": [wsr_entry(*case) for case in WSR_CASES],
    "counts": counts_section(),
}

json.dump(fixture, sys.stdout, indent=1)
