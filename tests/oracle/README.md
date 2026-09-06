# Oracle fixture generators

`src/stats.rs` is validated against golden fixtures produced by
independent reference implementations — never against values derived
from the Rust code itself. Every expected number in
`tests/fixtures/stats_scipy.json` and `tests/fixtures/stats_r.json`
traces to one of the scripts here.

| Script | Oracle | Covers |
| --- | --- | --- |
| `gen_stats_scipy.py` | scipy + numpy | Mann-Whitney U (all alternatives × methods, tie/zero-variance edge cases), Wilcoxon signed-rank (exact / permutation / approx auto resolution), descriptives, A12 counting, Holm-Bonferroni (v1 port as its own oracle), exact binomial tail, Clopper-Pearson, Poisson upper bounds |
| `gen_stats_r.R` | R `wilcox.test` + pROC | Hodges-Lehmann shift estimate with the exact Moses order-statistic CI (including unachievable-level infinite bounds), DeLong A12 confidence intervals |

## Regenerating

```
nix run .#gen-stats-fixtures
```

The app lints the scripts (ruff, basedpyright, lintr) and rewrites
both JSONs under this flake's locked nixpkgs, so the interpreter and
library versions come from `flake.lock` — never from a machine
channel. The fixture JSONs record the versions they were generated
with; `cargo test` re-checks parity on every run at 1e-9 relative
tolerance.

## Rules

- New stats functions get an oracle case *first*; if scipy lacks the
  procedure (as with the Hodges-Lehmann CI), find the canonical
  reference implementation elsewhere (R) rather than self-certifying.
- Behavioral quirks of the oracles are preserved deliberately
  (scipy 1.18's signed continuity correction on zero variance, R's
  qwilcox boundary bump). If a regeneration changes golden values,
  the oracle version moved — investigate before updating the JSONs.
- jsonlite writes R's infinities as the strings `"Inf"`/`"-Inf"`;
  the Rust test harness maps them back.
