# How the gates test

The two measured gates share one shape: the null hypothesis is "the
Rust driver is worse by at least the margin", and only rejecting it
passes. Failing to reject never passes. Everything to the left of the
decision diamonds below is descriptive, kept for continuity with v1,
and gates nothing.

```mermaid
flowchart TD
    subgraph PERF["Performance gate: one-sided non-inferiority per workload, intersection-union across workloads"]
        P0["fio JSON per rep, both drivers<br>same guest geometry, one boot per driver"]
        P1["Drop rep 1 (warm-up)<br>reject unparseable JSON<br>keep workloads present on both sides"]
        P2["Per workload: IOPS samples for C and Rust<br>take log IOPS"]
        P3["Hodges-Lehmann shift of log IOPS<br>= median of all pairwise Rust - C differences"]
        P4["Order-statistic 90% CI on the shift (1 - 2 alpha)<br>exponentiate: ratio interval [lo, hi]"]
        P5{"lo >= 0.95 ?<br>margin 5%, alpha 0.05 one-sided"}
        P6["workload passes"]
        P7["workload fails<br>(too few samples to bound = fail)"]
        P8["Descriptive only:<br>Mann-Whitney U, Holm across workloads<br>A12 with DeLong CI<br>seeded bootstrap 95% CI on median delta, B = 10000"]
        P9{"every workload passed?"}
        PP["performance PASS<br>FWER <= alpha, no correction (Berger)"]
        PF["performance FAIL"]
        P10["Device geometry read back from both guests<br>shared attribute differs: data quality = inferred"]
        P0 --> P1
        P1 --> P2
        P1 --> P10
        P2 --> P3
        P2 --> P8
        P3 --> P4
        P4 --> P5
        P5 -->|yes| P6
        P5 -->|no| P7
        P6 --> P9
        P7 --> P9
        P9 -->|yes| PP
        P9 -->|no| PF
    end

    subgraph FUZZ["Fuzzing gate: exact conditional bound on the crash rate ratio"]
        F0["syzkaller crash buckets per campaign, both drivers"]
        F1["Classify each bucket by call stack only<br>strip 'Modules linked in'<br>driver or abstraction frame = target-attributable<br>infra signature anywhere = infrastructure noise<br>otherwise unknown; override CSV wins"]
        F2["Exposure per campaign = seconds it actually ran<br>budget only as a labelled fallback<br>T_C and T_Rust = sums per side"]
        F3["k_C, k_Rust = target-attributable buckets<br>summed across campaigns"]
        F4{"k_C + k_Rust = 0 ?"}
        F5["INCONCLUSIVE<br>report per-side 95% Poisson bound<br>about 3 / T crashes per hour"]
        F6["Condition on N = k_C + k_Rust<br>Rust share ~ Binomial(N, p0)<br>p0 = T_Rust / (T_C + T_Rust)"]
        F7["Clopper-Pearson interval on the share (1 - 2 alpha)<br>ratio bounds rho = p / (1 - p) * T_C / T_Rust<br>one-sided exact p for H0: rho <= 1<br>minimum detectable ratio at 80% power"]
        F8{"upper bound <= 2 ?<br>(margin)"}
        F9{"lower bound > 1 ?"}
        FP["fuzzing PASS: non-inferior"]
        FF["fuzzing FAIL: inferior"]
        F10["Descriptive only:<br>Mann-Whitney U and A12 over per-campaign counts"]
        F0 --> F1
        F0 --> F2
        F1 --> F3
        F1 --> F10
        F2 --> F4
        F3 --> F4
        F4 -->|yes| F5
        F4 -->|no| F6
        F6 --> F7
        F7 --> F8
        F8 -->|yes| FP
        F8 -->|no| F9
        F9 -->|yes| FF
        F9 -->|no| F5
    end

    subgraph VERDICT["Verdict"]
        S["Safety gate: elimination rate >= 34.2%<br>threshold rule, exact 95% CI and n reported"]
        V1{"any decidable gate failed?"}
        V2{"all three present and passed?"}
        VF["overall FAIL<br>recommendation names failed and undecided legs"]
        VP["overall PASS"]
        VI["overall INCONCLUSIVE"]
        VX["overall PARTIAL"]
        V3["data quality = worst of the gates<br>TCG substrate: guest-side gates = inferred<br>Phase-1 screening folded in"]
        PP --> V1
        PF --> V1
        FP --> V1
        FF --> V1
        F5 --> V1
        S --> V1
        V1 -->|yes| VF
        V1 -->|no| V2
        V2 -->|yes| VP
        V2 -->|a gate undecided| VI
        V2 -->|a gate missing| VX
        VF --> V3
        VP --> V3
        VI --> V3
        VX --> V3
    end
```

Two things the picture cannot show:

- **This is the left half of a TOST, not a TOST.** Equivalence testing
  runs two one-sided tests and needs both to reject. The performance
  gate runs one: it shows the Rust driver is not more than the margin
  slower, and never tests whether it is faster, because a faster Rust
  driver is not a problem for a migration decision. A pass means "not
  worse than 5%", never "the same". The artifact field names still say
  `tost`; the README and this page say non-inferiority.
- **v1 had the burden of proof backwards.** Its performance gate passed
  when a Mann-Whitney test failed to reach significance, and its
  fuzzing gate passed when sparse counts could not separate, which is
  "we know nothing" read as parity. v2 flips the null in both gates,
  and the fuzzing gate says inconclusive out loud when the data cannot
  bound the ratio either way.

The implementation is `src/block/compare/perf.rs` and
`src/block/compare/fuzz.rs` on top of `src/stats.rs`, whose functions
are checked against scipy, numpy and R fixtures on every `cargo test`.
