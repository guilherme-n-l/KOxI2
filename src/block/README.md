# KOxI Block Harness

The block-device instantiation of KOxI: `koxi block …`. See the
[repository README](../../README.md) for the methodology this
implements, the evidence lenses, and the verdict semantics.

The harness is calibrated around block driver behavior, workloads,
and evidence thresholds. Another driver class should reuse the KOxI
structure and recalibrate the class-specific thresholds below.

## What it measures

Phase 1 screens a C driver on its own: static structure and unsafe
surface, commit-history risk, and syzkaller campaigns with crash
attribution. Phase 2 evaluates a registered Rust counterpart against
it: Rust unsafe surface split between driver code and the shared
`rust/kernel/` abstractions, matched campaigns, and a matched fio
matrix. The main Phase-2 pair is `null_blk` (C) versus `rnull`
(Rust).

Phase 1 iterates every registered C driver, paired or not: a driver
nobody has rewritten still gets its static analysis, its campaigns
and a screening band. Phase 2 iterates pairs, since it needs both
halves.

## Quick start

In an existing checkout of this repository, `koxi.toml` is already
here. For a project of your own, `koxi new <path> --nix` writes one;
see [starting a project](../../README.md#starting-a-project).

```sh
# runtime shell: koxi + every tool the pipeline shells out to, pinned
nix develop .#koxi

koxi block test    # preflight: tools, toolchain sanity, headers
koxi block setup   # fetch + verify all sources, build everything

# the whole pipeline under one campaign name, at development sizes
koxi block all --quick --campaign dev

# re-gate a campaign later without collecting new data
koxi block compare --campaign dev
```

Useful variants:

```sh
koxi block all --p1 --quick               # phase 1 only
koxi block perf --quick --campaign dev    # just the fio matrix
koxi block static --campaign dev          # just the host-side analysis
koxi vm --driver rnull ls -l /dev/rnullb0 # boot the guest and look around
koxi vm --fuzz                            # boot the instrumented kernel
```

Real campaigns need an x86_64 Linux host with `/dev/kvm` and enough
RAM for the guests. `koxi block perf` and `koxi block fuzz` refuse a
host that has neither, naming what is missing.

`--longrun` is a long-run profile, not the published dataset's plan.
That dataset was 10 fuzzing campaigns of 24 hours and 50 fio
repetitions per cell, so reproducing it takes the campaign count
explicitly:

```sh
koxi block all --longrun --fuzz-campaigns 10 --campaign paper
```

## Commands

| Command              | Purpose                                                                                 |
| -------------------- | --------------------------------------------------------------------------------------- |
| `koxi block setup`   | Fetch and verify every source, build both kernel flavors and the guest userland.        |
| `koxi block test`    | Preflight the host: tools on PATH, a compiler whose binaries run, kernel build headers. |
| `koxi block static`  | AST metrics and commit mining, for the C baseline and the Rust driver.                  |
| `koxi block fuzz`    | Syzkaller campaigns for both sides.                                                     |
| `koxi block perf`    | The fio benchmark matrix, one boot per driver.                                          |
| `koxi block screen`  | Synthesize the Phase-1 candidacy band from cached baselines.                            |
| `koxi block compare` | The three gates plus the overall verdict for a named campaign.                          |
| `koxi block all`     | Every phase in order, phase-aware, under one campaign name.                             |

Each verb declares only the options it reads, so `koxi block <verb>
--help` is the truth about what that verb consumes.

## Common flags

| Flag                   | Meaning                                                                      |
| ---------------------- | ---------------------------------------------------------------------------- |
| `--quick`              | Fast development settings: small fio matrix, short campaigns.                |
| `--longrun`            | Paper defaults: 30 campaigns of 24 hours, 50 fio reps.                       |
| `--p1`                 | Phase 1 only.                                                                |
| `--only <name[:name]>` | Limit the run to one or more C drivers.                                      |
| `--campaign <name>`    | Name the Phase-2 campaign directory. Required by `compare`.                  |
| `--force-p1`           | Re-run cached Phase-1 baseline work.                                         |
| `--force-build`        | Rebuild kernel artifacts.                                                    |
| `--allow-unfit-host`   | Run a campaign on a host the fitness gate rejects. The numbers are not data. |

Every measurement knob also reads an environment variable, keeping
the names v1 used. The fio matrix (`--fio-bs`, `--fio-rw`, `--fio-qd`,
`--fio-sz`, `--fio-reps`, `--fio-runtime`, `--fio-engine`) and the
campaign plan (`--fuzz-campaigns`, `--fuzz-hours`, `--fuzz-parallel`)
are the class workload knobs; `--quick` and `--longrun` fill only the
ones nothing else pinned, so an explicit flag or environment variable
always beats a profile. See `koxi block perf --help` and
`koxi block fuzz --help` for the full sets.

## Driver registry

Drivers are declared under `[block.drivers]` in `koxi.toml`. Each
entry tells the harness where the module is built, how to load it in
the guest, and where its source lives in the kernel tree.

| Driver     | Role | Pair       | Notes                                                        |
| ---------- | ---- | ---------- | ------------------------------------------------------------ |
| `null_blk` | C    |            | The C baseline of the Phase-2 pair; carries `history-paths`. |
| `rnull`    | Rust | `null_blk` | Declares the `rust/kernel/` abstractions it leans on.        |
| `loop`     | C    |            | Boots; needs a file-backed `/dev/loop0` (`prep`).            |
| `brd`      | C    |            | Boots; RAM disk.                                             |
| `zram`     | C    |            | Built as a module; needs a configured disk size (`prep`).    |
| `nbd`      | C    |            | Boots; needs an in-guest connector before it is usable.      |
| `dm-zero`  | C    |            | Built as a module; needs `dmsetup`, which BusyBox lacks.     |

Only `rnull` carries `pair`, so `null_blk` is the only driver that
reaches Phase 2; the rest screen and stop. The Rust entry also carries
`abstractions`, the kernel-tree paths whose unsafe surface is counted
separately, so a driver body with no `unsafe` cannot hide unsafe
pushed one layer down; crash attribution charges those paths to the
Rust driver as well, so a crash whose only frames are in
`kernel::block::mq` is its crash, not an unknown one.

Two more things the pair's entries pin, because the defaults differ
between the two drivers and a comparison on defaults measures the
difference in configuration as much as in implementation:

- **Device geometry.** `configfs-params` sets block size, capacity,
  completion mode and (for null_blk) queue depth and submit queues to
  the same values on both sides, and `prep` pins the I/O scheduler.
  Left alone, null_blk completes through softirq with 512-byte blocks
  and 64 tags under no scheduler, and rnull completes inline with 4 KiB
  blocks and 256 tags under mq-deadline. The perf phase reads back
  what each device presented and records it in the manifest.
- **History.** `history-paths` lists where the driver's source lived
  before `gitpath`, so commit mining is not cut off at the move that
  created the current directory. null_blk was a single file under
  `drivers/block/` from 2013 to 2020, and the directory alone holds
  139 of its 364 commits. `commits_summary.csv` states the window it
  mined.

## Results

The default result root is `results/`, overridable with `--output`.
It holds measurement data only, and is never touched by `koxi clean`.

Phase 1 is a content-addressed baseline cache. Changing a knob
changes the identity hash, which mints a fresh baseline and leaves
the old one in place:

```text
results/p1/<c_driver>/
|-- screening.json                  # the candidacy band
|-- static/<identity_hash>/
|   |-- manifest.toml
|   |-- functions.csv  unsafe_sites.csv  unsafe_density.csv  loc.csv
|   `-- commits.csv    commits_summary.csv
|-- fuzz/<identity_hash>/
|   |-- manifest.toml
|   `-- campaigns/campaign_<n>/
|       |-- syz.cfg  syz-manager.log  .campaign_done
|       |-- crashes/<crash_id>/
|       `-- crash_classification.json
`-- perf/<identity_hash>/
    |-- manifest.toml  kernel.log
    `-- <bs>_<rw>_<qd>_<size>/fio_<rep>.json
```

Phase 2 stores campaign outputs by driver pair, in the same per-domain
shapes, plus the gate artifacts:

```text
results/p2/<c_driver>::<rs_driver>/<campaign>/
|-- static/  fuzz/  perf/
`-- compare/
    |-- safety.json       safety.csv
    |-- fuzz_stats.json   fuzz.csv
    |-- perf_stats.json   perf.csv
    `-- verdict.json
```

Every result root carries a `manifest.toml`; see
[the model](../../README.md#the-model) for what its `[identity]`
table holds and why. For the block harness the identity that matters
is the fio matrix for a perf root and the campaign plan for a fuzz
root, so changing `--fio-engine` or `--fuzz-hours` mints a fresh
baseline rather than pooling with the old one.

## Screening a candidate

`koxi block screen` answers the Phase-1 question without needing a
Rust counterpart: is this C driver worth considering at all. It reads
the cached Phase-1 baselines under `results/p1/<c_driver>/`, taking
the newest complete one per domain and recording which hash it used,
and scores four dimensions from 0 to 3:

| Dimension            | Read from                             | Scored on                                                                          |
| -------------------- | ------------------------------------- | ---------------------------------------------------------------------------------- |
| `historical_risk`    | `commits.csv`, `commits_summary.csv`  | 3 at 40% safety-related commits or 25 of them; 2 at 20% or 10; 1 if any; else 0.   |
| `static_surface`     | `functions.csv`, `unsafe_density.csv` | 3 at 2000 lines or 500 implicit unsafe operations; 2 at 800 or 150; 1 if any.      |
| `dynamic_robustness` | the fuzz baseline's campaigns         | 3 if any crash is target-attributable; 2 if any is unknown; 1 if only infra noise. |
| `tractability`       | which baselines are cached            | 3 if static and fuzz are both cached with 10 or more campaigns; 2 if both; else 1. |

The mean of the available scores becomes the band:
`strong_candidate` at 2.5 or above, `moderate` at 1.5, otherwise
`weak`, and `inconclusive` when fewer than two dimensions produced a
score at all. The result carries the worst data quality of its
dimensions, so a band computed partly from inferred evidence says so,
and lands in `results/p1/<c_driver>/screening.json`.

Screening never invents evidence: a domain with no cached baseline
scores nothing and is reported as unavailable rather than as zero.

## Comparing a campaign

`koxi block compare --campaign <name>` is Phase 2, and collects no
data of its own. For each registered pair it walks
`results/p2/<c>::<rs>/<campaign>/` and, per domain, resolves the
baseline the campaign recorded rather than whatever is newest:

1. Load the campaign domain's `manifest.toml`. A domain that was
   never run is skipped; one that exists but is incomplete is an
   error, since a partial measurement is not a comparable one.
2. Read the baseline identity hash out of the manifest and resolve
   `results/p1/<c>/<domain>/<hash>/`. A missing or incomplete
   baseline is an error.
3. Refuse the pair outright if the two identities disagree on host or
   acceleration. KVM and TCG numbers, or numbers from two machines,
   must never be pooled, and the manifest is what makes that
   checkable after the fact.

Each domain that survives that feeds its gate, and the artifacts land
in `<campaign>/compare/`.

Because the baseline is recorded by hash and not by symlink, a
results tree can be moved between machines and re-gated there:
`compare` runs wherever the tree lives.

## Gate artifacts and thresholds

| Gate        | Artifact          | Gated quantity                                                                                                                                   |
| ----------- | ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Safety      | `safety.json`     | Elimination rate over CWE-classified fix commits, against `--safety-threshold`; the exact 95% interval and n travel with it.                     |
| Fuzzing     | `fuzz_stats.json` | Non-inferiority of the target-attributable crash rate ratio, against `--fuzz-rate-margin`: `non_inferior`, `inferior`, or `inconclusive`.        |
| Performance | `perf_stats.json` | Per-workload one-sided non-inferiority on the Hodges-Lehmann log-IOPS ratio, combined as an intersection-union test, against `--perf-threshold`. |

These defaults are calibrated for block drivers:

| Knob                           | Flag                    | Default |
| ------------------------------ | ----------------------- | ------- |
| Safety elimination threshold   | `--safety-threshold`    | `34.2%` |
| Performance overhead threshold | `--perf-threshold`      | `5%`    |
| Fuzz rate-ratio margin         | `--fuzz-rate-margin`    | `2`     |
| Significance alpha             | `--alpha`               | `0.05`  |
| Bootstrap resamples            | `--bootstrap-resamples` | `10000` |

The thresholds are conventions, not derivations. 34.2% is the share
of Linux driver CVEs from 2020 to 2024 that Li et al. (ACSAC 2024,
Table 2) label as eliminated by Rust alone, 82 of 240, so the safety
gate asks whether this driver's history is at least as
Rust-eliminable as the fleet's; 5% is a conventional noise floor for a
throughput regression; and a rate ratio of 2 is the smallest
regression a campaign of this size can hope to rule out, which the
reported minimum detectable ratio makes checkable per run.

`fuzz_stats.json` also reports `exposure_basis`. A campaign records
the hours it actually ran, and the crash rate is divided by the sum
of those; a campaign that recorded none falls back to its budget and
the basis says so, because that denominator is then partly a plan
rather than a measurement. Its `verdict.outcome` is one of three
words: with zero events on both sides, or too few to bound the ratio,
it is `inconclusive` and `pass` is null, so the gate is never passed
by a campaign that found nothing.

`perf_stats.json` reports `data_quality.device_geometry`: the block
queue limits and configfs attributes each device actually presented,
read from the guest, and whether the two sides matched. A mismatch
drops the gate's data quality to `inferred`, because the comparison
is then between configurations as much as implementations.

## The verdict

`verdict.json` is the last artifact `compare` writes, and the only
one meant to be read first. It summarizes each gate, aggregates them
conservatively, and states a recommendation.

Per dimension it records whether the gate ran at all, whether it
passed, the data quality behind it, the gate's own one-line detail,
and the numbers a reader would otherwise have to dig out of the
gate artifact:

| Dimension     | Key numbers reported                                                                                    |
| ------------- | ------------------------------------------------------------------------------------------------------- |
| `safety`      | The elimination rate, its exact 95% interval, the n behind it, and the threshold it was tested against. |
| `fuzzing`     | The metric used, its p-value and A12, the rate-ratio upper bound, the outcome, and the gate basis.      |
| `performance` | The median delta, how many workloads passed the non-inferiority test, and the threshold.                |

The overall field is deliberately conservative:

- **`fail`** when any decidable gate failed, whatever the others did.
  One clear failure is enough to argue against replacing a mature C
  driver, and an undecided or unmeasured gate beside it does not
  soften that into "inconclusive".
- **`pass`** only when all three dimensions are present and all
  passed.
- **`inconclusive`** when nothing failed and at least one present
  gate could not decide: a fuzzing campaign with no events, say.
- **`partial`** when nothing failed and a dimension is missing, so
  the evidence cannot support a full verdict either way.

The verdict also records the `substrate` the guest-side campaigns ran
on (host and acceleration). Under TCG the fuzzing and performance
dimensions are marked `inferred` whatever they measured, since the
timing is the emulator's.

The recommendation is v1's matrix over the (safety, fuzzing,
performance) triple when all three decided, unchanged so that a v1
and a v2 report read the same way; a failure with an undecided or
missing dimension beside it is spelled out instead ("Do not replace:
performance fail; fuzzing undecided"):

| Safety | Fuzzing | Performance | Recommendation                                                   |
| ------ | ------- | ----------- | ---------------------------------------------------------------- |
| pass   | pass    | pass        | Replace: Rust driver meets all criteria for production use.      |
| pass   | pass    | fail        | Caution: safety and fuzzing pass but performance regresses.      |
| pass   | fail    | pass        | Caution: fuzzing shows regression, investigate before replacing. |
| pass   | fail    | fail        | Do not replace: fuzzing and performance both regress.            |
| fail   | pass    | pass        | Caution: safety elimination rate below threshold.                |
| fail   | pass    | fail        | Do not replace: safety and performance fail.                     |
| fail   | fail    | pass        | Do not replace: safety and fuzzing both fail.                    |
| fail   | fail    | fail        | Do not replace: all dimensions fail.                             |

Two things travel alongside the decision. The `data_quality` block
carries the worst quality of any dimension that produced one, ordered
`unavailable` below `inferred` below `measured` below
`manually_validated`, so a verdict resting partly on inferred
evidence cannot be quoted as if it were measured. And `caveats` names
every dimension that was missing, so a `partial` says which leg it is
standing on. The Phase-1 screening is folded in whole, which keeps
the candidacy band that motivated the campaign next to the campaign's
own result.

The verdict also records the campaign name, the per-domain baseline
hashes it compared against, and the driver pair, so the report
identifies the exact data it came from.

## Known limitations

The harness-wide limitations, covering the shared cache, the lock
format and the host fitness gate, are in the
[repository README](../../README.md#known-limitations). The block
harness adds two of its own:

- Every guest forwards its dropbear to one host port (`--port`, 5555
  by default), so two runs on one host need distinct ports; the second
  fails at boot rather than hanging.
- Run logs under `$KOXI_HOME/log/` are never swept. They are small
  (about a megabyte per thirty-five runs) but they are yours to
  remove.

## Adding a block driver

1. Add a `[block.drivers.<name>]` table to `koxi.toml`.
2. Set at least `role`, `ko`, `ko-dir`, `device`, and `gitpath`.
3. Add `insmod`, `configfs`, `configfs-params`, or `prep` when the
   guest must do more before the device node appears.
4. For a Rust driver, set `pair` to the C driver it replaces and
   `abstractions` to the kernel-tree paths whose unsafe surface
   should be counted separately from the driver body. Configure both
   halves of a pair identically (`configfs-params`, `prep`), and give
   the C driver its `history-paths` if the source has moved.
5. Run `koxi block setup` so the module is built and harvested, then
   `koxi vm --driver <name>` to confirm the device node appears
   before spending a campaign on it.
