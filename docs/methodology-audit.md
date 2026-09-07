# Methodology audit

An adversarial pass over what the instrument concludes, as distinct
from whether it runs (that is [hardening.md](hardening.md)). The
question asked of every gate, rubric and data path was the one a
statistician or a block-layer maintainer would ask from the floor
three weeks from now. Findings are ranked by how much of a published
conclusion they touch. Each says whether it was fixed in code or is
disclosed, and where.

The published pair (null_blk against rnull, linux 6.19) is the frame
throughout, because those are the numbers on the slides.

## Fixed

### 1. The two devices were not configured alike

The registry set `power=1` on both drivers and left everything else at
its default. The defaults differ, and not in small ways:

| attribute      | null_blk default      | rnull default   |
| -------------- | --------------------- | --------------- |
| completion     | softirq (`irqmode=1`) | inline (`None`) |
| logical block  | 512 B                 | 4096 B          |
| capacity       | 250 GiB               | 4 GiB           |
| hw queue depth | 64                    | 256             |
| I/O scheduler  | none                  | mq-deadline     |

Read from the guest on the pinned 6.19 tree (`drivers/block/null_blk/main.c`
lines 88-208, `drivers/block/rnull/configfs.rs` lines 73-77 and
`rnull.rs` line 58, and `/sys/block/*/queue` at boot). The C device
completed every request through a softirq and dispatched 64 at a time;
the Rust device completed inline, dispatched 256, and went through a
scheduler. Every published delta is a difference between those
configurations plus whatever the implementations add. The direction is
not obvious either: inline completion and no scheduler are the cheaper
paths, and the Rust side had one of each.

**Fixed.** Both registry entries now pin `blocksize=4096`, `size=4096`,
`irqmode=1`, and null_blk additionally `hw_queue_depth=256` and
`submit_queues=1`; `prep` sets the scheduler to `none` on both. The
perf phase reads what each device actually presents (`/sys/block/*/queue`
and the configfs attributes) into the manifest, and `compare` reports
`device_geometry` with a `matched` flag and drops the gate to `inferred`
when the two sides differ. The published performance numbers were
measured before this and should be described as a comparison on
default configurations.

### 2. The fuzzing gate passed on nothing, and failed on one crash

With zero target-attributable crashes on both sides the ratio is 0/0;
the gate reported the per-side Poisson bound and `pass: true`. With
one C crash and zero Rust crashes (the published data) the one-sided
upper bound on the ratio is 19, above the margin of 2, so the gate
reported `pass: false`. More evidence against C made Rust fail, and no
evidence at all made it pass. The README's promise that a gate with no
usable evidence never counts as a pass was not kept.

**Fixed.** The gate is three-valued: `non_inferior` when the upper
bound clears the margin, `inferior` when the lower bound sits above 1,
`inconclusive` otherwise, including the zero-event case, where the
per-side bound is still reported as what the exposure did establish.
`pass` is null for an inconclusive gate. Under this rule the published
fuzzing result is inconclusive, not a pass: one crash in 480 campaign
hours bounds nothing. That is the honest reading and the slide says so.

### 3. A failed gate could be outvoted by an undecided one

The verdict aggregator only produced "fail" when all three gates had
decided. A failed performance gate next to an undecided fuzzing gate
came out "inconclusive", against the documented rule that one clear
failure is enough. Finding 2 would have turned the published verdict
from "fail" into "inconclusive" through this path.

**Fixed.** A failure decides whatever the other gates did; the
recommendation names the legs it stands on ("Do not replace:
performance fail; fuzzing undecided").

### 4. Crashes in the abstraction layer were nobody's

The safety gate charges `rust/kernel/block/` to rnull, since that is
where the unsafe it leans on lives. Crash attribution did not: a
report whose frames are all in `kernel::block::mq` (a completion from
softirq context, say) had no `rnull` frame and landed in `unknown`,
outside the gated count. The two gates disagreed about what the Rust
driver is.

**Fixed.** The classifier takes the registry's `abstractions` and
matches both the demangled (`kernel::block`) and v0-mangled
(`6kernel5block`) spellings in the call stack.

### 5. Commit mining stopped at the directory move

`git log -- drivers/block/null_blk/` returns 139 commits, the oldest
being the November 2020 commit that created the directory. The driver
was `drivers/block/null_blk.c` and then `null_blk_main.c` from 2013,
and the full history is 364 commits. The screening's historical-risk
score, the "65% safety-related" figure and the safety gate's
denominator all rested on the most recent 38% of the driver's life,
without saying so.

**Fixed.** `history-paths` in the registry carries the earlier paths
and mining runs over all of them; `commits_summary.csv` records
`history_from` and `history_to`, and the log states the window. The
published numbers were mined over the 2020 to 2026 window and should
be quoted with it.

### 6. The safety rate had no interval and the README claimed a test

The README said every gate states its criterion as a hypothesis test.
The safety gate compared 2/11 = 18.2% to 34.2% as a point estimate.
The exact 95% interval on 2/11 is 2.3% to 51.8%, which contains the
threshold; it would also contain it for 4/11.

**Partly fixed.** `safety.json` and the verdict now carry the exact
interval, the n, and whether the threshold falls inside it, and the
README calls the gate a threshold rule. The rule itself is unchanged:
gating on the lower bound would make the gate unpassable at n=11, and
whether that is right is a calibration decision, not a bug.

### 7. Two spellings and two patterns the classifier missed

The driver's own name was scrubbed as `null_blk` but not as
`null-blk`, so "null-blk: save memory footprint" counted as
safety-related through the hyphen's word boundary. "fix
null-ptr-dereference" matched no CWE rule (the rule wanted "null ptr"
with a space), and "fix zone read length beyond write pointer", an
out-of-bounds read, matched nothing and fell out of the denominator.

**Fixed.** The name is scrubbed in either spelling before matching;
CWE-476 accepts `null.?ptr` and `null.?deref`; a CWE-125 rule catches
reads past a bound before the CWE-787 rule can claim them as writes.
Both rules are in the `classify.toml` asset, whose sha is part of the
static identity, so the baselines re-mine.

### 8. "manually_validated" meant one row

One hand-edited `manual_cwe` relabelled the whole safety dimension as
manually validated. **Fixed:** the label now requires every commit in
the denominator to carry a validator, and `data_quality.validation`
reports `validated/classified`.

### 9. TCG numbers travelled as "measured"

The manifests record the acceleration, and `compare` refuses to pool
KVM with TCG, but the verdict never said which it was, and a TCG run's
performance dimension was `measured`. **Fixed:** the verdict records
the substrate and marks the guest-side dimensions `inferred` under
TCG.

### 10. The host tag was "unknown"

`hostname` is not in the nix shell on every distribution, so every
manifest on the reference host said `host = "unknown"`, and the
same-substrate guard could not have told two such machines apart.
**Fixed:** the kernel's own record is read first.

### 11. Two of the published Rust campaigns never ran, and one ran 9.5 hours

The published dataset says ten 24-hour campaigns per driver. The
syz-manager logs under `KOxI-Results/p2/null_blk::rnull/paper-v2-null_blk/fuzz/`
say otherwise for the Rust side: campaigns 1 to 7 ran their 24 hours,
campaign 8 ran from 23:56 on 17 May 2026 to 09:24 on 18 May and died,
and campaigns 9 and 10 are one line each:

```
[FATAL] stat .../out/rootmnt/.ssh/nullb_id_rsa: permission denied
```

The harness lost read access to its own ssh key and the last three
campaigns went with it. The C side ran all ten. So the published Rust
exposure is about 177 hours, not 240, and v1's per-campaign vector
(`[12, 0, 10, 12, 8, 13, 8, 9, 9, 0]`, in lexical order, so the zeros
are campaigns 10 and 9) counted two campaigns that never started as two
campaigns with no crashes. The rank test was computed on that vector.

**Fixed in the instrument, disclosed for the paper.** v2 records the
hours a campaign ran in its completion marker, a campaign that died
before writing one is `unavailable` rather than a zero, and the rate
ratio divides by measured hours. For the talk: the Rust side is seven
full campaigns and part of an eighth, the exposure bound is 0.017
crashes per hour (one per 59 hours) rather than 0.0125, and the limits
slide says N = 10 planned. The reader's discrepancy 9 named campaigns
2 and 10 from the vector; the logs name 8, 9 and 10.

## Disclosed

These are stated in the README's "Known seams" and on the limits
slide. None is fixed in code.

- **Exposure is hours, not surface.** The rate ratio divides crashes
  by wall-clock hours. rnull implements a fraction of what null_blk
  does (361 lines against 2,491 in mainline; no zones, discard,
  memory backing or fault injection), so the ioctls syzkaller sends
  reach real code on one side and no-ops on the other. A feature-poor
  port cannot crash in code it does not have. Coverage is collected
  (KCOV is on and syz-manager records it) and discarded. Fold coverage
  into the exposure denominator before quoting a fuzzing pass on a
  port with a smaller surface.
- **Events are buckets per campaign.** syzkaller deduplicates within a
  campaign; the harness sums buckets across campaigns, so a persistent
  bug counts once per campaign it is found in, and the binomial treats
  those as independent. Deduplicate by title across campaigns, or gate
  per campaign on "any target crash", before a many-campaign result is
  quoted.
- **One boot per driver, in sequence.** All C reps run in one guest
  session, all Rust reps in another, and a cached C baseline can be
  arbitrarily older than the campaign. Host drift is confounded with
  the driver, and consecutive reps in one session are not the
  independent draws the order-statistic interval assumes. The
  manifests record enough to check; alternating boots per rep block is
  the fix.
- **Hangs are noise.** "no output from test machine" and "lost
  connection" match the infrastructure signature anywhere in the
  report, which is also what a driver-induced hard lockup looks like.
  Both sides are treated the same, and the count is reported, but a
  driver that hangs the guest is invisible to the gate.
- **The thresholds are conventions.** 34.2% is Li et al.'s fleet
  average under their taxonomy, and our CWE encoding is more
  conservative than theirs on races, which carry most of that number;
  under our mapping the comparable fleet figure would be lower. 5% and
  a ratio of 2 have no derivation beyond convention and detectability.
  The block README says where each comes from.
- **The screening bands are a rubric.** The score cut-offs are v1's,
  `dynamic_robustness` scores 3 on one target crash regardless of
  exposure, and `tractability` scores how much of the harness has been
  run, so running more campaigns raises the band by construction.
  Bands are heuristic and say so.
- **"Implicit unsafe operations" counts pointer expressions, member
  accesses, casts and allocation calls.** It is not a count of
  anything Rust would mark `unsafe`, and 1,071 of them against 0
  `unsafe` blocks is two units side by side, not a ratio.
- **The safety gate never inspects the Rust driver.** Residual unsafe
  is reported (driver body against abstractions) but nothing gates on
  it; a port that is entirely `unsafe` passes the safety gate exactly
  as a port with none does.

## What the published numbers become

Under the instrument as it stands now, with the same data:

| gate        | published (v1) | re-read under v2                                                               |
| ----------- | -------------- | ------------------------------------------------------------------------------ |
| safety      | fail, 18.2%    | fail, 18.2% with 95% CI 2.3% to 51.8% on n=11; window 2020 to 2026             |
| fuzzing     | pass           | inconclusive: 1 event in 417 h (240 C, 177 Rust) bounds the ratio at 19, not 2 |
| performance | fail, all 18   | fail; measured on unmatched device configurations                              |
| overall     | fail           | fail ("performance and safety fail; fuzzing undecided")                        |

The verdict does not move. What moves is what the fuzzing gate is
allowed to say, and what the performance number is a measurement of.
