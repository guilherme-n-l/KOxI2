# Hardening the instrument

Notes from a coverage-driven pass over koxi before publication: how the
harness was exercised, what it turned up, and what is still open. The
point of the exercise is that a measurement instrument whose own
failures are silent cannot be trusted to report someone else's.

## How it was exercised

Source-based coverage (`nix develop .#coverage`), on two fronts:

- **Unit tests**, on aarch64-darwin and x86_64-linux. These reach the
  statistics, the gates and the CLI, and almost nothing that shells out.
- **The real pipeline**, on a 14-core x86_64 host with KVM, driving an
  instrumented binary through `koxi block setup` and then
  `koxi block all` against linux 6.19 — two kernel builds, busybox,
  dropbear, fio, syzkaller, initramfs, guest boots, fio runs, syzkaller
  campaigns, screening, all three gates and a verdict. This is the only
  way `kernel/`, `virt/`, `block/setup.rs` and `block/fio.rs` execute at
  all.

Plus three probes that are not coverage but found things anyway: a walk
of the whole command tree (every `--help`, then garbage arguments at
every leaf, checking for panics and silently accepted input); eight
concurrent cache sweeps against one shared home; and a `koxi clean` run
against a live kernel build to check the scratch-liveness lock.

Two results worth stating plainly: **no panics** across 20 commands and
48 garbage invocations, and the concurrency and liveness guarantees both
held — eight racing sweeps produced exactly one removal and seven clean
reads, and a sweep run mid-build correctly kept the running build's
scratch.

### What it reaches

**75% of regions, 79% of lines**, from a single instrumented binary driven
through the unit tests, three complete pipeline runs (linux 6.19 under gcc and
clang, linux 7.2 under clang), guest boots, and the whole command surface.

Getting one honest number took three attempts, and the failures are worth
recording because they are easy to repeat. Measuring the two fronts separately
(unit tests 63%, pipeline 70%) and reporting both is not the same claim, and the
merge that would have combined them OOM-killed the host three times. Two
mistakes of mine: the accumulated `.profraw` came from a binary the source had
since moved past, so the profiles no longer matched the coverage map; and the
memory guard was `ulimit -v`, which is _per process_, so `-j4` let four
instrumented rustc processes each sit under the cap and still exhaust 30 GB
together. A `systemd-run --user --scope -p MemoryMax=14G` cgroup around the
whole job is the guard that actually holds.

The pipeline is what makes the shell-out layer visible at all -- unit tests
alone leave `virt/`, `kernel/`, `block/setup.rs` and `block/fio.rs` at zero.
What still is not reached: `metal.rs` needs a second physical machine to kexec
into.

## Confirmed and fixed

Each has a commit and a regression test.

| #   | Defect                                                                              | Severity   |
| --- | ----------------------------------------------------------------------------------- | ---------- |
| 1   | syzkaller failed to build at all, so the fuzzing gate was unreachable               | high       |
| 2   | Kconfig could silently drop `CONFIG_RUST`, deleting the Rust half of the comparison | high       |
| 3   | `koxi clean --cache` wiped the whole shared cache when the project had no lock      | high       |
| 4   | `read_csv` counted blank lines as rows, inflating published row totals              | medium     |
| 5   | CWEs outside the ACSAC taxonomy silently counted as "unaffected"                    | medium     |
| 6   | A corrupt `screening.json` was read as an absent one                                | low-medium |
| 7   | `--fio-reps 1` benchmarks the whole matrix and compares nothing                     | low-medium |
| 8   | `koxi block test` carried a dead positional argument                                | low        |
| 9   | `--toolchain llvm` produced the right make line but no kernel                       | high       |
| 10  | `linux-meta` pulled 3.8 GB because the mirror ignores the clone filter              | medium     |
| 11  | Screening's bottom surface band ignored the unsafe-operation census                 | low-medium |
| 12  | Host tools linked against openssl got no RPATH under `LLVM=1`                       | medium     |

Number 2 is the one that mattered most. `make olddefconfig` drops a
symbol whose dependencies stopped holding, says nothing, and exits 0:

```
with-rust  make rc=0  CONFIG_RUST=y          CONFIG_RUST_OVERFLOW_CHECKS=y
no-rust    make rc=0  CONFIG_RUST=<DROPPED>  CONFIG_RUST_OVERFLOW_CHECKS=<DROPPED>
```

The fuzz fragment was asserted after olddefconfig, so the fuzzing
instrumentation was safe — but `CONFIG_RUST` lives in the base config,
which was never asserted, and the clean/perf flavor has no fragment at
all. Registry modules are harvested as optional, so a missing
`rnull_mod.ko` only warned, and the run failed two builds later with
nothing pointing at the config.

Number 9 took four attempts and is the clearest case of the pass paying for
itself: `--toolchain llvm` emitted a correct `make ... LLVM=1` line and built
nothing, because nixpkgs' clang wrapper injects `-nostdlibinc` and the kernel's
`-Werror` makes clang's "unused argument" complaint fatal. Most of the tree is
reachable through kbuild's five user-append variables; `arch/x86/realmode` and
the EFI stub rebuild `KBUILD_CFLAGS` from scratch and are reachable through
none of them, so they need a compiler that was never handed the flag. It now
builds and boots:

```
Linux version 6.19.0 (clang version 21.1.7, LLD 21.1.7) #1 SMP PREEMPT_DYNAMIC
brw-------  1 root  0  259, 0  /dev/rnullb0
1048576 bytes (1.0MB) copied, 0.000367 seconds, 2.7GB/s
```

That is a clang-and-LLD kernel running the _Rust_ driver, which is the pairing
most at risk: bindgen resolves libclang, and the kernel checks it against the C
compiler, so the two are pinned to one package set.

Number 1 is worth recording carefully because the obvious culprit was
wrong. syzkaller's build died in Makefile parsing with `relocation
target getgrgid_r not defined`. The first hypothesis — koxi's
`GLIBC_STATIC_LIB` on `NIX_LDFLAGS` — was tested and disproved: removing
it changed nothing. The actual chain:

| Test                                         | Result                       |
| -------------------------------------------- | ---------------------------- |
| syzkaller build in the dev shell             | FAIL                         |
| plain 8-line `os/user` program, same shell   | FAIL — no syzkaller involved |
| same go 1.26.7 + `/usr/bin/gcc`, outside nix | **OK**                       |
| in the shell, only `CC=/usr/bin/gcc` changed | **OK**                       |
| every `NIX_*` variable emptied               | still FAIL                   |

So the nixpkgs gcc wrapper breaks go's cgo external linking, and
syzkaller only tripped over it because its Makefile runs one `go run`
during parsing, above the line where it sets `CGO_ENABLED ?= 0`. koxi
now asks for what syzkaller already asks for. **This is not a syzkaller
bug and was not reported as one.**

## Added

`[build].toolchain` (`gnu` | `llvm`), because `LLVM=1` is not a value of
`--cc`: it swaps the assembler, linker and binutils as a set. Threaded
through every make invocation so configure and compile cannot disagree,
folded into the build fingerprint so a toolchain switch cannot reuse a
cached kernel, recorded in `artifacts/toolchain` so a results directory
says what built it, and checked by preflight. Verified on linux 6.19:
`make LLVM=1 olddefconfig` keeps `CONFIG_RUST`, `CONFIG_KASAN`,
`CONFIG_KCOV` and `CONFIG_BLK_DEV_NULL_BLK`.

The knob reads `KOXI_CC`, not `CC`. Adding clang to the dev shell makes
nixpkgs' cc-wrapper export `CC=clang`, which turned the _default gnu_
build into clang driving GNU binutils — silently, which is the exact
failure the toolchain selection exists to prevent.

## Open

- **`driver_spec` colon-joins unescaped fields.** It is the identity that
  content-addresses the results cache, so two registry entries differing only in
  where a `:` falls would share a baseline directory and pool their
  measurements. No real trigger known.
- **`koxi metal reset` reboots without confirming**, while `koxi metal boot`
  asks. Defensible -- reset is the recovery path -- but undocumented.
- **Upstream availability is a single point of failure.** busybox.net was
  unreachable mid-run (TLS reset) and setup failed 44 minutes in. Nothing was
  lost, since the kernels were already cached and the re-run resumed, but no
  source has a mirror or fallback. Moving `linux-meta` to a mirror that honours
  the clone filter fixed the size problem, not this one.

## Portability

### Linux 7.2

Pointing a fresh project at 7.2 and changing nothing else was the portability
test, and the tree passed the parts that matter to the registry: `null_blk/` and
`rnull/` are still where the registry says, both declared abstraction paths
(`rust/kernel/block.rs`, `rust/kernel/block/`) still exist, and the static
analysis ran unchanged -- 119 functions and 1,068 implicit unsafe operations for
null_blk against 53 functions and 54 unsafe sites for rnull.

The kernel build did not pass, and the reason is a real upstream change:

```
7.2:   depends on !KASAN || CC_IS_CLANG      <- new in 7.2
6.19:  depends on !KASAN_SW_TAGS
```

`CONFIG_RUST` in 7.2 refuses to coexist with KASAN unless the compiler is clang.
koxi's fuzz flavor sets `CONFIG_KASAN=y`, so under the default gnu toolchain the
7.2 fuzz kernel silently loses Rust support -- **on 7.2, a Rust driver can only
be fuzzed from a clang-built kernel.** The clean flavor is unaffected and built
`rnull_mod.ko` normally.

Two things fell out of this. The first is that the config assertion earned its
place on a tree it was not written against: it stopped the run at configure
time, named the symbol, and pointed at the toolchain, instead of building two
kernels and failing later with a missing module. The second is that the
toolchain selection is not a convenience -- on 7.2 it is the only way to fuzz
the Rust side at all, which is why that project's `koxi.toml` carries
`toolchain = "llvm"`.

Switching that project to the llvm toolchain exposed a second, unrelated
blocker: `certs/extract-cert` links against openssl and records no RPATH,
because under `LLVM=1` kbuild links host programs with `clang -fuse-ld=lld` and
that bypasses the nix `ld` wrapper which would otherwise add one. It links
clean and dies at runtime with `libcrypto.so.3: cannot open shared object
file`. 6.19 never hit it: its settled config does not build
`certs/x509_certificate_list`. Fixed by giving host links an explicit rpath.

With both addressed, **7.2 runs end to end** -- setup, static, perf, fuzzing,
screening, all three gates, verdict:

| gate        | 7.2 result                                                   |
| ----------- | ------------------------------------------------------------ |
| fuzzing     | pass (zero events both sides, reported as an exposure bound) |
| safety      | pass (elimination rate 40.0% against a 34.2% threshold)      |
| performance | fail                                                         |
| overall     | fail -- "safety and fuzzing pass but performance regresses"  |

**These are not publishable numbers.** The run used the `--quick` profile (one
workload, three reps, five-second fio runs) and 0.06 hours of fuzzing per side,
against a clang-built kernel. It demonstrates that the instrument produces a
complete, well-formed verdict on a kernel it was not built against; it says
nothing about how rnull performs on 7.2, and the -58.77% median delta should not
be quoted.

## Second pass: what the first one did not touch

The first pass drove the pipeline and walked the command tree. The
second went looking for surfaces neither of those reach: the integrity
checks a results tree is supposed to enforce, the crash classifier on
crashes (no real campaign had produced one), the registry entries
nobody had booted, interrupted runs, and knob values at the edge of
their domain. Forty-six scenarios on the reference host, scripted, no
kernel builds; then a verification run of every fix.

### Found and fixed

| #   | Defect                                                                                                      | Severity   |
| --- | ----------------------------------------------------------------------------------------------------------- | ---------- |
| 13  | `--alpha 1.5` and `--bootstrap-resamples 0` panicked inside the statistics; `--alpha 0` was accepted        | medium     |
| 14  | Negative thresholds were refused by clap as unknown flags, never by the range check                         | low        |
| 15  | A fio matrix typo (`--fio-bs 4x`, `--fio-rw randfoo`, `--fio-runtime 0`) booted a guest before failing      | low-medium |
| 16  | SIGTERM to koxi left the guest running on the ssh port; SIGKILL mid-fuzz left syz-manager and 4 guests      | medium     |
| 17  | A registry driver whose module was not built failed a whole `fuzz` run after every other campaign ran       | medium     |
| 18  | `zram` and `dm-zero` were registered but the shipped config built neither as a module                       | medium     |
| 19  | A tampered `koxi.lock` (artifact sha edited) measured and completed without a word                          | medium     |
| 20  | A compare that failed halfway left the previous run's `verdict.json` in place                               | low-medium |
| 21  | "Permission denied (os error 13)" named no file and no gate                                                 | low        |
| 22  | A workload with no usable reps reported a median delta of 0%, which reads as parity                         | low        |
| 23  | `koxi block all --p1` on a driver with no pair failed at the compare phase it should have skipped           | low-medium |
| 24  | The manifests' host tag was "unknown": `hostname` is not in the nix shell, so the substrate guard was blind | medium     |
| 25  | The two devices of the pair ran on different default geometries (see the methodology audit)                 | high       |

Number 16 is the kind of thing a scripted pass finds and a person at a
terminal never does, because Ctrl-C sends SIGINT to the whole
foreground group and the guest dies with koxi. A service manager, a
parent process or `kill` sends it to koxi alone, and a Rust binary
with no signal handler exits without running a single `Drop`. The fix
is not a handler: every guest and every syz-manager now asks the
kernel for `PR_SET_PDEATHSIG`, so it dies when koxi does, however koxi
died.

Number 17 was reported as `No such file or directory (os error 2)`
after a successful campaign, with no path. The identity of the next
subject hashes its module file, `zram.ko` did not exist, and the error
carried no context. That is also number 18: `CONFIG_ZRAM` was unset
and `CONFIG_DM_ZERO` built in, so two of the seven registry entries
could never have been booted. Both are modules now, and an unbuilt
module skips its driver with a warning instead of ending the run.

Number 18 had a second half. With both modules built, `koxi vm --driver
zram` still died in the guest: `zram: Unknown symbol zs_malloc`, eleven
times over, because zram's allocator is its own module (`zsmalloc.ko`)
and the registry loads exactly one. Building the allocator in does not
work either: kconfig caps a symbol's prompt at the visibility of what
selects it, so with `CONFIG_ZRAM=m` an explicit `CONFIG_ZSMALLOC=y`
comes back as `=m` from `olddefconfig`, silently, and a rebuild proved
it. The registry now carries `deps`, kernel-tree paths of modules a
driver needs first; they are harvested beside the driver's own module,
shipped in the overlay under `deps/` with an ordinal prefix, inserted
in order by the guest script, and folded into the driver's module
identity so a rebuilt allocator re-baselines the driver that runs on
it. With that, `koxi vm --driver zram` boots to `/dev/zram0` with a
2 GiB disk and `lsmod` showing zsmalloc held by zram.

Number 25 came from reading the queue limits back from the guest,
which the pass did for the 1 MiB question (`max_sectors_kb` is 127, so
a 1 MiB request is eight or nine): `nr_requests` was 64 on the C device
and 256 on the Rust one, and the scheduler was `none` against
`mq-deadline`. The methodology audit has the rest.

### Held

- Results trees are portable: a copied tree re-gates to the same
  verdict, in a path with spaces too, and the substrate guard refuses an
  edited host or acceleration tag.
- An incomplete domain and a missing baseline are both refused with
  the path that is wrong.
- The crash classifier does what the paper says: a driver frame in the
  call stack attributes, the driver's name in `Modules linked in:`
  alone does not, an infrastructure signature anywhere is noise, and an
  override CSV wins over the automatic verdict. Two things it did not
  do are in the audit: frames in the abstraction layer (fixed) and
  frames without a module tag, which only a built-in driver produces.
- Ctrl-C mid-perf leaves a resumable root: the reps in flight are
  recorded as failed, the next run fills them and marks the root
  complete.
- A knob change mints a new baseline instead of pooling: `--fio-engine
psync` beside `io_uring` gave a fifth perf root, not a wider one.
- `koxi new`, `koxi init` and `koxi assets dump` refuse to overwrite,
  and an override under `assets/` is reported as one.
- Two guests on the same forward port fail cleanly (qemu exits early);
  on distinct ports they run side by side.
- The other registry drivers boot: brd, loop and nbd come up with their
  device node, and the fuzz kernel boots rnull.
- Logs grow by about a megabyte per thirty-five runs and nothing sweeps
  them; `koxi clean` leaves `log/` alone by design.

## Third pass: the results tree as an adversary

The first two passes drove the pipeline and probed the command tree.
The third treated the results tree itself as untrusted input: every
file compare and screen read was corrupted, truncated, misfiled,
duplicated, backdated or replaced with a directory, one mutation per
scenario, and the question each time was whether the gate noticed.
The battery grew across four rounds to 257 scenarios, each in its own
project, home and results tree, synthetic throughout, no kernel builds
or guest boots. It ran on the Mac after every fix and on the reference
host at the end, 257 of 257 both places.

### Found and fixed

| #   | Defect                                                                                                                | Severity   |
| --- | --------------------------------------------------------------------------------------------------------------------- | ---------- |
| 26  | A workload cell whose every rep was invalid or warmup dropped out of the gate on both sides, and the rest passed      | medium     |
| 27  | A fio job that reported an I/O error still counted its partial IOPS as a sample                                       | medium     |
| 28  | The performance matrix was whatever directories survived, not what the manifest declared                              | medium     |
| 29  | A baseline directory was never checked against the identity hash it was named for                                     | medium     |
| 30  | An undecided gate beside a missing one read as `partial`, which is softer than `inconclusive`                         | low-medium |
| 31  | A truncated gate artifact read as a dimension never measured                                                          | low-medium |
| 32  | `--fuzz-rate-margin NaN` and `inf` passed the range check: neither is below 1                                         | low        |
| 33  | A `manifest.toml` that was a directory read as a domain never run                                                     | low-medium |
| 34  | A completion marker holding `inf` was a valid duration and panicked inside statrs' beta function                      | medium     |
| 35  | A campaign with no marker and no crashes counted as zero crashes over its budgeted hours; a Rust side of them passed  | high       |
| 36  | One substrate for the verdict: a TCG fuzz campaign beside a KVM perf run travelled as `measured`                      | medium     |
| 37  | A campaign directory with no usable domain still got an all-unavailable `verdict.json` before compare failed          | low-medium |
| 38  | The same-substrate guard compared host and accel only; 8 vCPUs and psync gated against 4 and io_uring                 | medium     |
| 39  | A completion marker that could not be read was neither completed nor dead, so the campaign was guessed dead           | low-medium |
| 40  | The plan was a floor: an undeclared cell, thirty extra reps, four of eleven, five campaigns for a plan of two         | medium     |
| 41  | A `--validated-crashes` row naming a crash not on disk did nothing, silently                                          | low        |
| 42  | A driver with no CWE-classified commit was gated at 0 of 0 = 0% and failed safety                                     | medium     |
| 43  | A missing static table or a renamed column read as an empty table; `safety_related = yes` was neither true nor false  | medium     |
| 44  | The `[p2]` record was read for its hash only: another campaign's name, a non-hash baseline, a phase-2 manifest as p1  | medium     |
| 45  | A manifest read from disk was trusted as written: an empty matrix declared zero workloads and nothing to fail         | medium     |
| 46  | `--campaign ../x` wrote outside the results tree; `trial/../trial` was `trial` under another name                     | medium     |
| 47  | `qd = [32, 32]` produced two cells that shared a directory and counted twice                                          | low        |
| 48  | The adjudication CSV was split on commas by position: a quoted export failed, a comma in notes shifted the columns    | low-medium |
| 49  | Screening scored historical risk from `commits_summary.csv`; absent, it scored 0 with ten safety commits in the table | medium     |
| 50  | Screening took any complete manifest under a domain root: fuzz data under `static/`, another driver, a p2 manifest    | medium     |
| 51  | A failed screening left the previous `screening.json`, and compare folded it into the verdict                         | low-medium |
| 52  | Tractability counted directories: eight dead campaigns beside two real ones made a ten-campaign baseline              | medium     |
| 53  | compare and screen wrote the results tree with no lock; two at once raced on the stale-artifact removal               | medium     |

Number 35 is the defect the methodology audit found in the published
dataset, reproduced by the instrument that was meant to catch it: the
two campaigns that never started were two clean campaigns to v1, and
to v2 until this pass. A campaign that neither completed nor crashed
is now dropped from the gate and named in `campaigns_excluded`; a side
left with none is `inconclusive`. Number 52 is the same defect on the
screening side.

Numbers 38, 40, 44, 45 and 50 are one rule stated five times: the
manifest is the record, and the data on disk must be exactly what it
describes. Every identity field that is not the driver must agree
between the two sides; the matrix, the rep count and the campaign
count are bounds, not floors; the campaign record must name this
campaign and a real hash; the plan must be one the gates can run; and
what sits under a phase-1 domain root must be that driver's, that
domain's, under its own hash. Before this pass, the manifest declared
and the gate believed whatever it found.

Number 53 was found by running eight compares against one campaign at
once. Each removed the stale gate artifacts first, so one could delete
`perf_stats.json` between another's write and its verdict, and that
verdict read the gap as a dimension never measured. compare and screen
now hold an advisory lock at `results/.gate-lock`; both also write
`crash_classification.json` into the same phase-1 campaign
directories, which the lock covers too.

One shape change: `verdict.json` records `substrate` per domain
(`substrate.fuzz`, `substrate.perf`) rather than once, because the two
campaigns are separate runs and one may have fallen back to TCG.

Also fixed on the way: two tests in `block::cli` read the environment
without the env lock and failed about once in twenty runs beside a
sibling that pins `FIO_REPS=1`.

### Held

- A device geometry recorded on one side only is `matched: null` and
  stays `measured`: a v1 import beside a v2 campaign is unknown, not
  mismatched. Left as is; the flag is in the artifact.
- `--logfile` to a path that cannot be opened degrades to console with
  a warning rather than failing the run, as `logging.rs` says.
- `assets list` and `clean` work outside a project (the embedded set,
  the scratch sweep); the cache and artifact scopes still refuse.
- A byte-order mark on a manifest is not corruption; the TOML reader
  strips it.
- `--only` names the C driver, v1-style; `--only rnull` selects
  nothing and says so.
- Symlink loops under `crashes/`, binary crash reports, zero-variance
  and extreme IOPS, a 30% regression, a Rust side crashing 24 to 0,
  stray files under `campaigns/`, unicode and 200-character campaign
  names, CRLF manifests, unknown manifest keys, a symlinked results
  root, a read-only results tree, eight concurrent screens: all held
  without a change.

## Backlog

### A clang-built comparison

The clang kernel now builds and boots, so what is left is the measurement, not
the plumbing. If perf numbers move between the gcc and clang kernels, the
toolchain belongs in the _results_ identity rather than only in the build
fingerprint: today it is recorded as provenance in `artifacts/toolchain`, which
documents a baseline but does not by itself stop two toolchains' measurements
landing in one. In practice the artifact shas differ and separate them; the
point is that nothing states the rule.
