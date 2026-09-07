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

## Backlog

### A clang-built comparison

The clang kernel now builds and boots, so what is left is the measurement, not
the plumbing. If perf numbers move between the gcc and clang kernels, the
toolchain belongs in the _results_ identity rather than only in the build
fingerprint: today it is recorded as provenance in `artifacts/toolchain`, which
documents a baseline but does not by itself stop two toolchains' measurements
landing in one. In practice the artifact shas differ and separate them; the
point is that nothing states the rule.
