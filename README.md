# KOxI v2

**KOxI** (Kernel Oxidation Instrument) is a methodology and harness for
deciding whether migrating a Linux kernel driver from C to Rust is
supported by evidence. This repository is the Rust rewrite of the
[original shell/Python harness](https://github.com/guilherme-n-l/KOxI);
see that repo's README for the methodology (evidence lenses, verdict
gates, project flow).

`koxi` is an orchestrator binary: it shells out to host tools (gcc,
make, qemu, git, syzkaller's toolchain, …) to fetch and build its
subjects, then drives qemu guests to run fuzzing and benchmarks. The
current instantiation is the block-device harness (`koxi block …`),
with `null_blk` (C) vs `rnull` (Rust) as the Phase-2 pair.

## Quick start

```sh
# runtime shell: koxi + every tool the pipeline shells out to, pinned
nix develop .#koxi

koxi block test    # preflight: tools, toolchain sanity, headers
koxi block setup   # fetch + verify all sources, build the kernel
```

Real campaigns need an x86_64 Linux host (ideally with /dev/kvm).
Development works anywhere nix does; `nix develop` (default shell)
adds the rust toolchain, LSPs, and git hooks.

## The model

- **`koxi.toml`** — per-project declaration (found by walking up from
  the cwd, cargo-style): third-party sources (tarball / `git` /
  `git-meta` history mirrors, all pinned), the `[build]` toolchain
  (`cc`, `target`), asset overrides, and the block driver registry.
- **`koxi.lock`** — machine-written resolved state: tarball sha256s,
  git commits, asset hashes, and build fingerprints (recipe + source
  sha + config sha + toolchain identity). Committed like `Cargo.lock`;
  builds are skipped only on a fingerprint match.
- **`assets/`** — build inputs (kconfigs, patches, the VM init
  script). Defaults are embedded in the binary; a file under
  `assets/<name>` overrides them, and `[assets]` in `koxi.toml` can
  point elsewhere. `koxi assets dump` materializes defaults for
  editing.
- **`artifacts/`** — per-project build outputs: `bzImage` plus the
  registry drivers' kernel modules and any `[build].extra-artifacts`
  (e.g. `vmlinux` for syzkaller symbolization), each sha256-locked
  under the lock's `[artifacts]` table. `koxi block clean` removes
  them.
- **`$KOXI_HOME`** (default `~/.koxi`) — shared across projects:
  `cache/` (tarballs, source trees, git mirrors; `--nocache` clears
  it), `tmp/` (mktemp-style build scratch, kept on failure for
  debugging), `log/<project>/<run-id>/` (run log + per-task subprocess
  logs).

Builds are deterministic by construction: every build re-extracts a
pristine tree into scratch, applies the config asset, and records its
input fingerprint in the lock.

## Known limitations

- Concurrent runs sharing `$KOXI_HOME` have no cache locking (scratch
  dirs are collision-safe; the cache is not).
- A killed build (SIGKILL / power loss) can orphan `tmp/` entries;
  `koxi clean` (or `--nocache`) sweeps them. Don't run either
  concurrently with a build — scratch dirs carry no liveness marker.
- The cache never garbage-collects superseded versions.
- The lock format is strict (`deny_unknown_fields`, `version = 1`):
  older binaries hard-fail on newer locks. Bump the version whenever a
  lock table changes shape.
- Env-set flags count as "present" for clap conflict checks
  (`QUICK=1` + `--longrun` errors), and an invalid env value errors
  even when a CLI flag overrides it at the subcommand level.
- The nixbox used for pipeline validation has no `/dev/kvm` and
  3.7 GiB RAM: fine for builds and smoke tests, not for real fuzz or
  perf campaigns.
