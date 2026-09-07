//! `koxi block` CLI surface: one option group per concern, and each
//! subcommand declares exactly the groups it reads.
//!
//! v1's broker took every flag on every verb, so `block test` offered
//! fuzz campaign knobs and `block screen` offered VM geometry. Here a
//! group is a struct with `args()` + `from_matches()` over the
//! `crate::cli` env layer, so the help of a branch is the truth about
//! what that branch consumes, env vars keep their v1 names (with the
//! CLI beating env beating default), and an invalid env value errors
//! only when the running subcommand actually resolves that group.

use std::path::PathBuf;

use clap::{Arg, ArgMatches, Command};

use crate::cli::{exclusive, flag_value, knobs, source, value, Error, GuestOpts, Source, VmOpts};
use crate::config::{BuildConfig, Toolchain};

const SELECTION: &str = "Selection";
const PHASE: &str = "Phase";
const PROFILE: &str = "Profiles";
const BUILD: &str = "Build";
const FIO: &str = "Fio knobs";
const FUZZING: &str = "Fuzzing";
const STATIC: &str = "Static analysis";
const SCREENING: &str = "Screening";
const COMPARE: &str = "Compare";

/// Toolchain first, then the compiler within it: the CLI/env knob,
/// then koxi.toml's [build] table, then the toolchain's own compiler.
fn resolve_toolchain(
    toolchain: Option<Toolchain>,
    cc: Option<String>,
    build: Option<&BuildConfig>,
) -> (Toolchain, String) {
    let toolchain = toolchain
        .or_else(|| build.and_then(|build| build.toolchain))
        .unwrap_or_default();
    let cc = cc
        .or_else(|| build.and_then(|build| build.cc.clone()))
        .or_else(|| toolchain.env_cc())
        .unwrap_or_else(|| toolchain.default_cc().to_owned());
    (toolchain, cc)
}

/// The `koxi block` subcommand tree, mirroring v1 `block/run`.
pub fn command() -> Command {
    Command::new("block")
        .about("Block-device-driver harness")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("setup")
                .about("Only setup the environment")
                .args(BuildOpts::args()),
        )
        .subcommand(
            Command::new("test")
                .about("Verify system deps, user config, and setup state")
                .arg(BuildOpts::arg("toolchain"))
                .arg(BuildOpts::arg("cc")),
        )
        .subcommand(
            Command::new("perf")
                .about("Run performance benchmarks")
                .args(union([
                    RunOpts::args(),
                    Profile::args(),
                    VmOpts::args(),
                    FioOpts::args(),
                ])),
        )
        .subcommand(
            Command::new("fuzz")
                .about("Run fuzzing campaigns")
                .args(union([
                    RunOpts::args(),
                    Profile::args(),
                    GuestOpts::args(),
                    FuzzOpts::args(),
                ])),
        )
        .subcommand(
            Command::new("static")
                .about("Static analysis (loc, ast, commits)")
                .args(union([RunOpts::args(), StaticOpts::args()])),
        )
        .subcommand(
            Command::new("screen")
                .about("Synthesize cached Phase 1 screening artifacts")
                .args(union([Scope::args(), ScreenOpts::args()])),
        )
        .subcommand(
            Command::new("compare")
                .about("Phase 2 only: diff p1 vs p2 data")
                .args(union([
                    Scope::args(),
                    vec![campaign_arg()],
                    CompareOpts::args(),
                ])),
        )
        .subcommand(
            Command::new("all")
                .about("static + perf + fuzz + screen + compare (phase-aware)")
                .args(union([
                    RunOpts::args(),
                    Profile::args(),
                    VmOpts::args(),
                    FioOpts::args(),
                    GuestOpts::args(),
                    FuzzOpts::args(),
                    StaticOpts::args(),
                    CompareOpts::args(),
                ])),
        )
}

/// The union of several groups, deduped by arg id: `all` declares
/// every group, and a few knobs (--seed, the guest geometry, the
/// crash overrides) legitimately belong to more than one.
fn union<const N: usize>(groups: [Vec<Arg>; N]) -> Vec<Arg> {
    let mut seen = std::collections::BTreeSet::new();
    let mut args = Vec::new();
    for arg in groups.into_iter().flatten() {
        if seen.insert(arg.get_id().to_string()) {
            args.push(arg);
        }
    }
    args
}

knobs! {
    /// Which driver pairs a phase touches, and where its data lands.
    #[derive(Debug, Clone)]
    pub struct Scope(SELECTION) {
        /// Filter by C driver name; Rust pair follows from drivers.cfg.
        list only: String = "only" / "ONLY_DRIVERS", "name[:name]", split ':'
            => { .action(clap::ArgAction::Append) };
        /// Results root dir.
        req output: PathBuf = "output" / "RESULTS_ROOT", "dir", default "results";
    }
}

knobs! {
    /// Which phase of the study runs, over which drivers, into where.
    #[derive(Debug, Clone)]
    pub struct RunOpts(PHASE) {
        /// Phase 1 only (C baseline). Default: full run (p1 + p2).
        flag p1 = "p1" / "PHASE1_ONLY";
        /// P2 campaign name (default: unix timestamp).
        opt campaign: String = "campaign" / "CAMPAIGN", "name";
        /// Re-run baseline even if cached.
        flag force_p1 = "force-p1" / "FORCE_P1";
        /// Which drivers this phase covers and where its data lands.
        group scope: Scope;
    }
}

impl RunOpts {
    /// The campaign this run writes under: the name the user gave,
    /// else the run's own timestamp — the same `now` the manifests
    /// record, so the campaign dir and its data agree.
    pub fn campaign(&self, now: u64) -> String {
        self.campaign.clone().unwrap_or_else(|| now.to_string())
    }
}

/// The campaign name a comparison needs; unlike the measuring
/// phases, compare cannot invent one.
pub fn require_campaign(matches: &ArgMatches) -> Result<String, Error> {
    value::<String>(matches, "campaign", "CAMPAIGN")?.ok_or(Error::Missing {
        arg: "campaign",
        env: "CAMPAIGN",
    })
}

/// The `--campaign` arg on its own, for `compare` (which takes the
/// name but none of the rest of a phase's scope).
pub fn campaign_arg() -> Arg {
    RunOpts::arg("campaign")
}

knobs! {
    /// Workload size presets, plus the escape hatch for the host gate.
    #[derive(Debug, Clone, Copy)]
    pub struct Profile(PROFILE) custom {
        /// Fast defaults for dev/CI.
        flag quick = "quick" / "QUICK";
        /// Long-run defaults: 30 campaigns of 24h, 50 fio reps. Not
        /// the published dataset's plan, which was 10 campaigns of
        /// 24h; pass --fuzz-campaigns 10 to reproduce that.
        flag longrun = "longrun" / "LONGRUN";
        /// Run even on a host without KVM or memory for the guests
        /// (the numbers are then the user's problem, not data).
        flag allow_unfit_host = "allow-unfit-host" / "ALLOW_UNFIT_HOST";
    }
}

impl Profile {
    /// Hand-written because the two presets exclude each other, and
    /// the check has to see through the env layer: `QUICK=1` in the
    /// environment must lose to an explicit `--longrun` rather than
    /// error, which is what clap's own `conflicts_with` did.
    pub fn from_matches(matches: &ArgMatches) -> Result<Self, Error> {
        let (quick, longrun) = exclusive(matches, ("quick", "QUICK"), ("longrun", "LONGRUN"))?;
        Ok(Self {
            quick,
            longrun,
            allow_unfit_host: flag_value(matches, "allow-unfit-host", "ALLOW_UNFIT_HOST"),
        })
    }
}

knobs! {
    /// What `koxi block setup` builds and how.
    #[derive(Debug, Clone)]
    pub struct BuildOpts(BUILD) {
        /// Kernel build toolchain: gnu (gcc + GNU binutils) or llvm
        /// (clang + LLVM binutils, kbuild's LLVM=1). Default:
        /// koxi.toml [build].toolchain, else gnu.
        opt toolchain: Toolchain = "toolchain" / "KOXI_TOOLCHAIN", "gnu|llvm";
        /// C compiler for the kernel build, overriding the toolchain's
        /// own default (gcc for gnu, clang for llvm) -- e.g. clang-21.
        /// Default: koxi.toml [build].cc. Reads KOXI_CC, not CC: build
        /// environments set CC for their own reasons (a nix shell with
        /// clang in it exports CC=clang), and that would silently
        /// override the toolchain the project declared.
        opt cc: String = "cc" / "KOXI_CC", "compiler";
        /// Force kernel rebuild (also nukes the extracted tree).
        flag force_build = "force-build" / "FORCE_BUILD";
        /// Run `make menuconfig`, persist .config, force rebuild.
        flag menuconfig = "menuconfig" / "MENUCONFIG";
        /// Skip kernel build (initramfs still rebuilt).
        flag skip_build = "skip-build" / "SKIP_BUILD";
        /// Clear the KOXI_HOME download cache before running.
        flag nocache = "nocache" / "NOCACHE";
    }
}

impl BuildOpts {
    /// The compiler with no project config to consult (`block test`,
    /// which probes the toolchain and builds nothing).
    /// The toolchain and the C compiler for a kernel build: the
    /// CLI/env knob first, then koxi.toml's [build] table, then the
    /// toolchain's own compiler. Resolved together because `cc` is an
    /// override *within* a toolchain -- `LLVM=1` swaps the assembler,
    /// linker and binutils as a set, so it can never be a cc value.
    pub fn toolchain_and_cc(&self, build: Option<&BuildConfig>) -> (Toolchain, String) {
        resolve_toolchain(self.toolchain, self.cc.clone(), build)
    }

    /// The same resolution for a subcommand that declares only these
    /// two knobs instead of the whole build group -- `block test`
    /// takes no --force-build, so it cannot be read as a BuildOpts.
    pub fn toolchain_probe(
        matches: &ArgMatches,
        build: Option<&BuildConfig>,
    ) -> Result<(Toolchain, String), Error> {
        Ok(resolve_toolchain(
            value(matches, "toolchain", "KOXI_TOOLCHAIN")?,
            value(matches, "cc", "KOXI_CC")?,
            build,
        ))
    }
}

knobs! {
    /// The fio workload matrix.
    #[derive(Debug, Clone)]
    pub struct FioOpts(FIO) {
        /// Block sizes.
        list bs: String = "fio-bs" / "FIO_BSIZES", "sizes", split ' ',
            default ["4k", "64k", "1M"];
        /// I/O patterns.
        list rw: String = "fio-rw" / "FIO_RWS", "patterns", split ' ',
            default ["randread", "randwrite"];
        /// Queue depths.
        list qd: u32 = "fio-qd" / "FIO_QDS", "depths", split ' ',
            default ["1", "32", "256"];
        /// File sizes.
        list sz: String = "fio-sz" / "FIO_SIZES", "sizes", split ' ', default ["512M"];
        /// Repetitions per config.
        req reps: u32 = "fio-reps" / "FIO_REPS", "n", default "30";
        /// Seconds per fio run.
        req runtime: u64 = "fio-runtime" / "FIO_RUNTIME", "s", default "30";
        /// fio ioengine (io_uring makes the qd axis real; psync = v1 parity).
        req engine: String = "fio-engine" / "FIO_ENGINE", "engine", default "io_uring";
        /// Deterministic workload shuffle seed (default: unix time).
        opt seed: u64 = "seed" / "WORKLOAD_SEED", "n";
    }
}

impl FioOpts {
    /// Profile defaults fill only knobs the user pinned nowhere (v1
    /// `_set_quick` / `_set_longrun`).
    pub fn with_profile(matches: &ArgMatches, profile: Profile) -> Result<Self, Error> {
        let mut opts = Self::from_matches(matches)?;
        if profile.quick {
            if unset(matches, "fio-bs", "FIO_BSIZES") {
                opts.bs = vec!["4k".to_owned()];
            }
            if unset(matches, "fio-rw", "FIO_RWS") {
                opts.rw = vec!["randread".to_owned()];
            }
            if unset(matches, "fio-qd", "FIO_QDS") {
                opts.qd = vec![1];
            }
            if unset(matches, "fio-reps", "FIO_REPS") {
                opts.reps = 3;
            }
            if unset(matches, "fio-runtime", "FIO_RUNTIME") {
                opts.runtime = 5;
            }
        } else if profile.longrun && unset(matches, "fio-reps", "FIO_REPS") {
            opts.reps = 50;
        }
        // Rep 1 of every workload is annotated as a warmup and the
        // comparator drops warmups, so a single rep benchmarks for as
        // long as the matrix takes and then yields nothing to compare.
        // Checked here rather than with a clap value_parser because
        // the env fallback is this crate's own layer and never reaches
        // clap's parser (see cli::opt, which does not call .env()).
        if opts.reps < 2 {
            return Err(Error::Invalid {
                env: "FIO_REPS",
                arg: "fio-reps",
                value: opts.reps.to_string(),
                why: "needs at least 2: rep 1 of every workload is a warmup and \
                      warmups are excluded from the comparison, so one rep \
                      benchmarks the whole matrix and compares nothing"
                    .to_owned(),
            });
        }
        Ok(opts)
    }
}

knobs! {
    /// Syzkaller campaign plan and toolchain locations.
    #[derive(Debug, Clone)]
    pub struct FuzzOpts(FUZZING) {
        /// Independent campaigns.
        req campaigns: u32 = "fuzz-campaigns" / "FUZZ_CAMPAIGNS", "n", default "30";
        /// Hours per campaign.
        req hours: f64 = "fuzz-hours" / "FUZZ_CAMPAIGN_HOURS", "h", default "1";
        /// Parallel campaigns.
        req parallel: u32 = "fuzz-parallel" / "FUZZ_PARALLEL", "n", default "4";
        /// Base syz-manager config (JSON; machine-owned fields are overlaid).
        opt syz_cfg: PathBuf = "syz-cfg" / "CFG_TEMPLATE", "path";
        /// Syzkaller root dir.
        opt syz_root: PathBuf = "syz-root" / "SYZ_ROOT", "path";
        /// syz-manager binary.
        opt syz_manager: PathBuf = "syz-manager" / "SYZ_MANAGER", "path";
        /// syz-manager HTTP port (0 = random).
        req syz_http_port: u16 = "syz-http-port" / "SYZ_HTTP_PORT", "port", default "0";
    }
}

impl FuzzOpts {
    /// As [`FioOpts::with_profile`]: presets fill only what nothing
    /// else pinned.
    pub fn with_profile(matches: &ArgMatches, profile: Profile) -> Result<Self, Error> {
        let mut opts = Self::from_matches(matches)?;
        let (campaigns, hours) = if profile.quick {
            (1, 0.01)
        } else if profile.longrun {
            (30, 24.0)
        } else {
            return Ok(opts);
        };
        if unset(matches, "fuzz-campaigns", "FUZZ_CAMPAIGNS") {
            opts.campaigns = campaigns;
        }
        if unset(matches, "fuzz-hours", "FUZZ_CAMPAIGN_HOURS") {
            opts.hours = hours;
        }
        Ok(opts)
    }
}

knobs! {
    /// Static-analysis-only knobs.
    #[derive(Debug, Clone)]
    pub struct StaticOpts(STATIC) {
        /// Optional commit CWE override CSV.
        opt validated_cwe: PathBuf = "validated-cwe" / "VALIDATED_CWE", "csv";
    }
}

knobs! {
    /// Manual crash adjudication, shared by screening and the fuzz gate.
    #[derive(Debug, Clone)]
    pub struct ScreenOpts(SCREENING) {
        /// Optional crash classification override CSV.
        opt validated_crashes: PathBuf = "validated-crashes" / "VALIDATED_CRASHES", "csv";
    }
}

knobs! {
    /// The gate thresholds and the statistics they are tested at.
    #[derive(Debug, Clone)]
    pub struct CompareOpts(COMPARE) {
        /// Statistical significance threshold.
        req alpha: f64 = "alpha" / "ALPHA", "x", default "0.05";
        /// Max allowed overhead %.
        req perf_threshold: f64 = "perf-threshold" / "PERF_THRESHOLD", "pct", default "5";
        /// Bootstrap resamples for performance CIs.
        req bootstrap_resamples: u64 = "bootstrap-resamples" / "BOOTSTRAP_RESAMPLES", "n",
            default "10000";
        /// Non-inferiority margin on the rs/c attributable crash rate ratio.
        req fuzz_rate_margin: f64 = "fuzz-rate-margin" / "FUZZ_RATE_MARGIN", "x", default "2";
        /// Elimination rate threshold.
        req safety_threshold: f64 = "safety-threshold" / "SAFETY_THRESHOLD", "pct",
            default "34.2";
        /// Deterministic workload shuffle seed (default: unix time).
        opt seed: u64 = "seed" / "WORKLOAD_SEED", "n";
        /// Manual crash adjudication the fuzz gate honors.
        group screen: ScreenOpts;
    }
}

/// Whether a knob is still at its compiled-in default — the only
/// place a profile is allowed to write.
fn unset(matches: &ArgMatches, id: &str, env: &str) -> bool {
    source(matches, id, env) == Source::Default
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::with_env;

    /// Parse `koxi block <args>` with the root globals in place,
    /// yielding the leaf subcommand's matches.
    fn parse(args: &[&str]) -> ArgMatches {
        let root = clap::Command::new("koxi")
            .arg(crate::cli::yes_arg())
            .subcommand(super::command());
        let matches = root.get_matches_from([&["koxi", "block"], args].concat());
        let (_, block) = matches.subcommand().expect("block");
        let (_, sub) = block.subcommand().expect("leaf");
        sub.clone()
    }

    fn try_parse(args: &[&str]) -> Result<ArgMatches, clap::Error> {
        let root = clap::Command::new("koxi")
            .arg(crate::cli::yes_arg())
            .subcommand(super::command());
        root.try_get_matches_from([&["koxi", "block"], args].concat())
    }

    fn fio(args: &[&str]) -> FioOpts {
        let matches = parse(args);
        let profile = Profile::from_matches(&matches).expect("profile");
        FioOpts::with_profile(&matches, profile).expect("fio")
    }

    fn fuzz(args: &[&str]) -> FuzzOpts {
        let matches = parse(args);
        let profile = Profile::from_matches(&matches).expect("profile");
        FuzzOpts::with_profile(&matches, profile).expect("fuzz")
    }

    #[test]
    fn cli_is_well_formed() {
        super::command().debug_assert();
    }

    #[test]
    fn each_subcommand_takes_only_its_own_groups() {
        assert!(
            try_parse(&["test", "--fio-reps", "3"]).is_err(),
            "block test has no fio matrix"
        );
        assert!(
            try_parse(&["test", "kernel"]).is_err(),
            "block test takes no positional: a stray word must not be swallowed"
        );
        assert!(
            try_parse(&["screen", "--smp", "8"]).is_err(),
            "block screen boots no guest"
        );
        assert!(
            try_parse(&["perf", "--fuzz-hours", "2"]).is_err(),
            "block perf runs no campaigns"
        );
        assert_eq!(fio(&["perf", "--fio-reps", "3"]).reps, 3);
        assert_eq!(fuzz(&["fuzz", "--fuzz-hours", "2"]).hours, 2.0);
        assert!(try_parse(&["all", "--fio-reps", "3", "--fuzz-hours", "2"]).is_ok());
    }

    #[test]
    fn quick_and_longrun_fill_unset_knobs() {
        with_env(&[], || {
            let opts = fio(&["perf", "--quick"]);
            assert_eq!(opts.reps, 3);
            assert_eq!(opts.qd, vec![1]);
            assert_eq!(fuzz(&["fuzz", "--quick"]).hours, 0.01);

            assert_eq!(
                fio(&["perf", "--quick", "--fio-reps", "10"]).reps,
                10,
                "explicit flag beats the profile"
            );

            assert_eq!(fuzz(&["fuzz", "--longrun"]).hours, 24.0);
            assert_eq!(fio(&["perf", "--longrun"]).reps, 50);
        });
    }

    /// Rep 1 of every workload is annotated as a warmup and the
    /// comparator drops warmups, so a single rep runs the whole matrix
    /// and leaves nothing to compare. Rejected up front rather than
    /// discovered after the benchmark.
    #[test]
    fn one_fio_rep_is_all_warmup_and_is_refused() {
        let one_rep = |args: &[&str]| {
            let matches = parse(args);
            let profile = Profile::from_matches(&matches).expect("profile");
            FioOpts::with_profile(&matches, profile)
        };
        assert!(one_rep(&["perf", "--fio-reps", "1"]).is_err());
        assert!(one_rep(&["perf", "--fio-reps", "2"]).is_ok());
        // The env fallback is this crate's own layer, so it has to be
        // caught by the same check rather than by clap.
        with_env(&[("FIO_REPS", "1")], || {
            assert!(one_rep(&["perf"]).is_err(), "env path is guarded too");
        });
    }

    #[test]
    fn env_pinned_knobs_survive_a_profile() {
        with_env(&[("FIO_REPS", "7"), ("FUZZ_CAMPAIGN_HOURS", "3")], || {
            let opts = fio(&["perf", "--quick"]);
            assert_eq!(opts.reps, 7, "env counts as pinned");
            assert_eq!(opts.runtime, 5, "unpinned knobs still take the profile");
            assert_eq!(fuzz(&["fuzz", "--longrun"]).hours, 3.0);
        });
    }

    #[test]
    fn quick_and_longrun_are_exclusive() {
        with_env(&[], || {
            let matches = parse(&["perf", "--quick", "--longrun"]);
            assert!(matches!(
                Profile::from_matches(&matches),
                Err(Error::Conflict { .. })
            ));
        });
        with_env(&[("QUICK", "1")], || {
            let matches = parse(&["perf", "--longrun"]);
            let profile = Profile::from_matches(&matches).expect("cli beats env");
            assert!(profile.longrun && !profile.quick);
        });
    }

    #[test]
    fn compare_demands_a_campaign_from_cli_or_env() {
        with_env(&[], || {
            assert!(matches!(
                require_campaign(&parse(&["compare"])),
                Err(Error::Missing {
                    arg: "campaign",
                    ..
                })
            ));
            assert_eq!(
                require_campaign(&parse(&["compare", "--campaign", "trial"])).unwrap(),
                "trial"
            );
        });
        with_env(&[("CAMPAIGN", "from-env")], || {
            assert_eq!(require_campaign(&parse(&["compare"])).unwrap(), "from-env");
        });
    }

    #[test]
    fn groups_build_from_defaults() {
        with_env(&[], || {
            let matches = parse(&["perf"]);
            let vm = VmOpts::from_matches(&matches).unwrap();
            assert_eq!(vm.guest.smp, 4);
            assert_eq!(vm.port, 5555);
            assert_eq!(fio(&["perf"]).qd, vec![1, 32, 256]);
            let run = RunOpts::from_matches(&matches).unwrap();
            assert_eq!(run.scope.output, PathBuf::from("results"));
            assert!(!run.p1 && run.campaign.is_none());
        });
    }

    /// CC is ambient on many hosts (nix sets it), so --cc is left
    /// unresolved rather than defaulted here: koxi.toml gets a say
    /// only when neither the flag nor the environment named one.
    #[test]
    fn cc_comes_from_the_cli_then_the_environment() {
        with_env(&[("KOXI_CC", "clang")], || {
            assert_eq!(
                BuildOpts::from_matches(&parse(&["setup"]))
                    .unwrap()
                    .cc
                    .as_deref(),
                Some("clang")
            );
            assert_eq!(
                BuildOpts::toolchain_probe(&parse(&["test", "--cc", "gcc-13"]), None)
                    .unwrap()
                    .1,
                "gcc-13"
            );
        });
    }

    /// `LLVM=1` swaps the assembler, the linker and the binutils as a
    /// set, so it is a toolchain and never a value of `cc`; `cc` only
    /// narrows which compiler within the toolchain.
    #[test]
    fn the_toolchain_picks_the_compiler_and_cc_narrows_it() {
        let opts = |args: &[&str]| BuildOpts::from_matches(&parse(args)).unwrap();
        let bare: Option<&BuildConfig> = None;

        // Under the env guard even though it sets nothing: resolution
        // consults KOXI_*_CC, and cargo runs tests on parallel threads,
        // so asserting a *default* outside the lock can observe a value
        // another test is holding.
        with_env(&[], || {
            assert_eq!(
                opts(&["setup"]).toolchain_and_cc(bare),
                (Toolchain::Gnu, "gcc".to_owned()),
                "gnu is the default and brings gcc with it"
            );
            assert_eq!(
                opts(&["setup", "--toolchain", "llvm"]).toolchain_and_cc(bare),
                (Toolchain::Llvm, "clang".to_owned()),
                "llvm brings clang without anyone naming it"
            );
            assert_eq!(
                opts(&["setup", "--toolchain", "llvm", "--cc", "clang-21"]).toolchain_and_cc(bare),
                (Toolchain::Llvm, "clang-21".to_owned()),
                "cc narrows within the toolchain"
            );
        });

        // koxi.toml supplies both, and the flag beats the file.
        let declared = BuildConfig {
            toolchain: Some(Toolchain::Llvm),
            cc: Some("clang-20".to_owned()),
            ..BuildConfig::default()
        };
        with_env(&[], || {
            assert_eq!(
                opts(&["setup"]).toolchain_and_cc(Some(&declared)),
                (Toolchain::Llvm, "clang-20".to_owned())
            );
            assert_eq!(
                opts(&["setup", "--toolchain", "gnu"])
                    .toolchain_and_cc(Some(&declared))
                    .0,
                Toolchain::Gnu,
                "the flag overrides the project's declaration"
            );
        });

        // The env layer parses with FromStr, not clap's value_parser.
        with_env(&[("KOXI_TOOLCHAIN", "llvm")], || {
            assert_eq!(opts(&["setup"]).toolchain_and_cc(bare).0, Toolchain::Llvm);
        });

        // An environment may name the compiler for a toolchain when the
        // bare name on PATH is the wrong binary, but only for that
        // toolchain, and never over an explicit choice.
        with_env(&[("KOXI_LLVM_CC", "/store/unwrapped/clang")], || {
            assert_eq!(
                opts(&["setup", "--toolchain", "llvm"])
                    .toolchain_and_cc(bare)
                    .1,
                "/store/unwrapped/clang"
            );
            assert_eq!(
                opts(&["setup"]).toolchain_and_cc(bare).1,
                "gcc",
                "the llvm hook does not touch the gnu toolchain"
            );
            assert_eq!(
                opts(&["setup", "--toolchain", "llvm", "--cc", "clang-21"])
                    .toolchain_and_cc(bare)
                    .1,
                "clang-21",
                "an explicit --cc still wins"
            );
        });
        with_env(&[("KOXI_TOOLCHAIN", "nonsense")], || {
            assert!(BuildOpts::from_matches(&parse(&["setup"])).is_err());
        });
    }

    /// nixpkgs' cc-wrapper exports CC=clang the moment clang is in the
    /// shell, and the dev shell ships clang for the llvm toolchain. A
    /// knob reading CC would therefore turn the default gnu build into
    /// clang driving GNU binutils, silently -- the exact mismatch the
    /// toolchain selection exists to prevent.
    #[test]
    fn the_ambient_cc_does_not_decide_the_toolchain() {
        with_env(&[("CC", "clang"), ("CXX", "clang++")], || {
            let opts = BuildOpts::from_matches(&parse(&["setup"])).unwrap();
            assert_eq!(
                opts.toolchain_and_cc(None),
                (Toolchain::Gnu, "gcc".to_owned()),
                "the environment's CC is not the project's toolchain"
            );
        });
    }
}
