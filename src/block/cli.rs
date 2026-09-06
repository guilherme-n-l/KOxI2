//! CLI surface, mirroring the v1 `block/run` broker.
//!
//! Env var names follow v1 `block/scripts/flags`; CLI flags take
//! precedence over env vars, which take precedence over defaults.

use std::path::PathBuf;

use clap::builder::FalseyValueParser;
use clap::parser::ValueSource;
use clap::{value_parser, Arg, ArgAction, ArgMatches, Command};

/// Boolean flag, available to every subcommand. The env var enables
/// the flag unless empty or false-like ("0", "false", ...).
fn flag(name: &'static str, env: &'static str) -> Arg {
    Arg::new(name)
        .long(name)
        .action(ArgAction::SetTrue)
        .value_parser(FalseyValueParser::new())
        .env(env)
        .global(true)
}

/// Value-taking option, available to every subcommand.
fn opt(name: &'static str, env: &'static str) -> Arg {
    Arg::new(name).long(name).env(env).global(true)
}

/// The `koxi block` subcommand tree, mirroring v1 `block/run`.
pub fn command() -> Command {
    Command::new("block")
        .about("Block-device-driver harness")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(Command::new("setup").about("Only setup the environment"))
        .subcommand(
            Command::new("test")
                .about("Verify system deps, user config, and setup state")
                .arg(Arg::new("suite").num_args(0..).help("Test suites to run")),
        )
        .subcommand(
            Command::new("clean").about("Remove built artifacts (artifacts/; results preserved)"),
        )
        .subcommand(Command::new("perf").about("Run performance benchmarks"))
        .subcommand(Command::new("fuzz").about("Run fuzzing campaigns"))
        .subcommand(Command::new("static").about("Static analysis (loc, ast, commits)"))
        .subcommand(Command::new("screen").about("Synthesize cached Phase 1 screening artifacts"))
        .subcommand(Command::new("compare").about("Phase 2 only: diff p1 vs p2 data"))
        .subcommand(
            Command::new("debug")
                .about("Call an internal function with V=2")
                .arg(Arg::new("fn").required(true).help("Internal function name"))
                .arg(
                    Arg::new("args")
                        .num_args(0..)
                        .allow_hyphen_values(true)
                        .trailing_var_arg(true)
                        .help("Arguments forwarded to the function"),
                ),
        )
        .subcommand(Command::new("all").about("static + perf + fuzz + compare (phase-aware)"))
        // Global
        .arg(
            flag("p1", "PHASE1_ONLY")
                .help("Phase 1 only (C baseline). Default: full run (p1 + p2)"),
        )
        .arg(
            opt("only", "ONLY_DRIVERS")
                .value_name("name[:name]")
                .value_delimiter(':')
                .action(ArgAction::Append)
                .help("Filter by C driver name; Rust pair follows from drivers.cfg"),
        )
        .arg(
            opt("output", "RESULTS_ROOT")
                .value_name("dir")
                .value_parser(value_parser!(PathBuf))
                .default_value("results")
                .help("Results root dir"),
        )
        .arg(
            opt("mnt", "MNT")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .default_value("rootmnt")
                .help("Host mount dir"),
        )
        .arg(
            opt("campaign", "CAMPAIGN")
                .value_name("name")
                .help("P2 campaign name (default: unix timestamp)"),
        )
        .arg(flag("force-p1", "FORCE_P1").help("Re-run baseline even if cached"))
        .arg(
            flag("force-build", "FORCE_BUILD")
                .help("Force kernel rebuild (also nukes the extracted tree)"),
        )
        .arg(
            flag("menuconfig", "MENUCONFIG")
                .help("Run `make menuconfig`, persist .config, force rebuild"),
        )
        .arg(
            flag("quick", "QUICK")
                .conflicts_with("longrun")
                .help("Fast defaults for dev/CI"),
        )
        .arg(flag("longrun", "LONGRUN").help("Paper dataset defaults (30x24h fuzz campaigns)"))
        .arg(flag("verbose", "VERBOSE").help("Verbose output (V=1)"))
        .arg(
            flag("debug-output", "DEBUG")
                .long("debug")
                .help("Debug output with variable dumps (V=2)"),
        )
        .arg(
            opt("logfile", "LOGFILE")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .default_value("run.log")
                .conflicts_with("nologfile")
                .help("Log file (default: KOXI_HOME/log/<project>/<run-id>/run.log)"),
        )
        .arg(flag("nologfile", "NOLOGFILE").help("Discard subprocess output"))
        .arg(flag("nocache", "NOCACHE").help("Clear the KOXI_HOME download cache before running"))
        .arg(flag("skip-build", "SKIP_BUILD").help("Skip kernel build (initramfs still rebuilt)"))
        .arg(flag("yes", "ASSUME_YES").help("Assume yes for interactive prompts"))
        .arg(
            opt("cc", "CC")
                .value_name("compiler")
                .default_value("gcc")
                .help("C compiler for the kernel build (e.g. clang)"),
        )
        // VM / benchmark
        .arg(
            opt("kernel", "KERNEL")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .default_value("artifacts/bzImage")
                .help_heading("VM / benchmark")
                .help("Kernel bzImage (default resolved under the project root)"),
        )
        .arg(
            opt("initrd", "INITRD")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .default_value("artifacts/initramfs.cpio.gz")
                .help_heading("VM / benchmark")
                .help("Initrd"),
        )
        .arg(
            opt("port", "FWDPORT")
                .value_name("port")
                .value_parser(value_parser!(u16))
                .default_value("5555")
                .help_heading("VM / benchmark")
                .help("SSH forward port"),
        )
        .arg(
            opt("smp", "SMP")
                .value_name("n")
                .value_parser(value_parser!(u32))
                .default_value("4")
                .help_heading("VM / benchmark")
                .help("vCPUs"),
        )
        .arg(
            opt("memory", "MEMORY")
                .value_name("size")
                .default_value("4G")
                .help_heading("VM / benchmark")
                .help("RAM"),
        )
        .arg(
            opt("vm-timeout", "VM_TIMEOUT")
                .value_name("s")
                .value_parser(value_parser!(u64))
                .default_value("120")
                .help_heading("VM / benchmark")
                .help("VM ready timeout in seconds"),
        )
        // Fio knobs
        .arg(
            opt("fio-bs", "FIO_BSIZES")
                .value_name("sizes")
                .value_delimiter(' ')
                .default_values(["4k", "64k", "1M"])
                .help_heading("Fio knobs")
                .help("Block sizes"),
        )
        .arg(
            opt("fio-rw", "FIO_RWS")
                .value_name("patterns")
                .value_delimiter(' ')
                .default_values(["randread", "randwrite"])
                .help_heading("Fio knobs")
                .help("I/O patterns"),
        )
        .arg(
            opt("fio-qd", "FIO_QDS")
                .value_name("depths")
                .value_delimiter(' ')
                .value_parser(value_parser!(u32))
                .default_values(["1", "32", "256"])
                .help_heading("Fio knobs")
                .help("Queue depths"),
        )
        .arg(
            opt("fio-sz", "FIO_SIZES")
                .value_name("sizes")
                .value_delimiter(' ')
                .default_values(["512M"])
                .help_heading("Fio knobs")
                .help("File sizes"),
        )
        .arg(
            opt("fio-reps", "FIO_REPS")
                .value_name("n")
                .value_parser(value_parser!(u32))
                .default_value("30")
                .help_heading("Fio knobs")
                .help("Repetitions per config"),
        )
        .arg(
            opt("fio-runtime", "FIO_RUNTIME")
                .value_name("s")
                .value_parser(value_parser!(u64))
                .default_value("30")
                .help_heading("Fio knobs")
                .help("Seconds per fio run"),
        )
        .arg(
            opt("seed", "WORKLOAD_SEED")
                .value_name("n")
                .value_parser(value_parser!(u64))
                .help_heading("Fio knobs")
                .help("Deterministic workload shuffle seed (default: unix time)"),
        )
        .arg(
            opt("fio-engine", "FIO_ENGINE")
                .value_name("engine")
                .default_value("io_uring")
                .help_heading("Fio knobs")
                .help("fio ioengine (io_uring makes the qd axis real; psync = v1 parity)"),
        )
        // Fuzzing
        .arg(
            opt("fuzz-campaigns", "FUZZ_CAMPAIGNS")
                .value_name("n")
                .value_parser(value_parser!(u32))
                .default_value("30")
                .help_heading("Fuzzing")
                .help("Independent campaigns"),
        )
        .arg(
            opt("fuzz-hours", "FUZZ_CAMPAIGN_HOURS")
                .value_name("h")
                .value_parser(value_parser!(f64))
                .default_value("1")
                .help_heading("Fuzzing")
                .help("Hours per campaign"),
        )
        .arg(
            opt("fuzz-parallel", "FUZZ_PARALLEL")
                .value_name("n")
                .value_parser(value_parser!(u32))
                .default_value("4")
                .help_heading("Fuzzing")
                .help("Parallel campaigns"),
        )
        .arg(
            opt("syz-cfg", "CFG_TEMPLATE")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .help_heading("Fuzzing")
                .help("Base syz-manager config (JSON; machine-owned fields are overlaid)"),
        )
        .arg(
            opt("syz-desc", "SYZ_DESC")
                .value_name("path[:path]")
                .value_delimiter(':')
                .value_parser(value_parser!(PathBuf))
                .help_heading("Fuzzing")
                .help("Syzkaller description files"),
        )
        .arg(
            opt("syz-root", "SYZ_ROOT")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .help_heading("Fuzzing")
                .help("Syzkaller root dir"),
        )
        .arg(
            opt("syz-manager", "SYZ_MANAGER")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .help_heading("Fuzzing")
                .help("syz-manager binary"),
        )
        .arg(
            opt("syz-http-port", "SYZ_HTTP_PORT")
                .value_name("port")
                .value_parser(value_parser!(u16))
                .default_value("0")
                .help_heading("Fuzzing")
                .help("syz-manager HTTP port (0 = random)"),
        )
        // Compare
        .arg(
            opt("safety-threshold", "SAFETY_THRESHOLD")
                .value_name("pct")
                .value_parser(value_parser!(f64))
                .default_value("34.2")
                .help_heading("Compare")
                .help("Elimination rate threshold"),
        )
        .arg(
            opt("perf-threshold", "PERF_THRESHOLD")
                .value_name("pct")
                .value_parser(value_parser!(f64))
                .default_value("5")
                .help_heading("Compare")
                .help("Max allowed overhead %"),
        )
        .arg(
            opt("a12-large-threshold", "A12_LARGE_THRESHOLD")
                .value_name("x")
                .value_parser(value_parser!(f64))
                .default_value("0.71")
                .help_heading("Compare")
                .help("Vargha-Delaney large-effect threshold"),
        )
        .arg(
            opt("alpha", "ALPHA")
                .value_name("x")
                .value_parser(value_parser!(f64))
                .default_value("0.05")
                .help_heading("Compare")
                .help("Statistical significance threshold"),
        )
        .arg(
            opt("bootstrap-resamples", "BOOTSTRAP_RESAMPLES")
                .value_name("n")
                .value_parser(value_parser!(u64))
                .default_value("10000")
                .help_heading("Compare")
                .help("Bootstrap resamples for performance CIs"),
        )
        .arg(
            opt("validated-cwe", "VALIDATED_CWE")
                .value_name("csv")
                .value_parser(value_parser!(PathBuf))
                .help_heading("Compare")
                .help("Optional commit CWE override CSV"),
        )
        .arg(
            opt("validated-crashes", "VALIDATED_CRASHES")
                .value_name("csv")
                .value_parser(value_parser!(PathBuf))
                .help_heading("Compare")
                .help("Optional crash classification override CSV"),
        )
}

/// Typed view of the parsed `koxi block` flags, built once per run so
/// handlers never touch stringly `ArgMatches` lookups.
#[derive(Debug, Clone)]
pub struct Opts {
    pub p1: bool,
    pub only: Vec<String>,
    pub output: PathBuf,
    pub mnt: PathBuf,
    pub campaign: Option<String>,
    pub force_p1: bool,
    pub force_build: bool,
    pub menuconfig: bool,
    pub quick: bool,
    pub longrun: bool,
    pub verbose: bool,
    pub debug: bool,
    pub logfile: PathBuf,
    pub nologfile: bool,
    pub nocache: bool,
    pub skip_build: bool,
    pub yes: bool,
    pub cc: String,
    /// Whether --cc came from the CLI/env rather than clap's default,
    /// so koxi.toml [build].cc can fill the gap.
    pub cc_from_cli: bool,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub port: u16,
    pub smp: u32,
    pub memory: String,
    pub vm_timeout: u64,
    pub fio_bs: Vec<String>,
    pub fio_rw: Vec<String>,
    pub fio_qd: Vec<u32>,
    pub fio_sz: Vec<String>,
    pub fio_reps: u32,
    pub fio_runtime: u64,
    pub fio_engine: String,
    pub seed: Option<u64>,
    pub fuzz_campaigns: u32,
    pub fuzz_hours: f64,
    pub fuzz_parallel: u32,
    pub syz_cfg: Option<PathBuf>,
    pub syz_desc: Vec<PathBuf>,
    pub syz_root: Option<PathBuf>,
    pub syz_manager: Option<PathBuf>,
    pub syz_http_port: u16,
    pub safety_threshold: f64,
    pub perf_threshold: f64,
    pub a12_large_threshold: f64,
    pub alpha: f64,
    pub bootstrap_resamples: u64,
    pub validated_cwe: Option<PathBuf>,
    pub validated_crashes: Option<PathBuf>,
}

impl Opts {
    pub fn from_matches(matches: &ArgMatches) -> Self {
        fn strings(matches: &ArgMatches, name: &str) -> Vec<String> {
            matches
                .get_many::<String>(name)
                .into_iter()
                .flatten()
                .cloned()
                .collect()
        }
        fn paths(matches: &ArgMatches, name: &str) -> Vec<PathBuf> {
            matches
                .get_many::<PathBuf>(name)
                .into_iter()
                .flatten()
                .cloned()
                .collect()
        }
        fn path(matches: &ArgMatches, name: &str) -> PathBuf {
            matches
                .get_one::<PathBuf>(name)
                .cloned()
                .expect("defaulted")
        }
        fn copied<T: Copy + Clone + Send + Sync + 'static>(matches: &ArgMatches, name: &str) -> T {
            *matches.get_one::<T>(name).expect("defaulted")
        }

        let mut opts = Self {
            p1: matches.get_flag("p1"),
            only: strings(matches, "only"),
            output: path(matches, "output"),
            mnt: path(matches, "mnt"),
            campaign: matches.get_one::<String>("campaign").cloned(),
            force_p1: matches.get_flag("force-p1"),
            force_build: matches.get_flag("force-build"),
            menuconfig: matches.get_flag("menuconfig"),
            quick: matches.get_flag("quick"),
            longrun: matches.get_flag("longrun"),
            verbose: matches.get_flag("verbose"),
            debug: matches.get_flag("debug-output"),
            logfile: path(matches, "logfile"),
            nologfile: matches.get_flag("nologfile"),
            nocache: matches.get_flag("nocache"),
            skip_build: matches.get_flag("skip-build"),
            yes: matches.get_flag("yes"),
            cc: matches.get_one::<String>("cc").cloned().expect("defaulted"),
            cc_from_cli: matches.value_source("cc")
                != Some(clap::parser::ValueSource::DefaultValue),
            kernel: path(matches, "kernel"),
            initrd: path(matches, "initrd"),
            port: copied(matches, "port"),
            smp: copied(matches, "smp"),
            memory: matches
                .get_one::<String>("memory")
                .cloned()
                .expect("defaulted"),
            vm_timeout: copied(matches, "vm-timeout"),
            fio_bs: strings(matches, "fio-bs"),
            fio_rw: strings(matches, "fio-rw"),
            fio_qd: matches
                .get_many::<u32>("fio-qd")
                .into_iter()
                .flatten()
                .copied()
                .collect(),
            fio_sz: strings(matches, "fio-sz"),
            fio_reps: copied(matches, "fio-reps"),
            fio_runtime: copied(matches, "fio-runtime"),
            fio_engine: matches
                .get_one::<String>("fio-engine")
                .cloned()
                .expect("defaulted"),
            seed: matches.get_one::<u64>("seed").copied(),
            fuzz_campaigns: copied(matches, "fuzz-campaigns"),
            fuzz_hours: copied(matches, "fuzz-hours"),
            fuzz_parallel: copied(matches, "fuzz-parallel"),
            syz_cfg: matches.get_one::<PathBuf>("syz-cfg").cloned(),
            syz_desc: paths(matches, "syz-desc"),
            syz_root: matches.get_one::<PathBuf>("syz-root").cloned(),
            syz_manager: matches.get_one::<PathBuf>("syz-manager").cloned(),
            syz_http_port: copied(matches, "syz-http-port"),
            safety_threshold: copied(matches, "safety-threshold"),
            perf_threshold: copied(matches, "perf-threshold"),
            a12_large_threshold: copied(matches, "a12-large-threshold"),
            alpha: copied(matches, "alpha"),
            bootstrap_resamples: copied(matches, "bootstrap-resamples"),
            validated_cwe: matches.get_one::<PathBuf>("validated-cwe").cloned(),
            validated_crashes: matches.get_one::<PathBuf>("validated-crashes").cloned(),
        };
        opts.apply_profiles(matches);
        opts
    }

    /// v1 `_set_quick` / `_set_longrun`: profile defaults applied only
    /// where the user didn't set the knob explicitly.
    fn apply_profiles(&mut self, matches: &ArgMatches) {
        let defaulted = |name: &str| matches.value_source(name) == Some(ValueSource::DefaultValue);
        if self.quick {
            if defaulted("fio-bs") {
                self.fio_bs = vec!["4k".to_owned()];
            }
            if defaulted("fio-rw") {
                self.fio_rw = vec!["randread".to_owned()];
            }
            if defaulted("fio-qd") {
                self.fio_qd = vec![1];
            }
            if defaulted("fio-reps") {
                self.fio_reps = 3;
            }
            if defaulted("fio-runtime") {
                self.fio_runtime = 5;
            }
            if defaulted("fuzz-campaigns") {
                self.fuzz_campaigns = 1;
            }
            if defaulted("fuzz-hours") {
                self.fuzz_hours = 0.01;
            }
        } else if self.longrun {
            if defaulted("fuzz-campaigns") {
                self.fuzz_campaigns = 30;
            }
            if defaulted("fuzz-hours") {
                self.fuzz_hours = 24.0;
            }
            if defaulted("fio-reps") {
                self.fio_reps = 50;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_is_well_formed() {
        super::command().debug_assert();
    }

    #[test]
    fn quick_and_longrun_fill_unset_knobs() {
        let matches = super::command().get_matches_from(["block", "perf", "--quick"]);
        let (_, sub) = matches.subcommand().unwrap();
        let opts = super::Opts::from_matches(sub);
        assert_eq!(opts.fio_reps, 3);
        assert_eq!(opts.fuzz_hours, 0.01);
        assert_eq!(opts.fio_qd, vec![1]);

        let matches =
            super::command().get_matches_from(["block", "perf", "--quick", "--fio-reps", "10"]);
        let (_, sub) = matches.subcommand().unwrap();
        let opts = super::Opts::from_matches(sub);
        assert_eq!(opts.fio_reps, 10, "explicit flag beats the profile");

        let matches = super::command().get_matches_from(["block", "fuzz", "--longrun"]);
        let (_, sub) = matches.subcommand().unwrap();
        let opts = super::Opts::from_matches(sub);
        assert_eq!(opts.fuzz_hours, 24.0);
        assert_eq!(opts.fio_reps, 50);
    }

    #[test]
    fn opts_build_from_defaults() {
        let matches = super::command().get_matches_from(["block", "setup"]);
        let (_, sub) = matches.subcommand().unwrap();
        let opts = super::Opts::from_matches(sub);
        assert_eq!(opts.smp, 4);
        assert_eq!(opts.fio_qd, vec![1, 32, 256]);
        assert_eq!(opts.logfile, std::path::PathBuf::from("run.log"));
        assert!(!opts.yes);
    }
}
