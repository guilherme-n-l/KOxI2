//! CLI surface, mirroring the v1 `block/run` broker.
//!
//! Env var names follow v1 `block/scripts/flags`; CLI flags take
//! precedence over env vars, which take precedence over defaults.

use std::path::PathBuf;

use clap::builder::FalseyValueParser;
use clap::{value_parser, Arg, ArgAction, Command};

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
        .subcommand(Command::new("clean").about("Remove build artifacts (preserves results/)"))
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
                .default_value("out/run.log")
                .conflicts_with("nologfile")
                .help("Log file for subprocess output"),
        )
        .arg(flag("nologfile", "NOLOGFILE").help("Discard subprocess output"))
        .arg(flag("nocache", "NOCACHE").help("Clear download cache (out/) before running"))
        .arg(flag("skip-build", "SKIP_BUILD").help("Skip kernel build (initramfs still rebuilt)"))
        // VM / benchmark
        .arg(
            opt("kernel", "KERNEL")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .default_value("out/bzImage")
                .help_heading("VM / benchmark")
                .help("Kernel bzImage"),
        )
        .arg(
            opt("initrd", "INITRD")
                .value_name("path")
                .value_parser(value_parser!(PathBuf))
                .default_value("out/initramfs.cpio.gz")
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
                .help("Syzkaller config template"),
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

#[cfg(test)]
mod tests {
    #[test]
    fn cli_is_well_formed() {
        super::command().debug_assert();
    }
}
