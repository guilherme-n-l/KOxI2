//! Shared CLI plumbing: the option groups every subcommand tree
//! reuses, and env-var fallback with CLI > env > default precedence.
//!
//! Env vars are resolved here, not by clap: a knob set only in the
//! environment never counts as "present" for conflict checks, an
//! invalid env value is reported only when the running subcommand
//! actually consumes that knob, and profiles (`--quick`) can tell a
//! knob left at its default from one the user pinned. Env var names
//! follow the v1 `block/scripts/flags` so existing scripts keep
//! working.

use std::path::PathBuf;
use std::str::FromStr;

use clap::parser::ValueSource;
use clap::{value_parser, Arg, ArgAction, ArgMatches};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{env}={value:?}: invalid value for --{arg}: {why}")]
    Invalid {
        env: &'static str,
        arg: &'static str,
        value: String,
        why: String,
    },
    #[error("--{a} and --{b} cannot be combined")]
    Conflict { a: &'static str, b: &'static str },
    #[error("--{arg} is required (or {env} in the environment)")]
    Missing {
        arg: &'static str,
        env: &'static str,
    },
}

/// Where a knob's effective value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Cli,
    Env,
    Default,
}

fn env_var(env: &str) -> Option<String> {
    std::env::var(env).ok().filter(|value| !value.is_empty())
}

fn help_with_env(help: &str, env: &str) -> String {
    format!("{help} [env: {env}]")
}

/// A boolean flag with an env fallback; the env var enables the flag
/// unless false-like ("0", "false", "no", "off").
pub fn flag(name: &'static str, env: &'static str, help: &str) -> Arg {
    Arg::new(name)
        .long(name)
        .action(ArgAction::SetTrue)
        .help(help_with_env(help, env))
}

/// A value-taking option with an env fallback; the caller adds the
/// value parser, name, and default.
pub fn opt(name: &'static str, env: &'static str, help: &str) -> Arg {
    Arg::new(name).long(name).help(help_with_env(help, env))
}

/// Whether the arg was given on the command line (a clap default
/// reads as absent).
pub fn on_cli(matches: &ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

/// Resolve where a knob's value comes from.
pub fn source(matches: &ArgMatches, id: &str, env: &str) -> Source {
    if on_cli(matches, id) {
        Source::Cli
    } else if env_var(env).is_some() {
        Source::Env
    } else {
        Source::Default
    }
}

/// A boolean flag: CLI presence, else the env var's truthiness,
/// else false.
pub fn flag_value(matches: &ArgMatches, id: &'static str, env: &'static str) -> bool {
    if on_cli(matches, id) {
        return matches.get_flag(id);
    }
    env_var(env).is_some_and(|value| truthy(&value))
}

fn truthy(value: &str) -> bool {
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "n"
    )
}

/// A single value: CLI, else env (parsed with `T::from_str`), else
/// clap's default when the arg has one.
pub fn value<T>(
    matches: &ArgMatches,
    id: &'static str,
    env: &'static str,
) -> Result<Option<T>, Error>
where
    T: FromStr + Clone + Send + Sync + 'static,
    T::Err: std::fmt::Display,
{
    if on_cli(matches, id) {
        return Ok(matches.get_one::<T>(id).cloned());
    }
    if let Some(raw) = env_var(env) {
        return raw.parse::<T>().map(Some).map_err(|err| Error::Invalid {
            env,
            arg: id,
            value: raw,
            why: err.to_string(),
        });
    }
    Ok(matches.get_one::<T>(id).cloned())
}

/// A value that always resolves (the arg carries a clap default).
pub fn required<T>(matches: &ArgMatches, id: &'static str, env: &'static str) -> Result<T, Error>
where
    T: FromStr + Clone + Send + Sync + 'static,
    T::Err: std::fmt::Display,
{
    Ok(value::<T>(matches, id, env)?.expect("arg carries a default"))
}

/// A list: CLI values, else the env var split on `delimiter`, else
/// clap's defaults.
pub fn values<T>(
    matches: &ArgMatches,
    id: &'static str,
    env: &'static str,
    delimiter: char,
) -> Result<Vec<T>, Error>
where
    T: FromStr + Clone + Send + Sync + 'static,
    T::Err: std::fmt::Display,
{
    if on_cli(matches, id) {
        return Ok(matches
            .get_many::<T>(id)
            .into_iter()
            .flatten()
            .cloned()
            .collect());
    }
    if let Some(raw) = env_var(env) {
        return raw
            .split(delimiter)
            .filter(|item| !item.is_empty())
            .map(|item| {
                item.parse::<T>().map_err(|err| Error::Invalid {
                    env,
                    arg: id,
                    value: raw.clone(),
                    why: err.to_string(),
                })
            })
            .collect();
    }
    Ok(matches
        .get_many::<T>(id)
        .into_iter()
        .flatten()
        .cloned()
        .collect())
}

/// Two flags that exclude each other, env included: both on the CLI
/// is an error, a CLI flag beats an env flag, both from env is an
/// error. Returns `(a, b)`.
pub fn exclusive(
    matches: &ArgMatches,
    a: (&'static str, &'static str),
    b: (&'static str, &'static str),
) -> Result<(bool, bool), Error> {
    let cli = (on_cli(matches, a.0), on_cli(matches, b.0));
    let env = (
        env_var(a.1).is_some_and(|value| truthy(&value)),
        env_var(b.1).is_some_and(|value| truthy(&value)),
    );
    match cli {
        (true, true) => Err(Error::Conflict { a: a.0, b: b.0 }),
        (true, false) => Ok((true, false)),
        (false, true) => Ok((false, true)),
        (false, false) => match env {
            (true, true) => Err(Error::Conflict { a: a.0, b: b.0 }),
            other => Ok(other),
        },
    }
}

/// Logging flags, global to the whole tree.
pub fn logging_args() -> [Arg; 4] {
    [
        flag("verbose", "VERBOSE", "Verbose console output").global(true),
        flag("debug", "DEBUG", "Debug console output (trace level)").global(true),
        opt(
            "logfile",
            "LOGFILE",
            "Run log file (default: $KOXI_HOME/log/<project>/<run-id>/run.log)",
        )
        .value_name("path")
        .value_parser(value_parser!(PathBuf))
        .global(true),
        flag("nologfile", "NOLOGFILE", "Console only: write no run log")
            .conflicts_with("logfile")
            .global(true),
    ]
}

/// `--yes`, global: every confirmation prompt in the tree honors it.
pub fn yes_arg() -> Arg {
    flag("yes", "ASSUME_YES", "Assume yes for interactive prompts").global(true)
}

/// The globals every subcommand sees.
#[derive(Debug, Clone)]
pub struct Globals {
    pub verbose: bool,
    pub debug: bool,
    pub logfile: Option<PathBuf>,
    pub nologfile: bool,
    pub yes: bool,
}

impl Globals {
    pub fn from_matches(matches: &ArgMatches) -> Result<Self, Error> {
        Ok(Self {
            verbose: flag_value(matches, "verbose", "VERBOSE"),
            debug: flag_value(matches, "debug", "DEBUG"),
            logfile: value::<PathBuf>(matches, "logfile", "LOGFILE")?,
            nologfile: flag_value(matches, "nologfile", "NOLOGFILE"),
            yes: flag_value(matches, "yes", "ASSUME_YES"),
        })
    }
}

/// Declare a CLI option group: one line per knob, from which this
/// derives the struct field, the clap [`Arg`], and the env-aware
/// resolution.
///
/// The point is that a knob names its flag and its env var exactly
/// once. Hand-written, each appeared three times (arg builder, struct
/// field, resolver lookup) with nothing tying them together, so a
/// typo in one produced a knob that parsed but never resolved, or
/// resolved but ignored its env var.
///
/// Forms, all spelled `<field>: <ty> = "<long>" / "<ENV>"`:
/// - `flag` — a `bool`, true when present or when the env var is truthy.
/// - `opt` — an `Option<T>`, absent when neither is given.
/// - `req` — a `T` carrying a `default`.
/// - `list` — a `Vec<T>` split on a delimiter, optionally with defaults.
/// - `group` — another group's args and fields, flattened into the
///   same matches.
///
/// The doc comment is the help text. A trailing `=> { .method(..) }`
/// appends builder calls to that one arg. A group declared `custom`
/// gets `args()` but no `from_matches`: write that by hand when the
/// knobs interact (see [`crate::block::cli::Profile`]).
///
/// `matches` is threaded through the recursion as a token rather than
/// written in each expansion: macro_rules gives every expansion its
/// own syntax context, so an identifier minted in one arm would not
/// be the one bound in another.
macro_rules! knobs {
    // Entry: the generated `from_matches` is the group's constructor.
    (
        $(#[$meta:meta])*
        pub struct $name:ident($heading:expr) { $($body:tt)* }
    ) => {
        knobs!(@munch [full] [matches] [$(#[$meta])*] [$name] [$heading]
            fields {} args {} init {} rest { $($body)* });
    };
    // Entry: `custom` suppresses `from_matches`.
    (
        $(#[$meta:meta])*
        pub struct $name:ident($heading:expr) custom { $($body:tt)* }
    ) => {
        knobs!(@munch [custom] [matches] [$(#[$meta])*] [$name] [$heading]
            fields {} args {} init {} rest { $($body)* });
    };

    (@munch [$mode:ident] [$m:ident] [$($meta:tt)*] [$name:ident] [$heading:expr]
        fields { $($f:tt)* } args { $($a:tt)* } init { $($i:tt)* }
        rest {
            $(#[doc = $help:literal])+
            flag $field:ident = $long:literal / $env:literal
            $(=> { $($chain:tt)* })? ;
            $($rest:tt)*
        }
    ) => {
        knobs!(@munch [$mode] [$m] [$($meta)*] [$name] [$heading]
            fields { $($f)* $(#[doc = $help])+ pub $field: bool, }
            args { $($a)* vec![
                $crate::cli::flag($long, $env, knobs!(@help $($help),+))
                    .help_heading($heading)
                    $($($chain)*)?
            ], }
            init { $($i)* $field: $crate::cli::flag_value($m, $long, $env), }
            rest { $($rest)* });
    };

    (@munch [$mode:ident] [$m:ident] [$($meta:tt)*] [$name:ident] [$heading:expr]
        fields { $($f:tt)* } args { $($a:tt)* } init { $($i:tt)* }
        rest {
            $(#[doc = $help:literal])+
            opt $field:ident: $ty:ty = $long:literal / $env:literal, $value:literal
            $(=> { $($chain:tt)* })? ;
            $($rest:tt)*
        }
    ) => {
        knobs!(@munch [$mode] [$m] [$($meta)*] [$name] [$heading]
            fields { $($f)* $(#[doc = $help])+ pub $field: Option<$ty>, }
            args { $($a)* vec![
                $crate::cli::opt($long, $env, knobs!(@help $($help),+))
                    .value_name($value)
                    .value_parser(::clap::value_parser!($ty))
                    .help_heading($heading)
                    $($($chain)*)?
            ], }
            init { $($i)* $field: $crate::cli::value($m, $long, $env)?, }
            rest { $($rest)* });
    };

    (@munch [$mode:ident] [$m:ident] [$($meta:tt)*] [$name:ident] [$heading:expr]
        fields { $($f:tt)* } args { $($a:tt)* } init { $($i:tt)* }
        rest {
            $(#[doc = $help:literal])+
            req $field:ident: $ty:ty = $long:literal / $env:literal, $value:literal,
                default $default:literal
            $(=> { $($chain:tt)* })? ;
            $($rest:tt)*
        }
    ) => {
        knobs!(@munch [$mode] [$m] [$($meta)*] [$name] [$heading]
            fields { $($f)* $(#[doc = $help])+ pub $field: $ty, }
            args { $($a)* vec![
                $crate::cli::opt($long, $env, knobs!(@help $($help),+))
                    .value_name($value)
                    .value_parser(::clap::value_parser!($ty))
                    .default_value($default)
                    .help_heading($heading)
                    $($($chain)*)?
            ], }
            init { $($i)* $field: $crate::cli::required($m, $long, $env)?, }
            rest { $($rest)* });
    };

    (@munch [$mode:ident] [$m:ident] [$($meta:tt)*] [$name:ident] [$heading:expr]
        fields { $($f:tt)* } args { $($a:tt)* } init { $($i:tt)* }
        rest {
            $(#[doc = $help:literal])+
            list $field:ident: $ty:ty = $long:literal / $env:literal, $value:literal,
                split $split:literal $(, default [$($default:literal),+ $(,)?])?
            $(=> { $($chain:tt)* })? ;
            $($rest:tt)*
        }
    ) => {
        knobs!(@munch [$mode] [$m] [$($meta)*] [$name] [$heading]
            fields { $($f)* $(#[doc = $help])+ pub $field: Vec<$ty>, }
            args { $($a)* vec![
                $crate::cli::opt($long, $env, knobs!(@help $($help),+))
                    .value_name($value)
                    .value_delimiter($split)
                    .value_parser(::clap::value_parser!($ty))
                    $(.default_values([$($default),+]))?
                    .help_heading($heading)
                    $($($chain)*)?
            ], }
            init { $($i)* $field: $crate::cli::values($m, $long, $env, $split)?, }
            rest { $($rest)* });
    };

    (@munch [$mode:ident] [$m:ident] [$($meta:tt)*] [$name:ident] [$heading:expr]
        fields { $($f:tt)* } args { $($a:tt)* } init { $($i:tt)* }
        rest {
            $(#[doc = $help:literal])+
            group $field:ident: $ty:ty;
            $($rest:tt)*
        }
    ) => {
        knobs!(@munch [$mode] [$m] [$($meta)*] [$name] [$heading]
            fields { $($f)* $(#[doc = $help])+ pub $field: $ty, }
            args { $($a)* <$ty>::args(), }
            init { $($i)* $field: <$ty>::from_matches($m)?, }
            rest { $($rest)* });
    };

    // Terminal: the struct, its args, and (unless `custom`) its
    // resolver. Args are assembled by flattening per-knob vectors so
    // no local binding has to survive across expansions.
    (@munch [$mode:ident] [$m:ident] [$($meta:tt)*] [$name:ident] [$heading:expr]
        fields { $($f:tt)* } args { $($a:tt)* } init { $($i:tt)* }
        rest {}
    ) => {
        $($meta)*
        pub struct $name { $($f)* }

        impl $name {
            /// The clap args this group contributes to a subcommand.
            pub fn args() -> Vec<::clap::Arg> {
                [$($a)*].into_iter().flatten().collect()
            }

            /// This group's arg with the given id, for a verb that
            /// wants one knob of the group rather than all of it.
            #[allow(dead_code, reason = "not every group is picked apart")]
            pub fn arg(id: &str) -> ::clap::Arg {
                Self::args()
                    .into_iter()
                    .find(|arg| arg.get_id() == id)
                    .unwrap_or_else(|| panic!("{id} is not a knob of this group"))
            }
        }

        knobs!(@resolver [$mode] [$m] [$name] init { $($i)* });
    };

    // The doc comment is the help text: joined, trimmed, and with the
    // sentence-final period dropped, so Rust doc style and clap help
    // style can both be right.
    (@help $($help:literal),+) => {{
        let help = concat!($($help),+).trim();
        help.strip_suffix('.').unwrap_or(help)
    }};

    (@resolver [full] [$m:ident] [$name:ident] init { $($i:tt)* }) => {
        impl $name {
            /// Resolve the group: CLI beats env beats default.
            pub fn from_matches($m: &::clap::ArgMatches) -> Result<Self, $crate::cli::Error> {
                Ok(Self { $($i)* })
            }
        }
    };
    (@resolver [custom] [$m:ident] [$name:ident] init { $($i:tt)* }) => {};
}

pub(crate) use knobs;

const VM_HEADING: &str = "VM";

knobs! {
    /// The guest a phase boots: its initramfs and geometry. The fuzz
    /// phase takes only this — syz-manager owns the kernel choice,
    /// the forwarded port, and the boot timeout.
    #[derive(Debug, Clone)]
    pub struct GuestOpts(VM_HEADING) {
        /// Initrd (default resolved under the project root).
        req initrd: PathBuf = "initrd" / "INITRD", "path",
            default "artifacts/initramfs.cpio.gz";
        /// vCPUs.
        req smp: u32 = "smp" / "SMP", "n", default "4";
        /// RAM, qemu-style (4G, 512M, bare MiB). Parsed where it is
        /// consumed, since the env layer bypasses clap's parser.
        req memory: String = "memory" / "MEMORY", "size", default "4G";
    }
}

knobs! {
    /// One qemu guest driven from the host over ssh: `koxi vm` and
    /// `block perf` boot exactly this.
    #[derive(Debug, Clone)]
    pub struct VmOpts(VM_HEADING) {
        /// Kernel bzImage (default resolved under the project root).
        req kernel: PathBuf = "kernel" / "KERNEL", "path", default "artifacts/bzImage";
        /// The guest this boots.
        group guest: GuestOpts;
        /// SSH forward port.
        req port: u16 = "port" / "FWDPORT", "port", default "5555";
        /// VM ready timeout in seconds.
        req vm_timeout: u64 = "vm-timeout" / "VM_TIMEOUT", "s", default "120";
    }
}

impl VmOpts {
    /// Whether --kernel was left alone (neither CLI nor env), so a
    /// caller may substitute a flavor-specific image.
    pub fn kernel_defaulted(matches: &ArgMatches) -> bool {
        source(matches, "kernel", "KERNEL") == Source::Default
    }
}

/// Env-driven tests share the process environment: every test that
/// sets or reads env vars runs its body under this one lock (across
/// modules) so none observes another's variables.
#[cfg(test)]
pub(crate) fn with_env(vars: &[(&str, &str)], body: impl FnOnce()) {
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (name, value) in vars {
        std::env::set_var(name, value);
    }
    body();
    for (name, _) in vars {
        std::env::remove_var(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Command;

    const T: &str = "Test knobs";

    knobs! {
        /// Every knob form, so the macro itself is under test.
        #[derive(Debug, Clone)]
        pub struct Sample(T) {
            /// A boolean.
            flag on = "on" / "T_ON";
            /// Something optional.
            opt name: String = "name" / "T_NAME", "s";
            /// Something with a default.
            req count: u32 = "count" / "T_COUNT", "n", default "7";
            /// A delimited list.
            list sizes: String = "sizes" / "T_SIZES", "sizes", split ' ', default ["4k", "1M"];
            /// A nested group.
            group nested: Nested;
        }
    }

    knobs! {
        /// Nested into [`Sample`].
        #[derive(Debug, Clone)]
        pub struct Nested(T) {
            /// A nested knob.
            req depth: u8 = "depth" / "T_DEPTH", "n", default "3";
        }
    }

    fn sample(args: &[&str]) -> Sample {
        let matches = Command::new("t")
            .args(Sample::args())
            .get_matches_from([&["t"], args].concat());
        Sample::from_matches(&matches).expect("sample")
    }

    fn cmd() -> Command {
        Command::new("t")
            .arg(flag("quick", "T_QUICK", "q"))
            .arg(flag("longrun", "T_LONGRUN", "l"))
            .arg(
                opt("reps", "T_REPS", "r")
                    .value_parser(value_parser!(u32))
                    .default_value("30"),
            )
            .arg(
                opt("bs", "T_BS", "b")
                    .value_delimiter(' ')
                    .default_values(["4k", "64k"]),
            )
    }

    #[test]
    fn generated_knobs_cover_every_form() {
        with_env(&[], || {
            let opts = sample(&[]);
            assert!(!opts.on);
            assert_eq!(opts.name, None);
            assert_eq!(opts.count, 7);
            assert_eq!(opts.sizes, vec!["4k", "1M"]);
            assert_eq!(opts.nested.depth, 3, "a nested group resolves too");

            let opts = sample(&[
                "--on", "--name", "x", "--count", "2", "--sizes", "8k", "--depth", "9",
            ]);
            assert!(opts.on);
            assert_eq!(opts.name.as_deref(), Some("x"));
            assert_eq!(opts.count, 2);
            assert_eq!(opts.sizes, vec!["8k"]);
            assert_eq!(opts.nested.depth, 9);
        });
        // Each knob names its env var once, and that one name is what
        // the resolver reads: the drift the macro exists to prevent.
        with_env(
            &[
                ("T_ON", "1"),
                ("T_NAME", "env"),
                ("T_COUNT", "5"),
                ("T_SIZES", "2k 4k"),
                ("T_DEPTH", "1"),
            ],
            || {
                let opts = sample(&[]);
                assert!(opts.on);
                assert_eq!(opts.name.as_deref(), Some("env"));
                assert_eq!(opts.count, 5);
                assert_eq!(opts.sizes, vec!["2k", "4k"]);
                assert_eq!(opts.nested.depth, 1);
            },
        );
    }

    #[test]
    fn generated_args_carry_help_heading_and_a_pickable_id() {
        let args = Sample::args();
        assert_eq!(args.len(), 5, "four own knobs plus the nested group's one");
        assert!(args.iter().all(|arg| arg.get_help_heading() == Some(T)));
        assert_eq!(Sample::arg("count").get_id(), "count");
        // The doc comment becomes the help, without its final period.
        assert_eq!(
            Sample::arg("on")
                .get_help()
                .map(ToString::to_string)
                .as_deref(),
            Some("A boolean [env: T_ON]")
        );
    }

    #[test]
    fn cli_beats_env_beats_default() {
        with_env(&[("T_REPS", "5"), ("T_BS", "1M 2M")], || {
            let m = cmd().get_matches_from(["t"]);
            assert_eq!(required::<u32>(&m, "reps", "T_REPS").unwrap(), 5);
            assert_eq!(source(&m, "reps", "T_REPS"), Source::Env);
            assert_eq!(
                values::<String>(&m, "bs", "T_BS", ' ').unwrap(),
                vec!["1M", "2M"]
            );

            let m = cmd().get_matches_from(["t", "--reps", "7", "--bs", "8k"]);
            assert_eq!(required::<u32>(&m, "reps", "T_REPS").unwrap(), 7);
            assert_eq!(source(&m, "reps", "T_REPS"), Source::Cli);
            assert_eq!(values::<String>(&m, "bs", "T_BS", ' ').unwrap(), vec!["8k"]);
        });
        with_env(&[], || {
            let m = cmd().get_matches_from(["t"]);
            assert_eq!(required::<u32>(&m, "reps", "T_REPS").unwrap(), 30);
            assert_eq!(source(&m, "reps", "T_REPS"), Source::Default);
            assert_eq!(
                values::<String>(&m, "bs", "T_BS", ' ').unwrap(),
                vec!["4k", "64k"]
            );
        });
    }

    #[test]
    fn invalid_env_only_matters_when_consumed_without_a_cli_override() {
        with_env(&[("T_REPS", "lots")], || {
            let m = cmd().get_matches_from(["t", "--reps", "3"]);
            assert_eq!(required::<u32>(&m, "reps", "T_REPS").unwrap(), 3);
            let m = cmd().get_matches_from(["t"]);
            assert!(matches!(
                required::<u32>(&m, "reps", "T_REPS"),
                Err(Error::Invalid { env: "T_REPS", .. })
            ));
        });
    }

    #[test]
    fn env_flags_never_conflict_with_cli_flags() {
        let quick = ("quick", "T_QUICK");
        let longrun = ("longrun", "T_LONGRUN");
        with_env(&[("T_QUICK", "1")], || {
            let m = cmd().get_matches_from(["t", "--longrun"]);
            assert_eq!(exclusive(&m, quick, longrun).unwrap(), (false, true));
            let m = cmd().get_matches_from(["t"]);
            assert_eq!(exclusive(&m, quick, longrun).unwrap(), (true, false));
            assert!(flag_value(&m, "quick", "T_QUICK"));
        });
        with_env(&[("T_QUICK", "0")], || {
            let m = cmd().get_matches_from(["t"]);
            assert!(!flag_value(&m, "quick", "T_QUICK"));
        });
        with_env(&[("T_QUICK", "1"), ("T_LONGRUN", "yes")], || {
            let m = cmd().get_matches_from(["t"]);
            assert!(matches!(
                exclusive(&m, quick, longrun),
                Err(Error::Conflict { .. })
            ));
        });
        with_env(&[], || {
            let m = cmd().get_matches_from(["t", "--quick", "--longrun"]);
            assert!(matches!(
                exclusive(&m, quick, longrun),
                Err(Error::Conflict { .. })
            ));
        });
    }
}
