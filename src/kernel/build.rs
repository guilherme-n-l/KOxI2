//! Build the kernel image (v1 `kernel/linux-*/build`).
//!
//! For determinism every build starts from a pristine tree: the
//! verified tarball is re-extracted into a mktemp-style scratch dir
//! under `tmp/` in the koxi home, the `linux/config` asset is
//! applied, and only then does make run. Scratch auto-deletes after
//! a successful build and is kept on failure for debugging (it lives
//! under the home rather than the system /tmp, which is often
//! RAM-backed tmpfs — too small for a kernel tree). A build is
//! skipped when the artifact exists and the lock's input fingerprint
//! (recipe version, tarball sha, config sha, toolchain identity) is
//! unchanged. Each build carries a [`Flavor`]: the clean kernel for
//! perf, the instrumented fuzz kernel for fuzzing — one base config
//! asset plus a merged, asserted fragment.

use std::fmt;
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use tracing::{debug, info, warn};

use crate::assets;
use crate::cmd;
use crate::fetch::{self, Ctx};
use crate::lock::LockedSource;

/// Project-relative directory for build outputs. Artifacts are
/// project-scoped (unlike sources) because they derive from
/// project-editable inputs like the kconfig asset.
pub const ARTIFACTS_DIR: &str = "artifacts";

/// The built kernel image name. The clean flavor lands at
/// `artifacts/bzImage`, the fuzz flavor at `artifacts/fuzz/bzImage`.
pub const BZIMAGE: &str = "bzImage";

/// The effective post-olddefconfig .config, harvested per flavor for
/// auditability (and for syzkaller, which wants the config file).
pub const EFFECTIVE_CONFIG: &str = "config";

/// A kernel build variant: the base config asset, plus (for Fuzz) a
/// kconfig fragment asset merged in with the kernel's own
/// merge_config.sh — the upstream mechanism for config variants.
/// Clean is production-like and feeds perf/vm/metal; Fuzz carries
/// the instrumentation set (KASAN, KCOV, DWARF5, fault injection)
/// and feeds fuzzing. Every fragment directive is asserted against
/// the final .config, so the fuzz kernel can never silently lose
/// its instrumentation to a dropped dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Clean,
    Fuzz,
}

impl Flavor {
    fn name(self) -> &'static str {
        match self {
            Flavor::Clean => "clean",
            Flavor::Fuzz => "fuzz",
        }
    }

    /// Lock artifact key prefix ("" for the clean default).
    fn prefix(self) -> &'static str {
        match self {
            Flavor::Clean => "",
            Flavor::Fuzz => "fuzz/",
        }
    }

    /// Kconfig fragment asset merged onto the base config.
    fn fragment(self) -> Option<&'static str> {
        match self {
            Flavor::Clean => None,
            Flavor::Fuzz => Some("linux/fuzz.config"),
        }
    }

    /// This flavor's slice of the artifacts dir.
    pub fn dir(self, artifacts: &Path) -> PathBuf {
        match self {
            Flavor::Clean => artifacts.to_owned(),
            Flavor::Fuzz => artifacts.join("fuzz"),
        }
    }
}

/// koxi.toml sources key for the kernel.
const SOURCE: &str = "linux";

/// Supported build targets, in kbuild vocabulary: target name to
/// (make ARCH value, image path inside the tree).
fn kbuild_arch(target: &str) -> Option<(&'static str, &'static str)> {
    match target {
        "x86_64" => Some(("x86_64", "arch/x86/boot/bzImage")),
        _ => None,
    }
}

/// Bumped when the build steps themselves change, so artifacts built
/// by an older recipe never fingerprint-match the new one.
/// r2: harvest kernel modules into artifacts/.
/// r3: flavor split — KASAN toggled per build, kasan/ namespace.
/// r4: flavors as merged+asserted kconfig fragments (fragment sha in
///     the fingerprint), effective .config harvested per flavor.
const RECIPE: u32 = 4;

pub struct Options {
    pub force: bool,
    /// Only sensible on the Clean flavor: the tuned .config persists
    /// as the shared base override, and clean has no fragment mixed
    /// in to contaminate it.
    pub menuconfig: bool,
    pub skip_build: bool,
    pub flavor: Flavor,
    /// C compiler passed to make as CC= (kbuild ignores the CC env
    /// var, so it must be an explicit make variable).
    pub cc: String,
    /// Build target arch in kbuild vocabulary (see [`kbuild_arch`]).
    pub target: String,
    /// Kernel modules to harvest into artifacts/ after the build.
    pub modules: Vec<Module>,
}

/// A file to harvest from the built tree into artifacts/.
#[derive(Clone)]
pub struct Module {
    pub file: String,
    pub tree_path: std::path::PathBuf,
    /// Required files fail the build when missing (explicit user
    /// requests like [build].extra-artifacts); optional ones warn —
    /// a registry driver may be built-in (=y) or absent from the
    /// config, and phases that need a specific module validate at
    /// their own step.
    pub required: bool,
}

/// Ensure the kernel image for the requested flavor is built;
/// returns its path (`artifacts/bzImage` or `artifacts/kasan/bzImage`).
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let (arch, image_path) =
        kbuild_arch(&opts.target).ok_or_else(|| Error::UnsupportedTarget(opts.target.clone()))?;
    let build_key = match opts.flavor {
        Flavor::Clean => format!("linux-{}", opts.target),
        Flavor::Fuzz => format!("linux-{}-fuzz", opts.target),
    };
    // Lock artifact keys carry the flavor prefix, matching the
    // artifacts/ layout (bzImage vs fuzz/bzImage).
    let key = |file: &str| format!("{}{file}", opts.flavor.prefix());

    let logs = ctx.logs;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let outdir = opts.flavor.dir(&artifacts);
    let artifact = outdir.join(BZIMAGE);

    let kconfig = assets::load_locked(ctx.root, ctx.config, "linux/config", ctx.lock)?;
    let fragment = match opts.flavor.fragment() {
        Some(name) => Some(assets::load_locked(ctx.root, ctx.config, name, ctx.lock)?),
        None => None,
    };
    let (tarball, stem) = fetch::tarball_path(SOURCE, ctx)?;
    let Some(LockedSource::Tarball {
        sha256: source_sha, ..
    }) = ctx.lock.sources.get(SOURCE)
    else {
        return Err(Error::NotFetched);
    };
    let toolchain = toolchain_id(&opts.cc, logs);
    let expected = fingerprint(
        source_sha,
        &kconfig.sha256,
        fragment.as_ref().map(|frag| frag.sha256.as_str()),
        &toolchain,
    );

    let harvested_missing = |file: &str| !outdir.join(file).is_file();
    if artifact.is_file()
        && !opts.force
        && !opts.menuconfig
        && ctx.lock.builds.get(&build_key) == Some(&expected)
        && !harvested_missing(EFFECTIVE_CONFIG)
        && !opts.modules.iter().any(|module| {
            ctx.lock.artifacts.contains_key(&key(&module.file)) && harvested_missing(&module.file)
        })
    {
        debug!(
            "{} kernel image cached at {}",
            opts.flavor.name(),
            artifact.display()
        );
        return Ok(artifact);
    }

    // Pristine tree in a mktemp-style scratch dir: unique per build,
    // auto-deleted on success, kept on failure for debugging. Never
    // build in the shared source extraction.
    let tmp_root = ctx.home.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix(&format!("{stem}-"))
        .tempdir_in(&tmp_root)?;
    let tree = scratch.path().join(&stem);

    let result = (|| -> Result<(), Error> {
        info!("extracting pristine {} for build", stem);
        let mut tar = Command::new("tar");
        tar.arg("-xf").arg(&tarball).arg("-C").arg(scratch.path());
        cmd::status(tar, "tar-build", logs)?;
        if !tree.is_dir() {
            return Err(Error::UnexpectedLayout(tree.clone()));
        }

        fs::write(tree.join(".config"), kconfig.contents.as_bytes())?;

        if let Some(fragment) = &fragment {
            info!("merging the {} flavor fragment", opts.flavor.name());
            fs::write(
                tree.join("koxi.flavor.config"),
                fragment.contents.as_bytes(),
            )?;
            let mut merge = Command::new("sh");
            merge
                .current_dir(&tree)
                .arg("scripts/kconfig/merge_config.sh")
                .arg("-m")
                .arg(".config")
                .arg("koxi.flavor.config");
            cmd::status(merge, "kconfig-merge", logs)?;
        }

        if opts.menuconfig {
            menuconfig(&tree, arch, &opts.cc)?;
        }

        info!("configuring kernel (olddefconfig)");
        cmd::status(
            make(&tree, arch, &opts.cc, &["olddefconfig"]),
            "make-olddefconfig",
            logs,
        )?;

        if let Some(fragment) = &fragment {
            verify_fragment(
                &fragment.contents,
                &fs::read_to_string(tree.join(".config"))?,
            )?;
        }

        if opts.menuconfig {
            // Persist the tuned config as the project override so
            // future runs use it (v1 copied it back into the repo).
            let dest = assets::default_override_path(ctx.root, "linux/config");
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(tree.join(".config"), &dest)?;
            info!("persisted menuconfig result to {}", dest.display());
        }

        if opts.skip_build {
            warn!("kernel build skipped (--skip-build); image may be stale or missing");
            return Ok(());
        }

        let jobs = thread::available_parallelism().map_or(1, |n| n.get());
        info!(
            "building the {} kernel with {jobs} jobs (log: {})",
            opts.flavor.name(),
            logs.join("make-kernel.log").display()
        );
        cmd::status(
            make(&tree, arch, &opts.cc, &["-j", &jobs.to_string()]),
            "make-kernel",
            logs,
        )?;

        let bzimage = tree.join(image_path);
        if !bzimage.is_file() {
            return Err(Error::MissingImage(bzimage));
        }
        fs::create_dir_all(&outdir)?;
        fs::copy(&bzimage, &artifact)?;
        ctx.lock
            .artifacts
            .insert(key(BZIMAGE), fetch::sha256(&artifact, logs)?);

        // The effective config is the audit trail for what the image
        // actually contains (and syzkaller's input later).
        let config_artifact = outdir.join(EFFECTIVE_CONFIG);
        fs::copy(tree.join(".config"), &config_artifact)?;
        ctx.lock.artifacts.insert(
            key(EFFECTIVE_CONFIG),
            fetch::sha256(&config_artifact, logs)?,
        );

        // Harvest the requested modules and lock their hashes; the
        // scratch (and the .kos in it) is gone after this function.
        for module in &opts.modules {
            let built = tree.join(&module.tree_path);
            if !built.is_file() {
                if module.required {
                    return Err(Error::MissingArtifact(module.tree_path.clone()));
                }
                warn!(
                    "module {} not produced by this config (built-in or disabled); skipping",
                    module.file
                );
                ctx.lock.artifacts.remove(&key(&module.file));
                continue;
            }
            let dest = outdir.join(&module.file);
            fs::copy(&built, &dest)?;
            ctx.lock
                .artifacts
                .insert(key(&module.file), fetch::sha256(&dest, logs)?);
            info!("harvested {}", dest.display());
        }

        // Re-hash the config assets actually used (menuconfig may
        // have changed the base) so the recorded fingerprint matches
        // the image.
        let built_with = assets::load_locked(ctx.root, ctx.config, "linux/config", ctx.lock)?;
        let built_frag = match opts.flavor.fragment() {
            Some(name) => Some(assets::load_locked(ctx.root, ctx.config, name, ctx.lock)?),
            None => None,
        };
        let source_sha = match ctx.lock.sources.get(SOURCE) {
            Some(LockedSource::Tarball { sha256, .. }) => sha256.clone(),
            _ => return Err(Error::NotFetched),
        };
        ctx.lock.builds.insert(
            build_key,
            fingerprint(
                &source_sha,
                &built_with.sha256,
                built_frag.as_ref().map(|frag| frag.sha256.as_str()),
                &toolchain,
            ),
        );
        Ok(())
    })();

    if let Err(err) = result {
        let kept = scratch.keep();
        warn!("build scratch kept for debugging at {}", kept.display());
        return Err(err);
    }

    info!("kernel image at {}", artifact.display());
    Ok(artifact)
}

/// Everything that determines the image bytes: recipe version,
/// source, base config (+ flavor fragment when present), and the
/// toolchain that compiles it.
fn fingerprint(
    source_sha: &str,
    config_sha: &str,
    fragment_sha: Option<&str>,
    toolchain: &str,
) -> String {
    let config = match fragment_sha {
        Some(fragment) => format!("{config_sha}+{fragment}"),
        None => config_sha.to_owned(),
    };
    format!("r{RECIPE}:{source_sha}:{config}:{toolchain}")
}

/// Assert every fragment directive survived olddefconfig. A dropped
/// symbol means kconfig vetoed it (missing dependency) — fail loudly
/// instead of shipping a fuzz kernel without its instrumentation.
fn verify_fragment(fragment: &str, config: &str) -> Result<(), Error> {
    let mut dropped = Vec::new();
    for line in fragment.lines().map(str::trim) {
        if let Some(symbol) = line
            .strip_prefix("# CONFIG_")
            .and_then(|rest| rest.strip_suffix(" is not set"))
        {
            let set = format!("CONFIG_{symbol}=");
            if config.lines().any(|have| have.starts_with(&set)) {
                dropped.push(line.to_owned());
            }
        } else if line.starts_with("CONFIG_") && !config.lines().any(|have| have == line) {
            dropped.push(line.to_owned());
        }
    }
    if dropped.is_empty() {
        Ok(())
    } else {
        Err(Error::FragmentDropped(dropped))
    }
}

/// Compiler identity (the configured CC + rustc when present); a
/// toolchain bump must rebuild even with identical source and config.
fn toolchain_id(cc: &str, logs: &Path) -> String {
    let probe = |program: &str, label: &'static str| {
        let mut cmd = Command::new(program);
        cmd.arg("--version");
        crate::cmd::stdout(cmd, label, logs)
            .map(|out| out.lines().next().unwrap_or_default().to_owned())
            .unwrap_or_else(|_| "none".to_owned())
    };
    format!(
        "{}|{}",
        probe(cc, "cc-version"),
        probe("rustc", "rustc-version")
    )
}

fn make(tree: &Path, arch: &str, cc: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new("make");
    cmd.arg("-C")
        .arg(tree)
        .arg(format!("ARCH={arch}"))
        .arg(format!("CC={cc}"))
        .args(args);
    cmd
}

/// Interactive `make menuconfig`, inheriting the terminal.
fn menuconfig(tree: &Path, arch: &str, cc: &str) -> Result<(), Error> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::MenuconfigNeedsTty);
    }
    info!("running menuconfig");
    let status = make(tree, arch, cc, &["menuconfig"])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(Error::Io)?;
    if !status.success() {
        return Err(Error::Menuconfig(status));
    }
    Ok(())
}

#[derive(Debug)]
pub enum Error {
    NotLinux,
    NotFetched,
    UnsupportedTarget(String),
    UnexpectedLayout(PathBuf),
    MissingImage(PathBuf),
    MissingArtifact(PathBuf),
    FragmentDropped(Vec<String>),
    MenuconfigNeedsTty,
    Menuconfig(std::process::ExitStatus),
    Io(std::io::Error),
    Asset(assets::Error),
    Fetch(fetch::Error),
    Cmd(cmd::Error),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<assets::Error> for Error {
    fn from(err: assets::Error) -> Self {
        Error::Asset(err)
    }
}

impl From<fetch::Error> for Error {
    fn from(err: fetch::Error) -> Self {
        Error::Fetch(err)
    }
}

impl From<cmd::Error> for Error {
    fn from(err: cmd::Error) -> Self {
        Error::Cmd(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotLinux => write!(f, "the kernel build requires a Linux host"),
            Error::UnsupportedTarget(target) => {
                write!(f, "unsupported build target {target} (supported: x86_64)")
            }
            Error::NotFetched => {
                write!(f, "the linux source is not locked yet (fetch step missing)")
            }
            Error::UnexpectedLayout(tree) => write!(
                f,
                "extracting the kernel tarball did not produce {}",
                tree.display()
            ),
            Error::MissingArtifact(path) => {
                write!(
                    f,
                    "requested extra artifact {} was not produced by the build",
                    path.display()
                )
            }
            Error::MissingImage(path) => {
                write!(
                    f,
                    "kernel build finished without producing {}",
                    path.display()
                )
            }
            Error::FragmentDropped(lines) => {
                write!(
                    f,
                    "flavor fragment directives vetoed by kconfig (missing \
                     dependency? see the kconfig-merge log): {}",
                    lines.join(", ")
                )
            }
            Error::MenuconfigNeedsTty => {
                write!(f, "--menuconfig needs an interactive terminal")
            }
            Error::Menuconfig(status) => write!(f, "menuconfig failed: {status}"),
            Error::Io(err) => write!(f, "{err}"),
            Error::Asset(err) => write!(f, "{err}"),
            Error::Fetch(err) => write!(f, "{err}"),
            Error::Cmd(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::verify_fragment;

    #[test]
    fn fragment_verification_catches_vetoed_symbols() {
        let config = "CONFIG_KASAN=y\nCONFIG_KCOV_IRQ_AREA_SIZE=0x40000\n# CONFIG_FOO is not set\n";
        verify_fragment(
            "CONFIG_KASAN=y\nCONFIG_KCOV_IRQ_AREA_SIZE=0x40000\n",
            config,
        )
        .unwrap();
        // Comment and blank lines are ignored.
        verify_fragment("# just a comment\n\nCONFIG_KASAN=y\n", config).unwrap();
        // A symbol kconfig dropped (absent or flipped) is fatal.
        assert!(verify_fragment("CONFIG_KCOV=y\n", config).is_err());
        assert!(verify_fragment("CONFIG_KASAN=n\n", config).is_err());
        // Prefix collisions don't count as matches or violations.
        verify_fragment("# CONFIG_KASAN_STACK is not set\n", config).unwrap();
        assert!(verify_fragment("# CONFIG_KASAN is not set\n", config).is_err());
    }
}
