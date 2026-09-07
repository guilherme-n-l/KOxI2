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

use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tracing::{debug, info, warn};

use crate::assets::{self, Loaded};
use crate::cmd;
use crate::fetch::{self, Ctx};
use crate::lock::{Lock, LockedSource};
use crate::scratch::Scratch;
use crate::util;

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

    /// Lock artifact key for a harvested file: the flavor prefix
    /// matches the artifacts/ layout (bzImage vs fuzz/bzImage).
    fn key(self, file: &str) -> String {
        format!("{}{file}", self.prefix())
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
    pub tree_path: PathBuf,
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

    let inputs = Inputs::resolve(ctx, opts)?;
    if inputs.cached(ctx, opts) {
        debug!(
            "{} kernel image cached at {}",
            opts.flavor.name(),
            inputs.artifact.display()
        );
        return Ok(inputs.artifact);
    }

    // Pristine tree in a mktemp-style scratch dir: unique per build,
    // auto-deleted on success, kept on failure for debugging. Never
    // build in the shared source extraction.
    let logs = ctx.logs;
    Scratch::new(ctx.home, &format!("{}-", inputs.stem))?.run(|dir| {
        let tree = fetch::extract_pristine(&inputs.tarball, dir, &inputs.stem, logs)?;
        configure(ctx, opts, &inputs, &tree)?;
        if opts.skip_build {
            warn!("kernel build skipped (--skip-build); image may be stale or missing");
            return Ok(());
        }
        compile(opts, &inputs, &tree, logs)?;
        harvest(ctx, opts, &inputs, &tree)
    })?;

    info!("kernel image at {}", inputs.artifact.display());
    Ok(inputs.artifact)
}

/// Everything a build derives from its inputs before touching a
/// scratch tree: where the image lands, the locked config assets,
/// and the fingerprint the lock must match to skip the build.
struct Inputs {
    arch: &'static str,
    image_path: &'static str,
    build_key: String,
    outdir: PathBuf,
    artifact: PathBuf,
    kconfig: Loaded,
    fragment: Option<Loaded>,
    tarball: PathBuf,
    stem: String,
    toolchain: String,
    expected: String,
}

impl Inputs {
    fn resolve(ctx: &mut Ctx, opts: &Options) -> Result<Self, Error> {
        let (arch, image_path) = kbuild_arch(&opts.target)
            .ok_or_else(|| Error::UnsupportedTarget(opts.target.clone()))?;
        let build_key = match opts.flavor {
            Flavor::Clean => format!("linux-{}", opts.target),
            Flavor::Fuzz => format!("linux-{}-fuzz", opts.target),
        };
        let outdir = opts.flavor.dir(&ctx.root.join(ARTIFACTS_DIR));
        let artifact = outdir.join(BZIMAGE);

        let (kconfig, fragment) = load_configs(ctx, opts.flavor)?;
        let (tarball, stem) = fetch::tarball_path(SOURCE, ctx)?;
        let toolchain = toolchain_id(&opts.cc);
        let expected = fingerprint(
            &locked_source_sha(ctx.lock)?,
            &kconfig.sha256,
            fragment.as_ref().map(|frag| frag.sha256.as_str()),
            &toolchain,
        );
        Ok(Self {
            arch,
            image_path,
            build_key,
            outdir,
            artifact,
            kconfig,
            fragment,
            tarball,
            stem,
            toolchain,
            expected,
        })
    }

    /// Whether the lock and artifacts/ already hold this exact build.
    fn cached(&self, ctx: &Ctx, opts: &Options) -> bool {
        let harvested_missing = |file: &str| !self.outdir.join(file).is_file();
        // A required file (extra-artifact) that the lock has never seen
        // busts the cache too — it only exists inside the build scratch,
        // so a fresh request needs a fresh build.
        let module_missing = |module: &Module| {
            let known = ctx
                .lock
                .artifacts
                .contains_key(&opts.flavor.key(&module.file));
            (known && harvested_missing(&module.file))
                || (module.required && (!known || harvested_missing(&module.file)))
        };
        self.artifact.is_file()
            && !opts.force
            && !opts.menuconfig
            && ctx.lock.builds.get(&self.build_key) == Some(&self.expected)
            && !harvested_missing(EFFECTIVE_CONFIG)
            && !opts.modules.iter().any(module_missing)
    }
}

/// The base config asset and the flavor's fragment, both locked.
fn load_configs(ctx: &mut Ctx, flavor: Flavor) -> Result<(Loaded, Option<Loaded>), Error> {
    let kconfig = assets::load_locked(ctx.root, ctx.config, "linux/config", ctx.lock)?;
    let fragment = flavor
        .fragment()
        .map(|name| assets::load_locked(ctx.root, ctx.config, name, ctx.lock))
        .transpose()?;
    Ok((kconfig, fragment))
}

fn locked_source_sha(lock: &Lock) -> Result<String, Error> {
    match lock.sources.get(SOURCE) {
        Some(LockedSource::Tarball { sha256, .. }) => Ok(sha256.clone()),
        _ => Err(Error::NotFetched),
    }
}

/// Apply the base config (+ the merged flavor fragment), run
/// menuconfig on request, settle with olddefconfig, and assert the
/// fragment survived. A menuconfig result persists as the project
/// override.
fn configure(ctx: &Ctx, opts: &Options, inputs: &Inputs, tree: &Path) -> Result<(), Error> {
    let logs = ctx.logs;
    fs::write(tree.join(".config"), inputs.kconfig.contents.as_bytes())?;

    if let Some(fragment) = &inputs.fragment {
        info!("merging the {} flavor fragment", opts.flavor.name());
        fs::write(
            tree.join("koxi.flavor.config"),
            fragment.contents.as_bytes(),
        )?;
        let mut merge = Command::new("sh");
        merge
            .current_dir(tree)
            .arg("scripts/kconfig/merge_config.sh")
            .arg("-m")
            .arg(".config")
            .arg("koxi.flavor.config");
        cmd::status(merge, "kconfig-merge", logs)?;
    }

    if opts.menuconfig {
        menuconfig(tree, inputs.arch, &opts.cc)?;
    }

    info!("configuring kernel (olddefconfig)");
    cmd::status(
        make(tree, inputs.arch, &opts.cc, &["olddefconfig"]),
        "make-olddefconfig",
        logs,
    )?;

    if let Some(fragment) = &inputs.fragment {
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
    Ok(())
}

fn compile(opts: &Options, inputs: &Inputs, tree: &Path, logs: &Path) -> Result<(), Error> {
    let jobs = util::jobs();
    info!(
        "building the {} kernel with {jobs} jobs (log: {})",
        opts.flavor.name(),
        logs.join("make-kernel.log").display()
    );
    Ok(cmd::status(
        make(tree, inputs.arch, &opts.cc, &["-j", &jobs.to_string()]),
        "make-kernel",
        logs,
    )?)
}

/// Copy the image, the effective config, and the requested modules
/// into artifacts/, locking their hashes and the build fingerprint.
fn harvest(ctx: &mut Ctx, opts: &Options, inputs: &Inputs, tree: &Path) -> Result<(), Error> {
    let key = |file: &str| opts.flavor.key(file);
    let bzimage = tree.join(inputs.image_path);
    if !bzimage.is_file() {
        return Err(Error::MissingImage(bzimage));
    }
    fs::create_dir_all(&inputs.outdir)?;
    fs::copy(&bzimage, &inputs.artifact)?;
    ctx.lock
        .artifacts
        .insert(key(BZIMAGE), util::sha256_file(&inputs.artifact)?);

    // The effective config is the audit trail for what the image
    // actually contains (and syzkaller's input later).
    let config_artifact = inputs.outdir.join(EFFECTIVE_CONFIG);
    fs::copy(tree.join(".config"), &config_artifact)?;
    ctx.lock
        .artifacts
        .insert(key(EFFECTIVE_CONFIG), util::sha256_file(&config_artifact)?);

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
        let dest = inputs.outdir.join(&module.file);
        fs::copy(&built, &dest)?;
        ctx.lock
            .artifacts
            .insert(key(&module.file), util::sha256_file(&dest)?);
        info!("harvested {}", dest.display());
    }

    // Re-hash the config assets actually used (menuconfig may
    // have changed the base) so the recorded fingerprint matches
    // the image.
    let (built_with, built_frag) = load_configs(ctx, opts.flavor)?;
    ctx.lock.builds.insert(
        inputs.build_key.clone(),
        fingerprint(
            &locked_source_sha(ctx.lock)?,
            &built_with.sha256,
            built_frag.as_ref().map(|frag| frag.sha256.as_str()),
            &inputs.toolchain,
        ),
    );
    Ok(())
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
fn toolchain_id(cc: &str) -> String {
    format!(
        "{}|{}",
        util::probe_version(cc, &["--version"], "none"),
        util::probe_version("rustc", &["--version"], "none")
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
        .status()?;
    if !status.success() {
        return Err(Error::Menuconfig(status));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the kernel build requires a Linux host")]
    NotLinux,
    #[error("the linux source is not locked yet (fetch step missing)")]
    NotFetched,
    #[error("unsupported build target {0} (supported: x86_64)")]
    UnsupportedTarget(String),
    #[error("kernel build finished without producing {}", .0.display())]
    MissingImage(PathBuf),
    #[error("requested extra artifact {} was not produced by the build", .0.display())]
    MissingArtifact(PathBuf),
    #[error(
        "flavor fragment directives vetoed by kconfig (missing dependency? see the \
         kconfig-merge log): {}",
        .0.join(", ")
    )]
    FragmentDropped(Vec<String>),
    #[error("--menuconfig needs an interactive terminal")]
    MenuconfigNeedsTty,
    #[error("menuconfig failed: {0}")]
    Menuconfig(std::process::ExitStatus),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Asset(#[from] assets::Error),
    #[error(transparent)]
    Fetch(#[from] fetch::Error),
    #[error(transparent)]
    Cmd(#[from] cmd::Error),
}

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
