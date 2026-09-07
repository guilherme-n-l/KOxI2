//! `koxi block setup` — acquire and verify every third-party source.

use anyhow::{anyhow, Context};
use tracing::{info, warn};

use crate::block::cli::{BuildOpts, DEFAULT_CC};
use crate::config::Project;
use crate::fetch::Ctx;
use crate::home::{self, CacheLock};
use crate::lock::{Lock, LOCK_PATH};
use crate::{fuzz, kernel, scratch, virt};

use super::fio;

pub fn drive(build: &BuildOpts, yes: bool, logs: &std::path::Path) -> anyhow::Result<()> {
    let project = Project::locate()?;
    let home = home::koxi_home()?;

    // Every fetch/extract/build below happens under the cache lock,
    // so concurrent runs sharing the home serialize instead of
    // racing on the same tarball or extraction.
    let _cache_lock = CacheLock::acquire(&home)?;
    if build.nocache {
        clear_cache(&home)?;
    }

    let lock_path = project.root.join(LOCK_PATH);
    let mut lock = Lock::load(&lock_path)?.unwrap_or_default();

    let result = {
        let mut ctx = Ctx {
            config: &project.config,
            root: &project.root,
            home: &home,
            lock: &mut lock,
            logs,
            assume_yes: yes,
        };
        build_all(&mut ctx, build)
    };

    // Save even on failure so already-resolved sources stay locked.
    if let Err(err) = lock.save(&lock_path) {
        warn!("could not save {}: {err}", lock_path.display());
    }
    result
}

fn build_all(ctx: &mut Ctx, opts: &BuildOpts) -> anyhow::Result<()> {
    let kernel = kernel::setup::setup(ctx)?;
    info!("kernel source ready at {}", kernel.display());
    let history = kernel::setup::history(ctx)?;
    info!("kernel history mirror ready at {}", history.display());
    // CLI/env --cc beats koxi.toml [build].cc beats the gcc default;
    // target comes from [build].target.
    let cc = opts
        .cc
        .clone()
        .or_else(|| ctx.config.build.cc.clone())
        .unwrap_or_else(|| DEFAULT_CC.to_owned());
    let target = ctx
        .config
        .build
        .target
        .clone()
        .unwrap_or_else(|| "x86_64".to_owned());
    // Harvest every registry driver's module (built-ins warn and are
    // skipped). The explicitly requested [build].extra-artifacts
    // (missing ones fail) ride the fuzz flavor only — they exist for
    // syzkaller symbolization, and a DWARF-laden vmlinux is dead
    // weight next to the clean kernel.
    let modules: Vec<kernel::build::Module> = ctx
        .config
        .block
        .drivers
        .values()
        .map(|driver| kernel::build::Module {
            file: driver.ko.clone(),
            tree_path: driver.ko_dir.join(&driver.ko),
            required: false,
        })
        .collect();
    let mut fuzz_modules = modules.clone();
    for extra in &ctx.config.build.extra_artifacts {
        let file = extra
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                anyhow!(
                    "[build].extra-artifacts entry {} has no file name",
                    extra.display()
                )
            })?;
        fuzz_modules.push(kernel::build::Module {
            file: file.to_owned(),
            tree_path: extra.clone(),
            required: true,
        });
    }
    // Both flavors from the same base config: clean (production-like)
    // for perf/vm/metal, fuzz (KASAN/KCOV/... fragment) for fuzzing.
    // menuconfig runs on the clean build, whose .config is the pure
    // base — the persisted override never absorbs fragment symbols.
    let image = kernel::build::build(
        ctx,
        &kernel::build::Options {
            force: opts.force_build,
            menuconfig: opts.menuconfig,
            skip_build: opts.skip_build,
            cc: cc.clone(),
            target: target.clone(),
            modules: modules.clone(),
            flavor: kernel::build::Flavor::Clean,
        },
    )?;
    info!("kernel image ready at {}", image.display());
    let fuzz_image = kernel::build::build(
        ctx,
        &kernel::build::Options {
            force: opts.force_build,
            menuconfig: false,
            skip_build: opts.skip_build,
            cc,
            target,
            modules: fuzz_modules,
            flavor: kernel::build::Flavor::Fuzz,
        },
    )?;
    info!("fuzz kernel image ready at {}", fuzz_image.display());
    userland(ctx, opts)
}

/// Everything the guest image and the fuzzing/benchmark tooling need,
/// all sharing --force-build.
fn userland(ctx: &mut Ctx, opts: &BuildOpts) -> anyhow::Result<()> {
    let force = virt::build::Options {
        force: opts.force_build,
    };
    let (busybox, dropbear) = virt::setup::setup(ctx)?;
    info!("busybox source ready at {}", busybox.display());
    info!("dropbear source ready at {}", dropbear.display());
    let busybox_bin = virt::build::build(ctx, &force)?;
    info!("busybox ready at {}", busybox_bin.display());
    let dropbear_bin = virt::build::build_dropbear(ctx, &force)?;
    info!("dropbear ready at {}", dropbear_bin.display());
    let syzkaller = fuzz::setup::setup(ctx)?;
    info!("syzkaller source ready at {}", syzkaller.display());
    let syz_bin = fuzz::build::build(ctx, &force)?;
    info!("syzkaller ready at {}", syz_bin.display());
    let fio = fio::setup(ctx)?;
    info!("fio source ready at {}", fio.display());
    let fio_bin = fio::build(ctx, &force)?;
    info!("fio ready at {}", fio_bin.display());
    let initramfs = virt::initramfs::build(ctx, &force)?;
    info!("initramfs ready at {}", initramfs.display());
    Ok(())
}

/// `--nocache`: drop every cache entry (the lock file stays — it is
/// the inode other runs block on) and sweep dead scratch.
fn clear_cache(home: &std::path::Path) -> anyhow::Result<()> {
    let plan = home::gc_plan(home, &std::collections::BTreeSet::new())
        .context("planning the cache sweep")?;
    if !plan.remove.is_empty() {
        info!("clearing {}", home.join(home::CACHE_DIR).display());
        home::gc_apply(&plan)?;
    }
    let swept = scratch::sweep(home)?;
    for live in swept.live {
        warn!("leaving live build scratch {}", live.display());
    }
    Ok(())
}
