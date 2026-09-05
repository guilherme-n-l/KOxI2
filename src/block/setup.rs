//! `koxi block setup` — acquire and verify every third-party source.

use std::fs;
use std::process::ExitCode;

use tracing::{error, info, warn};

use crate::block::cli::Opts;
use crate::config::Project;
use crate::fetch::{self, Ctx};
use crate::lock::{Lock, LOCK_PATH};
use crate::{fuzz, kernel, virt};

use super::fio;

pub fn setup(opts: &Opts, logs: &std::path::Path) -> ExitCode {
    let project = match Project::locate() {
        Ok(project) => project,
        Err(err) => return fail(err),
    };
    let home = match fetch::koxi_home() {
        Ok(home) => home,
        Err(err) => return fail(err),
    };

    if opts.nocache {
        for sub in [fetch::CACHE_DIR, "tmp"] {
            let dir = home.join(sub);
            if dir.exists() {
                info!("clearing {}", dir.display());
                if let Err(err) = fs::remove_dir_all(&dir) {
                    return fail(err);
                }
            }
        }
    }

    let lock_path = project.root.join(LOCK_PATH);
    let mut lock = match Lock::load(&lock_path) {
        Ok(lock) => lock.unwrap_or_default(),
        Err(err) => return fail(err),
    };

    let result = {
        let mut ctx = Ctx {
            config: &project.config,
            root: &project.root,
            home: &home,
            lock: &mut lock,
            logs,
            assume_yes: opts.yes,
        };
        drive(&mut ctx, opts)
    };

    // Save even on failure so already-resolved sources stay locked.
    if let Err(err) = lock.save(&lock_path) {
        warn!("could not save {}: {err}", lock_path.display());
    }

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => fail(err),
    }
}

fn drive(ctx: &mut Ctx, opts: &Opts) -> Result<(), Box<dyn std::error::Error>> {
    let kernel = kernel::setup::setup(ctx)?;
    info!("kernel source ready at {}", kernel.display());
    let history = kernel::setup::history(ctx)?;
    info!("kernel history mirror ready at {}", history.display());
    // CLI/env --cc beats koxi.toml [build].cc beats the gcc default;
    // target comes from [build].target.
    let cc = if opts.cc_from_cli {
        opts.cc.clone()
    } else {
        ctx.config
            .build
            .cc
            .clone()
            .unwrap_or_else(|| opts.cc.clone())
    };
    let target = ctx
        .config
        .build
        .target
        .clone()
        .unwrap_or_else(|| "x86_64".to_owned());
    // Harvest every registry driver's module (built-ins warn and are
    // skipped) plus the explicitly requested [build].extra-artifacts
    // (missing ones fail).
    let mut modules: Vec<kernel::build::Module> = ctx
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
    for extra in &ctx.config.build.extra_artifacts {
        let Some(file) = extra.file_name().and_then(|name| name.to_str()) else {
            return Err(format!(
                "[build].extra-artifacts entry {} has no file name",
                extra.display()
            )
            .into());
        };
        modules.push(kernel::build::Module {
            file: file.to_owned(),
            tree_path: extra.clone(),
            required: true,
        });
    }
    let image = kernel::build::build(
        ctx,
        &kernel::build::Options {
            force: opts.force_build,
            menuconfig: opts.menuconfig,
            skip_build: opts.skip_build,
            cc,
            target,
            modules,
        },
    )?;
    info!("kernel image ready at {}", image.display());
    let (busybox, dropbear) = virt::setup::setup(ctx)?;
    info!("busybox source ready at {}", busybox.display());
    info!("dropbear source ready at {}", dropbear.display());
    let busybox_bin = virt::build::build(
        ctx,
        &virt::build::Options {
            force: opts.force_build,
        },
    )?;
    info!("busybox ready at {}", busybox_bin.display());
    let dropbear_bin = virt::build::build_dropbear(
        ctx,
        &virt::build::Options {
            force: opts.force_build,
        },
    )?;
    info!("dropbear ready at {}", dropbear_bin.display());
    let syzkaller = fuzz::setup::setup(ctx)?;
    info!("syzkaller source ready at {}", syzkaller.display());
    let fio = fio::setup(ctx)?;
    info!("fio source ready at {}", fio.display());
    Ok(())
}

fn fail(err: impl std::fmt::Display) -> ExitCode {
    error!("koxi block setup: {err}");
    ExitCode::FAILURE
}
