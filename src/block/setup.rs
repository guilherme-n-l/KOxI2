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

pub fn setup(opts: &Opts) -> ExitCode {
    let project = match Project::locate() {
        Ok(project) => project,
        Err(err) => return fail(err),
    };
    let home = match fetch::koxi_home() {
        Ok(home) => home,
        Err(err) => return fail(err),
    };

    let out = home.join(fetch::OUT_DIR);
    if opts.nocache && out.exists() {
        info!("clearing cache {}", out.display());
        if let Err(err) = clear_cache(&out) {
            return fail(err);
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
    let image = kernel::build::build(
        ctx,
        &kernel::build::Options {
            force: opts.force_build,
            menuconfig: opts.menuconfig,
            skip_build: opts.skip_build,
            cc: opts.cc.clone(),
        },
    )?;
    info!("kernel image ready at {}", image.display());
    let (busybox, dropbear) = virt::setup::setup(ctx)?;
    info!("busybox source ready at {}", busybox.display());
    info!("dropbear source ready at {}", dropbear.display());
    let syzkaller = fuzz::setup::setup(ctx)?;
    info!("syzkaller source ready at {}", syzkaller.display());
    let fio = fio::setup(ctx)?;
    info!("fio source ready at {}", fio.display());
    Ok(())
}

/// Remove cached tarballs and trees but keep logs — `run.log` is open
/// for writing at this point, and `logs/` is history, not cache.
fn clear_cache(out: &std::path::Path) -> std::io::Result<()> {
    for entry in fs::read_dir(out)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_name() == "logs" || path.extension().is_some_and(|ext| ext == "log") {
            continue;
        }
        if entry.file_type()?.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn fail(err: impl std::fmt::Display) -> ExitCode {
    error!("koxi block setup: {err}");
    ExitCode::FAILURE
}
