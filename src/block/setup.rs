use std::path::Path;
use std::process::ExitCode;

use clap::ArgMatches;

use crate::config::{Config, CONFIG_PATH};
use crate::{fuzz, kernel, virt};

use super::fio;

pub fn setup(_matches: &ArgMatches) -> ExitCode {
    let config = match Config::load(Path::new(CONFIG_PATH)) {
        Ok(config) => config,
        Err(err) => return fail(err),
    };

    match kernel::setup::setup(&config) {
        Ok(dir) => ready("kernel", &dir),
        Err(err) => return fail(err),
    }
    match virt::setup::setup(&config) {
        Ok((busybox, dropbear)) => {
            ready("busybox", &busybox);
            ready("dropbear", &dropbear);
        }
        Err(err) => return fail(err),
    }
    match fuzz::setup::setup(&config) {
        Ok(dir) => ready("syzkaller", &dir),
        Err(err) => return fail(err),
    }
    match fio::setup(&config) {
        Ok(dir) => ready("fio", &dir),
        Err(err) => return fail(err),
    }
    ExitCode::SUCCESS
}

fn ready(name: &str, dir: &Path) {
    eprintln!("{name} source ready at {}", dir.display());
}

fn fail(err: impl std::fmt::Display) -> ExitCode {
    eprintln!("koxi block setup: {err}");
    ExitCode::FAILURE
}
