//! `koxi clean` — home-scoped housekeeping: sweep orphaned build
//! scratch (`$KOXI_HOME/tmp`) left behind by killed builds. A
//! successful build removes its own scratch; project artifacts are
//! `koxi block clean`; the download cache is `--nocache`.

use std::fs;
use std::process::ExitCode;

use clap::Command;

use crate::fetch;

pub fn command() -> Command {
    Command::new("clean")
        .about("Sweep orphaned build scratch from the koxi home (not while a build runs)")
}

pub fn run() -> ExitCode {
    let home = match fetch::koxi_home() {
        Ok(home) => home,
        Err(err) => {
            eprintln!("koxi clean: {err}");
            return ExitCode::FAILURE;
        }
    };
    let tmp = home.join("tmp");
    if tmp.exists() {
        if let Err(err) = fs::remove_dir_all(&tmp) {
            eprintln!("koxi clean: {err}");
            return ExitCode::FAILURE;
        }
        println!("removed {} (orphaned build scratch)", tmp.display());
    } else {
        println!("nothing to clean ({} absent)", tmp.display());
    }
    ExitCode::SUCCESS
}
