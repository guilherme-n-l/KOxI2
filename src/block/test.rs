//! `koxi block test` — verify system dependencies before running.

use std::process::ExitCode;

use crate::block::cli::Opts;
use crate::fetch;

/// Tools later phases shell out to (VM, benchmarks, fuzzing); missing
/// ones warn rather than fail so setup-only hosts still pass.
const PHASE_TOOLS: &[&str] = &["qemu-system-x86_64", "ssh", "ssh-keygen", "jq", "go"];

pub fn test(_opts: &Opts) -> ExitCode {
    let mut missing = false;
    for tool in fetch::REQUIRED_TOOLS {
        match fetch::find_tool(tool) {
            Some(path) => println!("ok       {tool} ({})", path.display()),
            None => {
                missing = true;
                println!("MISSING  {tool} (required by setup)");
            }
        }
    }
    for tool in PHASE_TOOLS {
        match fetch::find_tool(tool) {
            Some(path) => println!("ok       {tool} ({})", path.display()),
            None => println!("warn     {tool} not found (needed for perf/fuzz phases)"),
        }
    }
    if missing {
        eprintln!("koxi block test: missing required tools; enter the dev shell (nix develop) or install them");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
