//! `koxi block test` — verify system dependencies before running.
//!
//! Beyond checking tools exist on PATH, this compiles and *runs* a
//! hello-world (catching toolchain/libc mismatches like a poisoned
//! link path) and compiles against the headers the kernel build
//! needs (openssl, libelf).

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::bail;

use crate::config::Toolchain;
use crate::{cmd, fetch};

/// Tools the kernel/userland build chain shells out to (Linux only).
const KERNEL_TOOLS: &[&str] = &["make", "flex", "bison", "bc", "perl", "pahole"];

/// The binutils `LLVM=1` selects. Required only under that
/// toolchain, and checked here so a missing one fails preflight
/// instead of partway into a kernel build.
const LLVM_TOOLS: &[&str] = &[
    "ld.lld",
    "llvm-ar",
    "llvm-nm",
    "llvm-objcopy",
    "llvm-strip",
    "llvm-readelf",
    "llvm-objdump",
];

/// Tools later phases shell out to; missing ones warn rather than
/// fail so setup-only hosts still pass.
const PHASE_TOOLS: &[&str] = &[
    "qemu-system-x86_64",
    "ssh",
    "ssh-keygen",
    "jq",
    "go",
    "depmod",
    "cpio",
    "rustc",
    "bindgen",
];

pub fn drive(toolchain: Toolchain, cc: &str, logs: &Path) -> anyhow::Result<()> {
    let mut missing = false;

    let mut require = |tool: &str| {
        if let Some(path) = fetch::find_tool(tool) {
            println!("ok       {tool} ({})", path.display());
        } else {
            missing = true;
            println!("MISSING  {tool} (required)");
        }
    };
    for tool in fetch::REQUIRED_TOOLS {
        require(tool);
    }
    if cfg!(target_os = "linux") {
        println!("info     kernel toolchain: {} (CC={cc})", toolchain.name());
        require(cc);
        for tool in KERNEL_TOOLS {
            require(tool);
        }
        if toolchain == Toolchain::Llvm {
            for tool in LLVM_TOOLS {
                require(tool);
            }
        }
    }

    for tool in PHASE_TOOLS {
        match fetch::find_tool(tool) {
            Some(path) => println!("ok       {tool} ({})", path.display()),
            None => println!("warn     {tool} not found (needed for later phases)"),
        }
    }

    if cfg!(target_os = "linux") && !missing {
        match compile_checks(cc, logs) {
            Ok(()) => {}
            Err(err) => {
                missing = true;
                println!("FAILED   {err}");
            }
        }
    }

    if missing {
        bail!("preflight failed; enter the dev shell (nix develop) or install/fix the toolchain");
    }
    println!("preflight ok");
    Ok(())
}

/// Compile and run a hello-world (a binary that segfaults here means
/// a broken toolchain/libc mix, not user error), then compile against
/// the headers the kernel build needs.
fn compile_checks(cc: &str, logs: &Path) -> Result<(), String> {
    let dir = tempfile::tempdir().map_err(|err| format!("creating scratch: {err}"))?;

    let hello = dir.path().join("hello.c");
    let hello_bin = dir.path().join("hello");
    fs::write(&hello, "int main(void) { return 0; }\n")
        .map_err(|err| format!("writing scratch: {err}"))?;
    let mut compile = Command::new(cc);
    compile.arg(&hello).arg("-o").arg(&hello_bin);
    cmd::status(compile, "preflight-cc", logs)
        .map_err(|err| format!("{cc} cannot compile a hello world: {err}"))?;
    let ran = Command::new(&hello_bin)
        .status()
        .map_err(|err| format!("running the compiled hello world: {err}"))?;
    if !ran.success() {
        return Err(format!(
            "a freshly compiled binary failed to run ({ran}): broken toolchain/libc \
             environment (e.g. a poisoned link path)"
        ));
    }
    println!("ok       {cc} compiles and its binaries run");

    let headers = dir.path().join("headers.c");
    fs::write(
        &headers,
        "#include <openssl/bio.h>\n#include <gelf.h>\nint main(void) { return 0; }\n",
    )
    .map_err(|err| format!("writing scratch: {err}"))?;
    let mut compile = Command::new(cc);
    compile
        .arg("-c")
        .arg(&headers)
        .arg("-o")
        .arg(dir.path().join("headers.o"));
    cmd::status(compile, "preflight-headers", logs)
        .map_err(|err| format!("kernel build headers missing (openssl, libelf): {err}"))?;
    println!("ok       kernel build headers (openssl, libelf)");
    Ok(())
}
