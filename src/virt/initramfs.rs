//! Assemble the guest initramfs (v1 `kernel/mkinitramfs`) from
//! already-built artifacts: busybox (+ applet symlinks),
//! dropbearmulti (+ tool symlinks), fio, the `virt/init` asset as
//! `/init`, and the ssh client public key as authorized_keys.
//!
//! v1 shortcomings fixed here: the archive is byte-reproducible
//! (sorted entries, epoch mtimes, `cpio --reproducible`, `gzip -n`),
//! the pack is fingerprinted instead of rebuilt every run, auth is
//! public-key only (no /etc/shadow, no hardcoded password hash), and
//! everything static — passwd, host + client keys, authorized_keys —
//! is baked at build time so /init stays minimal. Kernel modules
//! deliberately stay OUT of the image — they ride the 9p rootmnt per
//! run, keeping one generic image for every driver.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, info, warn};

use crate::fetch::{self, Ctx};
use crate::kernel::build::ARTIFACTS_DIR;
use crate::virt::build::{Error, Options, BUSYBOX, DROPBEARMULTI};
use crate::{assets, cmd};

/// Artifact name; also the lock artifact key.
pub const INITRAMFS: &str = "initramfs.cpio.gz";

/// Lock build key.
const TARGET: &str = "initramfs";

/// Bumped when the assembly steps themselves change.
const RECIPE: u32 = 1;

/// Ensure the initramfs is assembled; returns
/// `artifacts/initramfs.cpio.gz`.
pub fn build(ctx: &mut Ctx, opts: &Options) -> Result<PathBuf, Error> {
    if !cfg!(target_os = "linux") {
        return Err(Error::NotLinux);
    }

    let logs = ctx.logs;
    let artifacts = ctx.root.join(ARTIFACTS_DIR);
    let artifact = artifacts.join(INITRAMFS);

    // Inputs: the three binaries (by locked sha), the init asset, and
    // the client public key.
    let ingredient_sha = |name: &str| -> Result<String, Error> {
        ctx.lock
            .artifacts
            .get(name)
            .cloned()
            .ok_or_else(|| Error::MissingPrereq(name.to_owned()))
    };
    let busybox_sha = ingredient_sha(BUSYBOX)?;
    let dropbear_sha = ingredient_sha(DROPBEARMULTI)?;
    let fio_sha = ingredient_sha(crate::block::fio::FIO)?;
    for name in [BUSYBOX, DROPBEARMULTI, crate::block::fio::FIO] {
        if !artifacts.join(name).is_file() {
            return Err(Error::MissingPrereq(name.to_owned()));
        }
    }
    let init = assets::load_locked(ctx.root, ctx.config, "virt/init", ctx.lock)?;
    let pubkey = ensure_client_key(&artifacts, logs)?;
    let pubkey_sha = fetch::sha256(&pubkey, logs)?;
    let host_keys = ensure_host_keys(&artifacts, logs)?;
    let mut host_keys_sha = String::new();
    for key in &host_keys {
        host_keys_sha.push_str(&fetch::sha256(key, logs)?);
        host_keys_sha.push('+');
    }

    let expected = format!(
        "r{RECIPE}:{busybox_sha}:{dropbear_sha}:{fio_sha}:{}:{pubkey_sha}:{host_keys_sha}",
        init.sha256
    );
    if artifact.is_file() && !opts.force && ctx.lock.builds.get(TARGET) == Some(&expected) {
        debug!("initramfs cached at {}", artifact.display());
        return Ok(artifact);
    }

    let tmp_root = ctx.home.join("tmp");
    fs::create_dir_all(&tmp_root)?;
    let scratch = tempfile::Builder::new()
        .prefix("initramfs-")
        .tempdir_in(&tmp_root)?;
    let root = scratch.path().join("rootfs");

    let result = (|| -> Result<(), Error> {
        info!("staging initramfs rootfs");
        for dir in ["bin", "usr/bin", "etc/dropbear", "root/.ssh"] {
            fs::create_dir_all(root.join(dir))?;
        }
        fs::set_permissions(root.join("root"), fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(root.join("root/.ssh"), fs::Permissions::from_mode(0o700))?;

        install(&artifacts.join(BUSYBOX), &root.join("bin/busybox"), 0o755)?;
        install(
            &artifacts.join(DROPBEARMULTI),
            &root.join("bin/dropbearmulti"),
            0o755,
        )?;
        install(
            &artifacts.join(crate::block::fio::FIO),
            &root.join("usr/bin/fio"),
            0o755,
        )?;

        // One symlink per busybox applet (v1 parity), asked of the
        // binary itself so the list always matches the build.
        let mut list = Command::new(root.join("bin/busybox"));
        list.arg("--list");
        let applets = cmd::stdout(list, "busybox-list", logs)?;
        for applet in applets.lines().map(str::trim).filter(|a| !a.is_empty()) {
            if applet == "busybox" {
                continue;
            }
            std::os::unix::fs::symlink("/bin/busybox", root.join("bin").join(applet))?;
        }
        for tool in ["dropbear", "dropbearkey", "scp"] {
            std::os::unix::fs::symlink("/bin/dropbearmulti", root.join("usr/bin").join(tool))?;
        }

        // Static identity baked at build time: dropbear needs
        // getpwnam to resolve root for pubkey auth; password auth is
        // disabled (-s), so no /etc/shadow exists at all. Host keys
        // are pre-generated so init never touches key material.
        fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n")?;
        fs::write(root.join("etc/shells"), "/bin/sh\n")?;
        for key in &host_keys {
            let name = key.file_name().expect("host key file name");
            install(key, &root.join("etc/dropbear").join(name), 0o600)?;
        }

        fs::write(root.join("init"), init.contents.as_bytes())?;
        fs::set_permissions(root.join("init"), fs::Permissions::from_mode(0o755))?;

        fs::copy(&pubkey, root.join("root/.ssh/authorized_keys"))?;
        fs::set_permissions(
            root.join("root/.ssh/authorized_keys"),
            fs::Permissions::from_mode(0o600),
        )?;

        // Reproducible pack: sorted entries, epoch mtimes, no gzip
        // timestamp — identical inputs give identical bytes.
        info!("packing {}", artifact.display());
        fs::create_dir_all(&artifacts)?;
        let mut pack = Command::new("sh");
        pack.arg("-c").arg(format!(
            "cd '{root}' && find . -exec touch -h -d @0 {{}} + && \
             find . | LC_ALL=C sort | cpio -o -H newc --owner 0:0 --reproducible | \
             gzip -n > '{out}'",
            root = root.display(),
            out = artifact.display()
        ));
        cmd::status(pack, "pack-initramfs", logs)?;

        ctx.lock
            .artifacts
            .insert(INITRAMFS.to_owned(), fetch::sha256(&artifact, logs)?);
        ctx.lock.builds.insert(TARGET.to_owned(), expected.clone());
        Ok(())
    })();

    if let Err(err) = result {
        let kept = scratch.keep();
        warn!("staging scratch kept for debugging at {}", kept.display());
        return Err(err);
    }

    info!("initramfs at {}", artifact.display());
    Ok(artifact)
}

fn install(src: &Path, dest: &Path, mode: u32) -> Result<(), Error> {
    fs::copy(src, dest)?;
    fs::set_permissions(dest, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Dropbear host keys, pre-generated with the freshly built
/// dropbearmulti so the guest never generates key material at boot.
fn ensure_host_keys(artifacts: &Path, logs: &Path) -> Result<Vec<PathBuf>, Error> {
    let keys = artifacts.join("keys");
    fs::create_dir_all(&keys)?;
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700))?;
    let mut paths = Vec::new();
    for ktype in ["rsa", "ecdsa", "ed25519"] {
        let key = keys.join(format!("dropbear_{ktype}_host_key"));
        if !key.is_file() {
            info!("generating dropbear {ktype} host key");
            let mut keygen = Command::new(artifacts.join(DROPBEARMULTI));
            keygen
                .arg("dropbearkey")
                .arg("-t")
                .arg(ktype)
                .arg("-f")
                .arg(&key);
            cmd::status(keygen, "dropbearkey", logs)?;
        }
        paths.push(key);
    }
    Ok(paths)
}

/// The ssh client keypair lives with the artifacts (block clean
/// regenerates it; the fingerprint ties authorized_keys to it, so a
/// new key always re-packs the image). Returns the public key path.
fn ensure_client_key(artifacts: &Path, logs: &Path) -> Result<PathBuf, Error> {
    let keys = artifacts.join("keys");
    let key = keys.join("id_ed25519");
    let pubkey = keys.join("id_ed25519.pub");
    if !key.is_file() || !pubkey.is_file() {
        info!("generating ssh client key");
        fs::create_dir_all(&keys)?;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o700))?;
        let _ = fs::remove_file(&key);
        let _ = fs::remove_file(&pubkey);
        let mut keygen = Command::new("ssh-keygen");
        keygen
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-q")
            .arg("-f")
            .arg(&key);
        cmd::status(keygen, "ssh-keygen", logs)?;
    }
    Ok(pubkey)
}
