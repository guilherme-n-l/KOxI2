//! Results tree — v1's run-broker layout, manifest-first.
//!
//! `results/p1/<c>/<domain>/<hash>/` is a content-addressed baseline
//! cache (change a knob → new hash → fresh baseline, old data kept);
//! `results/p2/<c>::<rs>/<campaign>/<domain>/` holds named campaign
//! runs. v1 encoded provenance only in the dirname hash; here every
//! result root carries a `manifest.toml` whose `[identity]` table IS
//! the hash input — the locked artifact shas, the host + accel tag
//! (KVM and TCG numbers must never pool), and the runner/workload
//! knobs — so directories are self-describing and the compare phase
//! reads manifests instead of re-deriving context. No symlinks: a
//! campaign manifest records its baseline hash, so results survive
//! rsync between machines. Completion is a manifest field, not a
//! separate .done marker. Results are project data under the
//! `--output` root — they belong to neither the lock nor $KOXI_HOME.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::assets;

pub const MANIFEST: &str = "manifest.toml";

/// One result root's record: identity (hashed) plus run state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Flipped to true only when every workload rep is on disk.
    pub complete: bool,
    /// Unix time of the first run against this root.
    pub created: u64,
    /// Workload shuffle seed; a resumed run must reuse it so the
    /// recorded order stays the order that actually ran.
    pub seed: u64,
    /// koxi version that produced the data (informational).
    pub koxi: String,
    pub identity: Identity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p2: Option<Campaign>,
}

/// Everything that makes two measurement sets comparable. Any change
/// here changes the baseline hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub domain: String,
    pub driver: String,
    /// The full in-guest driver contract (runner::driver_spec).
    pub spec: String,
    #[serde(default)]
    pub prep: String,
    /// Host identity + acceleration: laptop/KVM and nixbox/TCG
    /// numbers must never be compared or pooled.
    pub host: String,
    pub accel: String,
    pub smp: u32,
    pub memory: String,
    pub artifacts: ArtifactShas,
    pub fio: FioKnobs,
}

/// The exact bits measured, straight from the built artifacts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactShas {
    pub kernel: String,
    pub initrd: String,
    pub module: String,
    /// Effective kernel config (the lock's harvested `config`).
    pub kconfig: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FioKnobs {
    pub bs: Vec<String>,
    pub rw: Vec<String>,
    pub qd: Vec<u32>,
    pub size: Vec<String>,
    pub reps: u32,
    pub runtime: u64,
}

/// Phase-2 campaign record; `baseline` is the p1 identity hash of
/// the paired C driver (recorded, not symlinked).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Campaign {
    pub campaign: String,
    pub c_driver: String,
    pub rs_driver: String,
    pub baseline: String,
}

/// The dirname hash, derived from the identity's TOML serialization
/// (12 hex chars, like v1's `hash`).
pub fn identity_hash(identity: &Identity) -> Result<String, Error> {
    let text = toml::to_string(identity).map_err(Error::Toml)?;
    let sha = assets::sha256_text(&text).map_err(Error::Sha)?;
    Ok(sha[..12].to_owned())
}

pub fn p1_dir(root: &Path, c_driver: &str, domain: &str, hash: &str) -> PathBuf {
    root.join("p1").join(c_driver).join(domain).join(hash)
}

pub fn p2_dir(
    root: &Path,
    c_driver: &str,
    rs_driver: &str,
    campaign: &str,
    domain: &str,
) -> PathBuf {
    root.join("p2")
        .join(format!("{c_driver}::{rs_driver}"))
        .join(campaign)
        .join(domain)
}

impl Manifest {
    pub fn save(&self, dir: &Path) -> Result<(), Error> {
        fs::create_dir_all(dir).map_err(Error::Io)?;
        let text = toml::to_string_pretty(self).map_err(Error::Toml)?;
        fs::write(dir.join(MANIFEST), text).map_err(Error::Io)
    }

    /// Load a result root's manifest; Ok(None) when the dir has none.
    pub fn load(dir: &Path) -> Result<Option<Self>, Error> {
        let path = dir.join(MANIFEST);
        if !path.is_file() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path).map_err(Error::Io)?;
        toml::from_str(&text)
            .map(Some)
            .map_err(|err| Error::Parse(path, err))
    }

    pub fn is_complete(dir: &Path) -> bool {
        matches!(Self::load(dir), Ok(Some(manifest)) if manifest.complete)
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Toml(toml::ser::Error),
    Parse(PathBuf, toml::de::Error),
    Sha(assets::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => write!(f, "results manifest: {err}"),
            Error::Toml(err) => write!(f, "serializing manifest: {err}"),
            Error::Parse(path, err) => {
                write!(f, "parsing {}: {err}", path.display())
            }
            Error::Sha(err) => write!(f, "hashing identity: {err}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Identity {
        Identity {
            domain: "perf".to_owned(),
            driver: "null_blk".to_owned(),
            spec: "c:null_blk:null_blk.ko:/dev/nullb0:nr_devices=0:nullb/nullb0:power=1".to_owned(),
            prep: String::new(),
            host: "nixbox".to_owned(),
            accel: "tcg".to_owned(),
            smp: 4,
            memory: "4G".to_owned(),
            artifacts: ArtifactShas {
                kernel: "k".repeat(64),
                initrd: "i".repeat(64),
                module: "m".repeat(64),
                kconfig: "c".repeat(64),
            },
            fio: FioKnobs {
                bs: vec!["4k".to_owned()],
                rw: vec!["randread".to_owned()],
                qd: vec![1],
                size: vec!["512M".to_owned()],
                reps: 3,
                runtime: 5,
            },
        }
    }

    #[test]
    fn hash_is_stable_and_identity_sensitive() {
        let base = identity();
        let hash = identity_hash(&base).unwrap();
        assert_eq!(hash.len(), 12);
        assert_eq!(hash, identity_hash(&base).unwrap(), "hash is deterministic");

        let mut kvm = identity();
        kvm.accel = "kvm".to_owned();
        assert_ne!(hash, identity_hash(&kvm).unwrap(), "accel is identity");

        let mut knobs = identity();
        knobs.fio.reps = 30;
        assert_ne!(
            hash,
            identity_hash(&knobs).unwrap(),
            "fio knobs are identity"
        );
    }

    #[test]
    fn manifest_round_trips_and_tracks_completion() {
        let dir = std::env::temp_dir().join(format!("koxi-results-test-{}", std::process::id()));
        let manifest = Manifest {
            complete: false,
            created: 1,
            seed: 42,
            koxi: "test".to_owned(),
            identity: identity(),
            p2: Some(Campaign {
                campaign: "trial".to_owned(),
                c_driver: "null_blk".to_owned(),
                rs_driver: "rnull".to_owned(),
                baseline: "abc123def456".to_owned(),
            }),
        };
        manifest.save(&dir).unwrap();
        assert!(!Manifest::is_complete(&dir));
        let loaded = Manifest::load(&dir).unwrap().unwrap();
        assert_eq!(loaded, manifest);

        let mut done = loaded;
        done.complete = true;
        done.save(&dir).unwrap();
        assert!(Manifest::is_complete(&dir));

        assert!(Manifest::load(&dir.join("nope")).unwrap().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
