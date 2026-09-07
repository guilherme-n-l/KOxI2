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

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::util::{self, confirm};

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
    /// What the guest actually presented (perf domain): the block
    /// queue limits and the driver's configfs attributes, read after
    /// the device appeared. Recorded rather than identity-bearing, so
    /// the comparator can say the two sides differ instead of
    /// silently pooling a 64-deep softirq device with a 256-deep
    /// inline one.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub device: BTreeMap<String, String>,
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
    /// numbers must never be compared or pooled. VM-shaped fields
    /// are absent for host-side domains (static).
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smp: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<ArtifactShas>,
    /// Source pins for host-side analysis (static domain).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceIds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fio: Option<FioKnobs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzz: Option<FuzzKnobs>,
    #[serde(default, rename = "static", skip_serializing_if = "Option::is_none")]
    pub static_: Option<StaticKnobs>,
}

/// What the static domain analyzed: the pinned bits, not built ones.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SourceIds {
    /// Kernel source tarball sha (the tree being parsed).
    pub linux: String,
    /// linux-meta mirror commit (the history being mined).
    pub meta_commit: String,
    /// static/classify.toml asset sha (regexes are inputs too).
    pub classify: String,
}

/// Static-analysis scope knobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaticKnobs {
    /// Kernel-tree-relative driver source path.
    pub gitpath: String,
    /// Abstraction-layer paths counted separately.
    pub abstractions: Vec<String>,
    /// Absolute lower bound for mined commits ("" = unbounded).
    pub since: String,
    /// Version of the AST queries / mining logic.
    pub ast_recipe: u32,
}

/// The exact bits measured, straight from the built artifacts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArtifactShas {
    pub kernel: String,
    pub initrd: String,
    pub module: String,
    /// Effective kernel config (the lock's harvested `config`).
    pub kconfig: String,
    /// syz-manager binary (fuzz domain only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syzkaller: Option<String>,
    /// Rendered syzkaller config template (fuzz domain only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub syz_template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FioKnobs {
    pub bs: Vec<String>,
    pub rw: Vec<String>,
    pub qd: Vec<u32>,
    pub size: Vec<String>,
    pub reps: u32,
    pub runtime: u64,
    /// fio ioengine. Identity-bearing: with a synchronous engine fio
    /// silently caps iodepth at 1, so engine changes re-baseline.
    pub engine: String,
}

/// v1 _domain_hash fuzz inputs: campaign count, duration, VM count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuzzKnobs {
    pub campaigns: u32,
    pub hours: f64,
    pub parallel: u32,
}

/// Phase-2 campaign record; `baseline` is the p1 identity hash of
/// the paired C driver (recorded, not symlinked).
// The manifest key is literally `campaign` (the run's name), so the
// field keeps the name clippy would rather it drop.
#[allow(clippy::struct_field_names)]
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
    let text = toml::to_string(identity)?;
    Ok(util::sha256_bytes(text.as_bytes())[..12].to_owned())
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
        fs::create_dir_all(dir)?;
        let text = toml::to_string_pretty(self)?;
        Ok(fs::write(dir.join(MANIFEST), text)?)
    }

    /// Load a result root's manifest; Ok(None) when the dir has none.
    pub fn load(dir: &Path) -> Result<Option<Self>, Error> {
        let path = dir.join(MANIFEST);
        if !path.is_file() {
            return Ok(None);
        }
        let text = fs::read_to_string(&path)?;
        toml::from_str(&text)
            .map(Some)
            .map_err(|err| Error::Parse(path, err))
    }

    pub fn is_complete(dir: &Path) -> bool {
        matches!(Self::load(dir), Ok(Some(manifest)) if manifest.complete)
    }
}

/// Decide what to do with an existing campaign dir: resume when it
/// is the same unfinished measurement, otherwise ask before wiping
/// (v1 _ensure_clean_campaign). Returns false to skip this pair.
pub fn clear_for_campaign(
    dir: &Path,
    manifest: &Manifest,
    assume_yes: bool,
) -> anyhow::Result<bool> {
    if !dir.exists() {
        return Ok(true);
    }
    if matches!(
        Manifest::load(dir)?,
        Some(existing) if !existing.complete && existing.identity == manifest.identity
    ) {
        tracing::info!("resuming unfinished campaign at {}", dir.display());
        return Ok(true);
    }
    let question = format!(
        "campaign data exists at {}; delete and re-run?",
        dir.display()
    );
    // The prompt's own hint covers --yes; add the escape hatch that
    // only makes sense for a campaign dir.
    let wipe = confirm(&question, assume_yes)
        .map_err(|err| anyhow!("{err} (or pick another --campaign)"))?;
    if wipe {
        fs::remove_dir_all(dir)?;
    }
    Ok(wipe)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("results manifest: {0}")]
    Io(#[from] io::Error),
    #[error("serializing manifest: {0}")]
    Toml(#[from] toml::ser::Error),
    #[error("parsing {}: {}", .0.display(), .1)]
    Parse(PathBuf, #[source] toml::de::Error),
}

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
            accel: Some("tcg".to_owned()),
            smp: Some(4),
            memory: Some("4G".to_owned()),
            artifacts: Some(ArtifactShas {
                kernel: "k".repeat(64),
                initrd: "i".repeat(64),
                module: "m".repeat(64),
                kconfig: "c".repeat(64),
                syzkaller: None,
                syz_template: None,
            }),
            source: None,
            fio: Some(FioKnobs {
                bs: vec!["4k".to_owned()],
                rw: vec!["randread".to_owned()],
                qd: vec![1],
                size: vec!["512M".to_owned()],
                reps: 3,
                runtime: 5,
                engine: "io_uring".to_owned(),
            }),
            fuzz: None,
            static_: None,
        }
    }

    #[test]
    fn hash_is_stable_and_identity_sensitive() {
        let base = identity();
        let hash = identity_hash(&base).unwrap();
        assert_eq!(hash.len(), 12);
        assert_eq!(hash, identity_hash(&base).unwrap(), "hash is deterministic");

        let mut kvm = identity();
        kvm.accel = Some("kvm".to_owned());
        assert_ne!(hash, identity_hash(&kvm).unwrap(), "accel is identity");

        let mut knobs = identity();
        knobs.fio.as_mut().unwrap().reps = 30;
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
            device: std::collections::BTreeMap::new(),
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
