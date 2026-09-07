//! Host fitness for VM campaigns. Smoke runs go anywhere; a real
//! campaign on a host without KVM, or without memory for its VMs,
//! produces numbers that look like data but are not (TCG timing,
//! swap-bound fuzzing), so the perf and fuzz phases refuse such hosts
//! unless explicitly overridden.

use std::fs::{self, OpenOptions};

/// What this host offers to guests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Host {
    pub kvm: bool,
    /// Total physical memory, when the platform exposes it.
    pub memory: Option<u64>,
    pub cpus: usize,
}

/// What a campaign asks of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Demand {
    /// Guests running at once (1 for perf, `--fuzz-parallel` for fuzz).
    pub vms: u64,
    /// Guest memory each, in bytes.
    pub vm_memory: u64,
    pub smp: u64,
}

/// Memory the host itself needs beside the guests.
const HOST_HEADROOM: u64 = 1 << 30;

#[derive(Debug, thiserror::Error)]
pub enum Unfit {
    #[error(
        "/dev/kvm is unavailable: guests would run under TCG, whose numbers are smoke-only \
         (use --quick for a smoke run, or --allow-unfit-host to proceed anyway)"
    )]
    NoKvm,
    #[error(
        "host has {have} of RAM but the campaign wants {need} ({vms} guest(s) x {each} + \
         {headroom} headroom); use --quick, smaller --memory/--fuzz-parallel, or \
         --allow-unfit-host"
    )]
    Memory {
        have: String,
        need: String,
        vms: u64,
        each: String,
        headroom: String,
    },
}

pub fn probe() -> Host {
    Host {
        kvm: kvm_available(),
        memory: total_memory(),
        cpus: crate::util::jobs(),
    }
}

/// Whether the campaign can be trusted on this host.
pub fn check(host: &Host, demand: &Demand) -> Result<(), Unfit> {
    if !host.kvm {
        return Err(Unfit::NoKvm);
    }
    if let Some(have) = host.memory {
        let need = demand
            .vms
            .saturating_mul(demand.vm_memory)
            .saturating_add(HOST_HEADROOM);
        if have < need {
            let size = crate::home::human_size;
            return Err(Unfit::Memory {
                have: size(have),
                need: size(need),
                vms: demand.vms,
                each: size(demand.vm_memory),
                headroom: size(HOST_HEADROOM),
            });
        }
    }
    Ok(())
}

/// The acceleration guests will boot with — part of a result's
/// identity (KVM and TCG numbers must never be pooled).
pub fn accel() -> &'static str {
    if kvm_available() {
        "kvm"
    } else {
        "tcg"
    }
}

pub fn kvm_available() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

/// Total physical memory in bytes (Linux: /proc/meminfo).
pub fn total_memory() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kib| kib.parse::<u64>().ok())
        .map(|kib| kib * 1024)
}

/// qemu `-m` style sizes to bytes: "4G", "512M", "2048" (MiB).
pub fn parse_memory(spec: &str) -> Option<u64> {
    let trimmed = spec.trim();
    let (digits, unit) = match trimmed.chars().last()? {
        'G' | 'g' => (&trimmed[..trimmed.len() - 1], 1u64 << 30),
        'M' | 'm' => (&trimmed[..trimmed.len() - 1], 1u64 << 20),
        'K' | 'k' => (&trimmed[..trimmed.len() - 1], 1u64 << 10),
        _ => (trimmed, 1u64 << 20),
    };
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_specs_parse_like_qemu() {
        assert_eq!(parse_memory("4G"), Some(4 << 30));
        assert_eq!(parse_memory("512M"), Some(512 << 20));
        assert_eq!(parse_memory("2048"), Some(2048 << 20));
        assert_eq!(parse_memory("lots"), None);
        assert_eq!(parse_memory(""), None);
    }

    #[test]
    fn check_rejects_no_kvm_and_thin_memory() {
        let demand = Demand {
            vms: 4,
            vm_memory: 4 << 30,
            smp: 4,
        };
        let fit = Host {
            kvm: true,
            memory: Some(32 << 30),
            cpus: 8,
        };
        check(&fit, &demand).unwrap();

        let tcg = Host { kvm: false, ..fit };
        assert!(matches!(check(&tcg, &demand), Err(Unfit::NoKvm)));

        let thin = Host {
            memory: Some(4 << 30),
            ..fit
        };
        assert!(matches!(check(&thin, &demand), Err(Unfit::Memory { .. })));

        let unknown = Host {
            memory: None,
            ..fit
        };
        check(&unknown, &demand).unwrap();
    }
}
