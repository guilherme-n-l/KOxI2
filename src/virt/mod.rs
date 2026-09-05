//! VM guest userland infrastructure shared across driver classes:
//! BusyBox (initramfs) and dropbear (ssh).

pub mod build;
pub mod initramfs;
pub mod setup;
