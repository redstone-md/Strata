//! Machines context: the computers a disk served. One [`MachineProfile`] per operating-system
//! installation found on the disk (dual boot, `Windows.old`, a copied system, containers), built
//! from host facts the artefact parsers stored, and a [`UsageReport`] saying when the disk and
//! each installation were in use, built from user activity only.
//!
//! The context reads plain rows ([`FactRow`], [`ActivityRow`], [`LogonRow`], [`ProgramRow`]) so it
//! never depends on the case database; the application layer queries and feeds them.

mod catalog;
mod location;
mod profile;
mod software;
mod usage;
mod values;

pub use catalog::{DiskInputs, DiskMachines, FactRow, LogonRow, Machine};
pub use location::{InstallKey, InstallKind, Location, OsFamily};
pub use profile::{PROFILE_KEYS, Hardware, MachineProfile, Network, NetworkProfile, OsInfo, TimeZone, UsbDevice, UserAccount, first_source, utc_offset};
pub use software::{CryptoSoftware, ProgramEvidence, ProgramRow};
pub use usage::{
    ActivityKind, ActivityRow, KindCount, MonthActivity, NOT_ACTIVITY_PREFIXES, Outlier, POWER_TITLE_INFIXES, POWER_TITLE_PREFIXES, Period,
    UsageAnalyzer, UsageReport, UsageWindow,
};
pub use values::{Provenance, Sourced, Values, When};

#[cfg(test)]
mod tests;
