//! Application layer. GUI and CLI talk to Strata only through [`Workbench`].

mod browser;
mod catalog;
mod connections;
mod disk_index;
pub mod explore;
mod insights;
mod jobs;
mod machines;
mod mail;
mod monitor;
mod sector_map;
mod steps;
mod triage;
mod workbench;

pub use catalog::DetectorCatalog;
pub use jobs::context::CheckpointPolicy;
pub use jobs::{CheckpointInfo, Job, JobId, JobKind, JobState, JobView, LogLine, ProgressUnit, eta};
pub use monitor::{JobSample, Monitor, MonitorView, ProcessWatch, ResourceSample, SystemSample};
pub use steps::ArchiveSummary;
pub use disk_index::{DiskIndexView, ScnImport};
pub use sector_map::{SectorCell, SectorMap};
pub use workbench::Workbench;
pub use explore::{DirNode, FileFilter, FileListQuery, FileListing, FileView};
pub use strata_case::{FileRow, FileTypes, SearchRecord, SearchResultRow, TypeCount};
pub use strata_case::{MessageLocation, MessageQuery, MessageRow, MessageState, StoredMessage};
pub use strata_mail::{Attachment, Container as MailContainer, Envelope, Message, Party, join as join_parties};
pub use strata_fs::EntryState as FileEntryState;
pub use strata_identify::Category as TypeCategory;
pub use strata_volume::VolumeOrigin;
pub use strata_search::{Encoding, Pattern, Scope, SearchQuery, Snippet};

pub use strata_case::FactGroup;
pub use strata_case::{
    BrowserFamily, BrowserFilter, BrowserOverview, BrowserQuery, BrowserRow, BrowserSegment, BrowserSpan, CookieSite, Credential, DownloadSource, ProfileKey, ProfileSummary, SiteSummary,
    site_key,
};
pub use strata_machines::{
    ActivityKind, CryptoSoftware, DiskMachines, InstallKind, Machine, MachineProfile, MonthActivity, NetworkProfile, OsFamily, Period as UsagePeriod, Provenance,
    UsageReport, UsbDevice, UserAccount, Values, first_source, utc_offset,
};
pub use strata_case::{EventQuery, HostFact, CorrelationService, EvidenceRecord, FileComplement, HitQuery, SharedFinding, StoredHit};
pub use strata_kernel::scan::HitCategory;
pub use strata_index::{BlockClass, CellContent, IndexStats, Ownership, TextKind};
pub use strata_timeline::{EventKind, TimelineEvent};
pub use strata_chain::{AddressBalance, AddressHistory};
pub use strata_accounts::{Account, AccountSource, Catalogue, IdentifierKind, Service, ServiceEntry, ServiceKind, SourceRef, Years};
pub use strata_leads::{EventRecord, Lead, LeadRef, LeadRule};
pub use strata_graph::{
    ChainState, EdgeKind, Evidence, Flags, Graph, GraphView, Layout, Link, Node, NodeDetail, NodeKey, NodeKind, ViewScope, ViewEdge, ViewNode,
};
pub use strata_kernel::{EvidenceId, Period, Result, Timestamp};
