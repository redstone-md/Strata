//! Linux artefacts: shell history, GNOME recent files, login records, wallet data folders and
//! system configuration (host name, distribution, time zone, users, networks).

mod history;
mod recent;
mod system;
mod wallet_dirs;
mod wtmp;

pub(crate) use history::ShellHistory;
pub(crate) use recent::RecentlyUsed;
pub(crate) use system::LinuxSystem;
pub(crate) use wallet_dirs::WalletDir;
pub(crate) use wtmp::Wtmp;
