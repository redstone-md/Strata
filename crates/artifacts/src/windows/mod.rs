//! Windows shell and system artefacts: shell links, prefetch, recycle bin, event logs (`.evt`,
//! `.evtx`).

mod evt;
mod evtx;
mod lnk;
mod prefetch;
mod recycle;

pub(crate) use evt::EventLog;
pub(crate) use evtx::Evtx;
pub(crate) use lnk::Lnk;
pub(crate) use prefetch::Prefetch;
pub(crate) use recycle::{Info2, RecycleI};

#[cfg(test)]
pub(crate) use evtx::testkit as evtx_testkit;
#[cfg(test)]
pub(crate) use {evt::build_evt, lnk::build_lnk, prefetch::build_prefetch, recycle::build_info2};
