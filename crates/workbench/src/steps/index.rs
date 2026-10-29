//! Index files: store the listing of every parsed volume, one volume per commit, then parse
//! wallet files found by name.

use super::wallet_files::WalletFileAnalyzer;
use crate::jobs::context::{Cursor, StepContext};
use serde::{Deserialize, Serialize};
use strata_kernel::Result;

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexCursor {
    /// Volumes whose listing is stored.
    volumes: Vec<u32>,
    entries: usize,
    /// Wallet files found, once that part is done.
    wallets: Option<usize>,
}

impl Cursor for IndexCursor {
    fn note(&self) -> String {
        match self.wallets {
            Some(_) => "nothing left".into(),
            None if self.volumes.is_empty() => "the first volume".into(),
            None => format!("after volume {} ({} entries stored)", super::list(&self.volumes), self.entries),
        }
    }
}

pub(super) fn run(ctx: &StepContext<'_>) -> Result<String> {
    let id = ctx.evidence();
    let layout = ctx.case().layout(id)?;
    let mut cur: IndexCursor = ctx.cursor().unwrap_or_default();
    let volumes: Vec<_> = layout.filesystems().collect();
    ctx.control().begin_at(cur.volumes.len() as u64, volumes.len() as u64 + 1);
    for (vol, fs) in &volumes {
        if cur.volumes.contains(&vol.index) {
            continue;
        }
        if ctx.should_stop() {
            return Ok(String::new());
        }
        ctx.current(&format!("volume {}", vol.index));
        cur.volumes.push(vol.index);
        cur.entries += fs.entries().len();
        let n = ctx.commit(&cur, |w| w.files(id, vol.index, fs.entries()))?;
        ctx.log(format!("volume {}: {n} entries stored", vol.index));
        ctx.control().item_done();
    }
    let wallets = match cur.wallets {
        Some(n) => n,
        None => {
            if ctx.should_stop() {
                return Ok(String::new());
            }
            let found = WalletFileAnalyzer::new(ctx).find()?;
            cur.wallets = Some(found.len());
            ctx.commit(&cur, |w| w.hits(id, &found))?;
            ctx.log(format!("{} wallet files parsed", found.len()));
            found.len()
        }
    };
    ctx.control().item_done();
    Ok(format!("{} entries, {wallets} wallet files", cur.entries))
}
