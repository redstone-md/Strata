//! Recursive unpacking: every member of every nested archive, under [`UnpackLimits`].

mod limits;
mod naming;

pub use limits::UnpackLimits;

use crate::entry::{ArchiveEntry, ArchiveFormat};
use crate::reader::{ArchiveReader, MemberData, OpenOptions, open_archive_with};
use limits::Budget;
use serde::Serialize;
use std::ops::ControlFlow;
use strata_identify::{Category, Identifier, TypeId, TypeVerdict};
use strata_kernel::{Damage, DamageKind, Result};

/// Bytes of a member identified to decide whether it is itself an archive.
const IDENTIFY_HEAD: usize = 1 << 20;

/// One unpacked member, as handed to the visitor.
pub struct Member<'a> {
    /// `outer.zip!/dir/inner.rar!/file.txt`
    pub path: &'a str,
    /// Virtual paths of the containing archives, outermost first.
    pub chain: &'a [String],
    /// Format of the archive holding this member.
    pub format: ArchiveFormat,
    pub entry: &'a ArchiveEntry,
    /// Recovered bytes; empty when nothing could be read (encrypted, damaged...).
    pub bytes: &'a [u8],
    /// 1 for members of the top-level archive.
    pub depth: usize,
    /// Entry damage plus everything that went wrong while reading.
    pub damage: &'a [Damage],
    /// Content type of `bytes` (with renamed-extension check against the member name).
    pub verdict: Option<&'a TypeVerdict>,
    /// The member was opened as an archive; its own members follow.
    pub unpacked: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct UnpackReport {
    /// Archives opened, the top-level one included.
    pub archives: usize,
    pub members: usize,
    /// Members listed as encrypted that could not be opened.
    pub encrypted: usize,
    /// Members with no recoverable bytes for other reasons.
    pub failed: usize,
    pub expanded: u64,
    /// Members cut by a size, ratio or count limit.
    pub limited: usize,
    /// Archive-level damage, each note prefixed with the archive's virtual path.
    pub damage: Vec<Damage>,
    pub cancelled: bool,
}

type Visit<'v> = dyn FnMut(&Member<'_>) -> ControlFlow<()> + 'v;

pub struct Unpacker {
    limits: UnpackLimits,
    options: OpenOptions,
    identifier: Identifier,
}

impl Unpacker {
    pub fn new(limits: UnpackLimits, options: OpenOptions) -> Self {
        Self { limits, options, identifier: Identifier::new() }
    }

    pub fn limits(&self) -> &UnpackLimits {
        &self.limits
    }

    /// Unpack `bytes` (named `name`, e.g. the file's path) and every archive nested inside.
    /// `hint` is the already identified type, if any. The visitor may stop the walk.
    pub fn unpack(&self, name: &str, bytes: &[u8], hint: Option<TypeId>, visit: &mut Visit<'_>) -> UnpackReport {
        let mut report = UnpackReport::default();
        let Some(reader) = open_archive_with(bytes, hint, &self.options) else {
            report.damage.push(Damage::new(DamageKind::Corrupt, None, format!("{name}: not readable as an archive")));
            return report;
        };
        report.archives = 1;
        let budget = Budget::new(self.limits);
        let mut chain = vec![name.to_string()];
        let mut walk = Walk { report, budget: &budget, visit };
        self.walk(&mut walk, reader.as_ref(), &mut chain, 1, bytes.len() as u64);
        walk.report
    }

    fn walk(&self, w: &mut Walk<'_, '_>, reader: &dyn ArchiveReader, chain: &mut Vec<String>, depth: usize, container_len: u64) {
        let container = chain.last().cloned().unwrap_or_default();
        for d in reader.damage() {
            w.report.damage.push(Damage::new(d.kind(), d.range(), format!("{container}: {}", d.note())));
        }
        let budget = w.budget;
        let limit = |e: &ArchiveEntry| budget.member_limit(e, container_len);
        reader.read_all(&limit, &mut |e, data| {
            if !budget.admit() {
                w.report.limited += 1;
                w.report.damage.push(Damage::new(DamageKind::Missing, None, format!("{container}: member limit reached")));
                return ControlFlow::Break(());
            }
            self.member(w, reader.format(), e, data, limit(e), chain, depth, &container)
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn member(
        &self,
        w: &mut Walk<'_, '_>,
        format: ArchiveFormat,
        e: &ArchiveEntry,
        data: Result<MemberData>,
        limit: usize,
        chain: &mut Vec<String>,
        depth: usize,
        container: &str,
    ) -> ControlFlow<()> {
        let name = if e.path.is_empty() { naming::stream_member(container) } else { e.path.clone() };
        let path = format!("{container}!/{name}");
        let mut damage = e.damage.clone();
        let bytes = match data {
            Ok((bytes, mut d)) => {
                damage.append(&mut d);
                bytes
            }
            Err(err) => {
                if e.encrypted {
                    w.report.encrypted += 1;
                } else {
                    w.report.failed += 1;
                }
                damage.push(Damage::new(DamageKind::Missing, None, err.to_string()));
                Vec::new()
            }
        };
        let cut = bytes.len() >= limit && e.size.is_none_or(|s| s > limit as u64);
        if cut && !bytes.is_empty() || limit == 0 && !e.is_dir && e.size != Some(0) {
            w.report.limited += 1;
            damage.push(Damage::new(DamageKind::Missing, None, format!("expansion stopped at {limit} bytes (size, ratio or total limit)")));
        }
        w.report.members += 1;
        w.report.expanded += bytes.len() as u64;
        w.budget.spend(bytes.len() as u64);
        let verdict = (!bytes.is_empty()).then(|| self.identifier.identify(&bytes[..bytes.len().min(IDENTIFY_HEAD)], Some(&name)));
        let nested = verdict
            .as_ref()
            .filter(|v| v.category == Category::Archive && w.budget.can_descend(depth))
            .and_then(|v| open_archive_with(&bytes, Some(v.file_type), &self.options));
        let member = Member {
            path: &path,
            chain,
            format,
            entry: e,
            bytes: &bytes,
            depth,
            damage: &damage,
            verdict: verdict.as_ref(),
            unpacked: nested.is_some(),
        };
        if (w.visit)(&member).is_break() {
            w.report.cancelled = true;
            return ControlFlow::Break(());
        }
        if let Some(inner) = nested {
            w.report.archives += 1;
            chain.push(path);
            self.walk(w, inner.as_ref(), chain, depth + 1, bytes.len() as u64);
            chain.pop();
        }
        if w.report.cancelled { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    }
}

struct Walk<'b, 'v> {
    report: UnpackReport,
    budget: &'b Budget,
    visit: &'b mut Visit<'v>,
}
