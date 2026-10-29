//! Structure scanners for containers, databases and system files.

use super::graded;
use crate::formats::document::{PdfStats, pdf_probe};
use crate::formats::exec::PeImage;
use crate::formats::wallet::{bitcoin_records, refine_bitcoin};
use crate::formats::{bdb as bdb_fmt, ole as ole_fmt, sqlite as sqlite_fmt, system, zip as zip_fmt};
use crate::probe::Probe;
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use memchr::memmem;
use strata_kernel::Confidence;
use strata_kernel::bytes::u32_le;

fn non_zero_pages(data: &[u8], size: usize) -> usize {
    data.chunks(size).skip(1).filter(|p| p.iter().any(|b| *b != 0)).count()
}

pub fn zip(data: &[u8]) -> Option<Probe> {
    let sigs = [b"PK\x03\x04".as_slice(), b"PK\x01\x02", b"PK\x05\x06"];
    if !sigs.iter().any(|s| memmem::find(data, s).is_some()) {
        return None;
    }
    let probe = zip_fmt::analyze(data, Confidence::new(0.8))?;
    let members = probe.inner.iter().filter(|i| i.kind == InnerKind::Member).count();
    let c = graded(0.45, 0.35, members, 4);
    Some(probe.with_confidence(c))
}

pub fn sqlite(data: &[u8]) -> Option<Probe> {
    let mut best: Option<(usize, usize, usize)> = None;
    for ps in bdb_fmt::PAGE_SIZES.iter().copied().filter(|ps| data.len() >= ps * 2) {
        let hits = data.chunks_exact(ps).skip(1).filter(|p| sqlite_fmt::btree_page_plausible(p, 0, ps)).count();
        if hits >= 2 && best.is_none_or(|(_, h, bps)| hits * ps > h * bps) {
            best = Some((ps, hits, non_zero_pages(data, ps)));
        }
    }
    let tables = sqlite_fmt::create_statements(data);
    let (ps, hits, pages) = best?;
    let frac = hits as f32 / pages.max(1) as f32;
    if frac < 0.3 {
        return None;
    }
    let c = Confidence::new(0.4 + 0.3 * frac + if tables.is_empty() { 0.0 } else { 0.1 });
    let mut p = Probe::new(TypeId::Sqlite, c).with_structure(frac);
    p.property("page_size", ps);
    for t in &tables {
        p.item(InnerKind::Table, t.clone(), None);
    }
    if tables.iter().any(|t| t == "main") {
        p = refine_bitcoin(p, &bitcoin_records(data), Confidence::new(0.75));
    }
    Some(p)
}

pub fn bdb(data: &[u8]) -> Option<Probe> {
    let (ps, hits, _) = bdb_fmt::page_evidence(data)?;
    let pages = non_zero_pages(data, ps);
    let frac = hits as f32 / pages.max(1) as f32;
    if frac < 0.3 {
        return None;
    }
    let mut p = Probe::new(TypeId::BerkeleyDb, Confidence::new(0.45 + 0.3 * frac)).with_structure(frac);
    p.property("page_size", ps);
    Some(refine_bitcoin(p, &bitcoin_records(data), Confidence::new(0.75)))
}

pub fn ole(data: &[u8]) -> Option<Probe> {
    let entries: Vec<ole_fmt::DirEntry> = data
        .as_chunks::<128>()
        .0
        .iter()
        .filter(|e| e.get(66).is_some_and(|k| matches!(k, 1 | 2 | 5)))
        .filter_map(|e| ole_fmt::DirEntry::parse(e))
        .collect();
    let root = entries.iter().any(|e| e.kind == 5 && e.name == "Root Entry");
    if entries.len() < 3 || !root && entries.len() < 6 {
        return None;
    }
    let id = ole_fmt::classify_names(entries.iter().map(|e| e.name.as_str()));
    let mut p = Probe::new(id, graded(0.45, 0.3, entries.len() + 4 * usize::from(root), 12)).with_structure(0.5);
    for e in entries.iter().filter(|e| e.kind != 5).take(2000) {
        p.item(InnerKind::Stream, e.name.clone(), (e.kind == 2).then_some(e.size));
    }
    Some(p)
}

pub fn pdf(data: &[u8]) -> Option<Probe> {
    let stats = PdfStats::of(data);
    let evidence = stats.evidence();
    if evidence < 3 {
        return None;
    }
    let mut p = pdf_probe(stats, graded(0.45, 0.35, evidence, 20), None)?;
    if let Some(at) = memmem::find(data, b"%PDF-") {
        p.note(format!("PDF header found at offset {at:#x}"));
    }
    // A headerless fragment's %%EOF is not the file length.
    Some(p.with_len(None))
}

pub fn pe(data: &[u8]) -> Option<Probe> {
    let image = memmem::find_iter(data, b"PE\0\0").take(64).find_map(|pos| PeImage::at(data, pos))?;
    Some(image.into_probe(Confidence::new(0.65)).with_len(None))
}

pub fn mft(data: &[u8]) -> Option<Probe> {
    let records = data.as_chunks::<1024>().0.iter().filter(|r| system::mft_record(r.as_slice()).is_some()).count();
    (records >= 2).then(|| {
        let mut p = Probe::new(TypeId::NtfsMft, graded(0.45, 0.3, records, 16));
        p.item(InnerKind::Object, format!("{records} FILE records"), Some(records as u64));
        p
    })
}

pub fn regf(data: &[u8]) -> Option<Probe> {
    let bins = memmem::find_iter(data, b"hbin")
        .filter(|p| p % 4096 == 0 && u32_le(data, p + 4).is_some_and(|off| u64::from(off) + 4096 == *p as u64))
        .count();
    (bins >= 1).then(|| {
        let mut p = Probe::new(TypeId::RegistryHive, graded(0.5, 0.3, bins, 8));
        p.property("hbins_present", bins);
        p
    })
}

pub fn evtx(data: &[u8]) -> Option<Probe> {
    let chunks = memmem::find_iter(data, b"ElfChnk\0").filter(|p| p % 4096 == 0).count();
    (chunks >= 1).then(|| {
        let mut p = Probe::new(TypeId::Evtx, graded(0.55, 0.25, chunks, 4));
        p.property("chunks_present", chunks);
        p
    })
}
