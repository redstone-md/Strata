//! Berkeley DB (btree / hash / queue) — the container of legacy Bitcoin Core `wallet.dat`.

use super::wallet::{bitcoin_records, refine_bitcoin};
use crate::probe::{Probe, ratio};
use crate::registry::TypeId;
use strata_kernel::bytes::{u32_be, u32_le, u8_at};
use strata_kernel::{Confidence, Damage};

const MAGICS: &[(u32, &str)] = &[(0x0005_3162, "btree"), (0x0006_1561, "hash"), (0x0004_2253, "queue")];
pub const PAGE_SIZES: &[usize] = &[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];

/// Metadata page facts.
pub struct Meta {
    pub kind: &'static str,
    pub little_endian: bool,
    pub version: u32,
    pub page_size: usize,
    pub last_page: u32,
}

impl Meta {
    pub fn parse(data: &[u8]) -> Option<Self> {
        for little_endian in [true, false] {
            let r32 = |o| if little_endian { u32_le(data, o) } else { u32_be(data, o) };
            let magic = r32(12)?;
            let Some((_, kind)) = MAGICS.iter().find(|(m, _)| *m == magic) else { continue };
            let page_size = r32(20)? as usize;
            let version = r32(16)?;
            if !PAGE_SIZES.contains(&page_size) || !(2..=12).contains(&version) {
                return None;
            }
            return Some(Self { kind, little_endian, version, page_size, last_page: r32(32)? });
        }
        None
    }

    pub fn declared_len(&self) -> u64 {
        (u64::from(self.last_page) + 1) * self.page_size as u64
    }
}

/// Count pages whose header records their own page number (pgno at offset 8) — survives the
/// loss of the metadata page. Returns (page size, matching pages, pages examined).
pub fn page_evidence(data: &[u8]) -> Option<(usize, usize, usize)> {
    PAGE_SIZES
        .iter()
        .filter(|ps| data.len() >= **ps * 2)
        .map(|ps| {
            let pages = data.len() / ps;
            let hits = (1..pages)
                .filter(|i| {
                    let off = i * ps;
                    u32_le(data, off + 8) == Some(*i as u32) && u8_at(data, off + 25).is_some_and(|t| (1..=13).contains(&t))
                })
                .count();
            (*ps, hits, pages.saturating_sub(1))
        })
        .filter(|(_, hits, _)| *hits >= 2)
        .max_by_key(|(ps, hits, _)| hits * ps)
}

pub fn validate(data: &[u8]) -> Option<Probe> {
    let meta = Meta::parse(data)?;
    let mut p = Probe::certain(TypeId::BerkeleyDb).with_len(Some(meta.declared_len()));
    p.property("access_method", meta.kind);
    p.property("version", meta.version);
    p.property("page_size", meta.page_size);
    p.property("byte_order", if meta.little_endian { "little" } else { "big" });
    // How many of the pages we hold carry a consistent page number?
    let data = data.get(..usize::try_from(meta.declared_len()).unwrap_or(usize::MAX).min(data.len())).unwrap_or(data);
    let pages = data.len() / meta.page_size;
    if pages > 1 && meta.little_endian {
        let (ok, total) = page_evidence(data)
            .filter(|(ps, _, _)| *ps == meta.page_size)
            .map(|(_, ok, total)| (ok, total))
            .unwrap_or((0, pages - 1));
        let zero_pages = (1..pages).filter(|i| data[i * meta.page_size..(i + 1) * meta.page_size].iter().all(|b| *b == 0)).count();
        p = p.with_structure(ratio(ok, total.saturating_sub(zero_pages).max(ok).max(1)).max(0.5));
        if zero_pages > 0 {
            p.damaged(Damage::missing(None, format!("{zero_pages} zero-filled page(s)")));
        }
    }
    let records = bitcoin_records(data);
    Some(refine_bitcoin(p, &records, Confidence::new(0.95)))
}
