//! Streaming file-start detector for the single-pass scan engine.
//!
//! Magics come from the registry table. Candidates are looked up through per-offset
//! first-byte buckets, so each examined position costs a handful of table lookups. By default
//! only sector-aligned positions are examined (files start on sector/cluster boundaries);
//! `with_alignment(1)` examines every byte for embedded or slack-space files.

use crate::registry::{FileType, Magic, Registry, TypeId};
use serde_json::json;
use strata_kernel::Confidence;
use strata_kernel::scan::{Detector, Hit, HitCategory, HitSink};

/// Bytes handed to a validator when confirming a hit.
const WINDOW: usize = 64 * 1024;
/// Confidence for a strong magic whose validator rejected or could not see the structure.
const UNVALIDATED: f32 = 0.35;
/// Magics at least this long are reported even when the validator rejects the header.
const STANDALONE_MAGIC: usize = 8;
/// Types whose magic marks records inside a larger structure, not carvable file starts.
const NOT_FILE_STARTS: &[TypeId] = &[TypeId::NtfsMft];

#[derive(Debug, Clone, Copy)]
struct Entry {
    spec: &'static FileType,
    magic: Magic,
}

/// Entries sharing one magic offset, bucketed by the magic's first byte.
struct OffsetGroup {
    offset: usize,
    buckets: Vec<Vec<Entry>>,
}

pub struct SignatureDetector {
    groups: Vec<OffsetGroup>,
    alignment: usize,
    /// Unaligned-mode prefilter: HEAD/TAIL flags per leading byte pair.
    pairs: Vec<u8>,
    /// Magics at a non-zero offset (unaligned mode).
    tails: Vec<Entry>,
}

const HEAD: u8 = 1;
const TAIL: u8 = 2;

impl Default for SignatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SignatureDetector {
    pub const ID: &'static str = "identify.signature";

    /// Sector-aligned (512) detector over every registry type that has a header magic.
    pub fn new() -> Self {
        let mut groups: Vec<OffsetGroup> = Vec::new();
        for spec in Registry::all().iter().filter(|t| !NOT_FILE_STARTS.contains(&t.id)) {
            for magic in spec.magics {
                let Some(first) = magic.bytes.first() else { continue };
                let idx = match groups.iter().position(|g| g.offset == magic.offset) {
                    Some(i) => i,
                    None => {
                        groups.push(OffsetGroup { offset: magic.offset, buckets: vec![Vec::new(); 256] });
                        groups.len() - 1
                    }
                };
                groups[idx].buckets[usize::from(*first)].push(Entry { spec, magic: *magic });
            }
        }
        groups.sort_by_key(|g| g.offset);
        let (pairs, tails) = Self::pair_flags(&groups);
        Self { groups, alignment: 512, pairs, tails }
    }

    /// Examine positions that are multiples of `alignment` (1 = every byte).
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = alignment.max(1);
        self
    }

    fn emit_at(&self, chunk: &[u8], pos: usize, base: u64, sink: &mut dyn HitSink) {
        for g in &self.groups {
            if pos + g.offset >= chunk.len() {
                break;
            }
            if self.emit_group(g, chunk, pos, base, sink) {
                return;
            }
        }
    }

    /// Check one offset group at `pos`; true when a hit was emitted.
    fn emit_group(&self, g: &OffsetGroup, chunk: &[u8], pos: usize, base: u64, sink: &mut dyn HitSink) -> bool {
        let Some(b) = chunk.get(pos + g.offset) else { return false };
        for e in &g.buckets[usize::from(*b)] {
            let start = pos + e.magic.offset;
            if chunk.get(start..start + e.magic.bytes.len()) != Some(e.magic.bytes) {
                continue;
            }
            if let Some(hit) = Self::confirm(e, chunk, pos, base) {
                sink.emit(hit);
                return true;
            }
        }
        false
    }

    /// Validate the candidate and build the hit; weak magics need a passing validator.
    fn confirm(e: &Entry, chunk: &[u8], pos: usize, base: u64) -> Option<Hit> {
        let window = &chunk[pos..chunk.len().min(pos + WINDOW)];
        let probe = e.spec.validate(window);
        let (id, confidence, declared_len) = match &probe {
            Some(p) => (p.id(), p.confidence().scaled(0.5 + 0.5 * p.structure()), p.declared_len()),
            // Short magics occur by chance; only long ones stand on their own.
            None if e.magic.bytes.len() < STANDALONE_MAGIC && e.spec.validator.is_some() || e.magic.is_weak() => return None,
            None => (e.spec.id, Confidence::new(UNVALIDATED), None),
        };
        let offset = base + pos as u64;
        let spec = id.spec();
        Some(
            Hit::new(Self::ID, HitCategory::FileSignature, offset, e.magic.end())
                .confidence(confidence)
                .label(spec.name)
                .value(format!("{}@{offset:#x}", spec.key))
                .details(json!({
                    "type_id": spec.key,
                    "category": spec.category,
                    "declared_len": declared_len,
                    "validated": probe.is_some(),
                })),
        )
    }

    /// Type of the first signature confirmed at exactly `pos` of `chunk`, if any.
    pub fn type_at(&self, chunk: &[u8], pos: usize) -> Option<TypeId> {
        let mut hits: Vec<Hit> = Vec::new();
        self.emit_at(chunk, pos, 0, &mut hits);
        hits.first().and_then(|h| h.details.get("type_id")?.as_str().and_then(TypeId::from_key))
    }
}

impl Detector for SignatureDetector {
    fn id(&self) -> &'static str {
        Self::ID
    }

    fn max_match(&self) -> usize {
        WINDOW
    }

    fn scan(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        if self.alignment == 1 {
            self.scan_every_byte(chunk, base, sink);
            return;
        }
        let a = self.alignment as u64;
        let mut pos = ((a - base % a) % a) as usize;
        while pos < chunk.len() {
            self.emit_at(chunk, pos, base, sink);
            pos += self.alignment;
        }
    }
}

impl SignatureDetector {
    /// Unaligned mode: one pass over every byte pair. A 64 Ki-entry flag table says whether an
    /// offset-0 magic starts with this pair (HEAD) or an offset magic does (TAIL).
    fn scan_every_byte(&self, chunk: &[u8], base: u64, sink: &mut dyn HitSink) {
        let Some(head) = self.groups.first().filter(|g| g.offset == 0) else { return };
        for (pos, w) in chunk.windows(2).enumerate() {
            let idx = usize::from(w[0]) << 8 | usize::from(w[1]);
            let flags = self.pairs[idx];
            if flags == 0 {
                continue;
            }
            if flags & HEAD != 0 {
                self.emit_group(head, chunk, pos, base, sink);
            }
            if flags & TAIL != 0 {
                for e in self.tails.iter().filter(|e| e.magic.bytes.starts_with(w)) {
                    if let Some(start) = pos.checked_sub(e.magic.offset)
                        && chunk[pos..].starts_with(e.magic.bytes)
                        && let Some(hit) = Self::confirm(e, chunk, start, base)
                    {
                        sink.emit(hit);
                    }
                }
            }
        }
    }

    fn pair_flags(groups: &[OffsetGroup]) -> (Vec<u8>, Vec<Entry>) {
        let mut pairs = vec![0u8; 1 << 16];
        let mut tails = Vec::new();
        for g in groups {
            for e in g.buckets.iter().flatten() {
                if let [a, b, ..] = e.magic.bytes {
                    pairs[usize::from(*a) << 8 | usize::from(*b)] |= if g.offset == 0 { HEAD } else { TAIL };
                }
                if g.offset > 0 {
                    tails.push(*e);
                }
            }
        }
        (pairs, tails)
    }
}
