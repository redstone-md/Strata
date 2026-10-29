//! PDF and RTF.

use crate::probe::Probe;
use crate::registry::TypeId;
use crate::verdict::InnerKind;
use crate::view::ByteView;
use memchr::memmem;
use strata_kernel::{Confidence, Damage};

/// Structural counts of a (possibly partial) PDF body.
#[derive(Debug, Default, Clone, Copy)]
pub struct PdfStats {
    pub objects: usize,
    pub endobjs: usize,
    pub streams: usize,
    pub pages: usize,
    pub xrefs: usize,
    pub trailers: usize,
    pub eofs: usize,
    pub encrypted: bool,
    pub last_eof_end: Option<usize>,
}

impl PdfStats {
    pub fn of(data: &[u8]) -> Self {
        let count = |n: &[u8]| memmem::find_iter(data, n).count();
        let objects = memmem::find_iter(data, b" obj")
            .filter(|p| p.checked_sub(1).and_then(|i| data.get(i)).is_some_and(u8::is_ascii_digit))
            .count();
        let pages = [b"/Type/Page".as_slice(), b"/Type /Page"]
            .iter()
            .flat_map(|n| memmem::find_iter(data, n).map(move |p| p + n.len()))
            .filter(|end| data.get(*end) != Some(&b's'))
            .count();
        let last_eof_end = memmem::rfind(data, b"%%EOF").map(|p| {
            let mut end = p + 5;
            while matches!(data.get(end), Some(b'\r' | b'\n')) && end < p + 7 {
                end += 1;
            }
            end
        });
        Self {
            objects,
            endobjs: count(b"endobj"),
            streams: count(b"endstream"),
            pages,
            xrefs: count(b"xref"),
            trailers: count(b"trailer"),
            eofs: count(b"%%EOF"),
            encrypted: memmem::find(data, b"/Encrypt").is_some(),
            last_eof_end,
        }
    }

    /// Amount of independent PDF evidence (0 when none).
    pub fn evidence(&self) -> usize {
        self.objects.min(self.endobjs) + self.streams.min(self.objects) + self.xrefs + self.trailers + self.eofs
    }
}

pub fn pdf(data: &[u8]) -> Option<Probe> {
    let version = data.get(5..8).filter(|v| v[0].is_ascii_digit() && v[1] == b'.' && v[2].is_ascii_digit())?;
    let stats = PdfStats::of(data);
    pdf_probe(stats, Confidence::new(0.95), Some(version))
}

/// Shared by the header validator and the headerless scanner.
pub fn pdf_probe(stats: PdfStats, base: Confidence, version: Option<&[u8]>) -> Option<Probe> {
    let mut p = Probe::new(TypeId::Pdf, base).with_len(stats.last_eof_end.map(|e| e as u64));
    if let Some(v) = version {
        p.property("version", String::from_utf8_lossy(v));
    }
    let structure = if stats.objects == 0 {
        0.0
    } else {
        stats.objects.min(stats.endobjs) as f32 / stats.objects.max(stats.endobjs) as f32
    };
    p = p.with_structure(structure);
    p.item(InnerKind::Object, format!("{} objects", stats.objects), Some(stats.objects as u64));
    if stats.pages > 0 {
        p.item(InnerKind::Object, format!("{} pages", stats.pages), Some(stats.pages as u64));
    }
    if stats.encrypted {
        p.note("document is encrypted");
    }
    if stats.eofs == 0 {
        p.damaged(Damage::truncated("no %%EOF marker"));
    }
    if stats.eofs > 1 {
        p.note(format!("{} incremental updates", stats.eofs - 1));
    }
    Some(p)
}

/// End of a PDF starting at 0: the last `%%EOF` that is followed by more PDF (incremental
/// update) or by nothing PDF-like.
pub fn pdf_end(view: &dyn ByteView, cap: u64) -> Option<u64> {
    let mut end = None;
    let mut from = 0;
    while let Some(at) = view.find(b"%%EOF", from, cap) {
        let mut e = at + 5;
        let tail = view.bytes(e, 64);
        let eol = tail.iter().take(2).take_while(|b| matches!(b, b'\r' | b'\n')).count();
        e += eol as u64;
        end = Some(e);
        from = at + 5;
        let next = &tail[eol..];
        let continues = next.starts_with(b"%") || next.first().is_some_and(u8::is_ascii_digit) || next.starts_with(b"xref");
        if !continues {
            break;
        }
    }
    end
}

pub fn rtf(data: &[u8]) -> Option<Probe> {
    if !data.starts_with(b"{\\rtf") {
        return None;
    }
    let mut depth = 0i64;
    let mut end = None;
    let mut escaped = false;
    for (i, b) in data.iter().enumerate() {
        match (*b, escaped) {
            (b'\\', false) => escaped = true,
            (b'{', false) => depth += 1,
            (b'}', false) => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i as u64 + 1);
                    break;
                }
            }
            (0, _) => break,
            _ => escaped = false,
        }
        if *b != b'\\' {
            escaped = false;
        }
    }
    let mut p = Probe::certain(TypeId::Rtf).with_len(end);
    if end.is_none() {
        p.damaged(Damage::truncated("RTF group never closes"));
        p = p.with_structure(0.6);
    }
    Some(p)
}
