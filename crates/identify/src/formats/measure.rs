//! "How long is the file that starts here?" — each type's own size information, used by the
//! carver. Header-declared sizes come from the type's validator; chain/footer formats are
//! walked over a [`ByteView`].

use super::{archive, document, image, media, system, zip};
use crate::registry::TypeId;
use crate::view::{ByteView, SubView};
use serde::{Deserialize, Serialize};

/// Bytes read from the start for header-declared sizes (OLE FAT, PE section table, ISO PVD...).
const HEAD: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasureMethod {
    /// A size field in the header.
    Declared,
    /// Walking the format's block/chunk chain to its end marker.
    Walked,
    /// Searching for the format's footer.
    Footer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measured {
    pub len: u64,
    pub method: MeasureMethod,
    /// The format declares more bytes than the cap (or the view) allows.
    pub clipped: bool,
}

/// Measure the file of type `id` starting at offset 0 of `view`, looking at most `cap` bytes.
pub fn measure(id: TypeId, view: &dyn ByteView, cap: u64) -> Option<Measured> {
    let cap = cap.min(view.view_len());
    let bounded = SubView::new(view, 0, cap);
    let v: &dyn ByteView = &bounded;
    let walked = |len: Option<u64>| len.map(|l| (l, MeasureMethod::Walked));
    let found = match id.spec().parent.filter(|p| *p == TypeId::Zip).unwrap_or(id) {
        TypeId::Zip => zip::end_of_archive(v, cap).map(|l| (l, MeasureMethod::Footer)),
        TypeId::Png => walked(image::png_walk(v).end),
        TypeId::Jpeg => walked(image::jpeg_walk(v).end),
        TypeId::Gif => walked(image::gif_walk(v).end),
        TypeId::Pdf => document::pdf_end(v, cap).map(|l| (l, MeasureMethod::Footer)),
        TypeId::Gzip => walked(archive::gzip_walk(v, 0).end),
        TypeId::Rar4 => walked(super::rar4_walk(v).end),
        TypeId::Rar5 => walked(super::rar5_walk(v).end),
        TypeId::Tar => walked(super::tar_walk(v).end),
        TypeId::Mp4 | TypeId::Mov => walked(media::mp4_walk(v).end),
        TypeId::Flv => walked(media::flv_walk(v).end),
        TypeId::Xz => archive::xz_end(v, cap).map(|l| (l, MeasureMethod::Footer)),
        TypeId::NtfsMft => mft_end(v),
        _ => declared(id, v),
    };
    found.filter(|(l, _)| *l > 0).map(|(len, method)| {
        let declared = len;
        Measured { len: declared.min(cap), method, clipped: declared > cap }
    })
}

fn declared(id: TypeId, view: &dyn ByteView) -> Option<(u64, MeasureMethod)> {
    let head = view.bytes(0, HEAD);
    let spec = id.spec();
    let validator = spec.validator.or_else(|| spec.ancestors().find_map(|a| a.spec().validator))?;
    let probe = validator(&head)?;
    // Lengths inferred only from what is inside `head` are lower bounds, not sizes.
    let len = probe.declared_len?;
    Some((len, MeasureMethod::Declared))
}

fn mft_end(view: &dyn ByteView) -> Option<(u64, MeasureMethod)> {
    let mut pos = 0u64;
    loop {
        let rec = view.bytes(pos, 1024);
        match system::mft_record(&rec) {
            Some(size) => pos += u64::from(size),
            None => break,
        }
    }
    (pos > 0).then_some((pos, MeasureMethod::Walked))
}
