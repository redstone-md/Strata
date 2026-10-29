//! R-Studio file-type tags that correspond to Strata registry types (data, defined once).
//!
//! Only unambiguous tags are mapped: a wrong type would make the carver measure the file with
//! the wrong rules. Unmapped tags still flag their block as holding a file start.

use strata_identify::TypeId;

const MAP: &[(&[u8; 4], TypeId)] = &[
    (b"\0JPG", TypeId::Jpeg),
    (b"EXIF", TypeId::Jpeg),
    (b"\0PNG", TypeId::Png),
    (b"\0GIF", TypeId::Gif),
    (b"\0BMP", TypeId::Bmp),
    (b"\0TIF", TypeId::Tiff),
    (b"\0ICO", TypeId::Ico),
    (b"\0ZIP", TypeId::Zip),
    (&[0, 0, b'7', b'Z'], TypeId::SevenZip),
    (b"\0CAB", TypeId::Cab),
    (b"\0\0GZ", TypeId::Gzip),
    (b"\0BZ2", TypeId::Bzip2),
    (b"\0\0XZ", TypeId::Xz),
    (b"\0PDF", TypeId::Pdf),
    (b"\0RTF", TypeId::Rtf),
    (b"\0OLE", TypeId::Ole2),
    (b"WORD", TypeId::Doc),
    (b"MXLS", TypeId::Xls),
    (b"MPPT", TypeId::Ppt),
    (b"PEEX", TypeId::Exe),
    (b"_EXE", TypeId::Exe),
    (b"PEDL", TypeId::Dll),
    (b"_DLL", TypeId::Dll),
    (b"_SYS", TypeId::Sys),
    (b"HIVE", TypeId::RegistryHive),
    (b"\0LNK", TypeId::Lnk),
    (b"\0WAV", TypeId::Wav),
    (b"\0AVI", TypeId::Avi),
    (b"\0MP4", TypeId::Mp4),
    (b"\0MOV", TypeId::Mov),
    (b"\0MKV", TypeId::Mkv),
    (b"\0FLV", TypeId::Flv),
    (b"\0DBX", TypeId::Dbx),
    (b"HTML", TypeId::Html),
    (b"\0XML", TypeId::Xml),
];

/// Strata type for an R-Studio tag (readable order, e.g. `*b"\0JPG"`).
pub fn type_for_tag(tag: [u8; 4]) -> Option<TypeId> {
    MAP.iter().find(|(t, _)| **t == tag).map(|(_, id)| *id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_tags_only() {
        assert_eq!(type_for_tag(*b"\0JPG"), Some(TypeId::Jpeg));
        assert_eq!(type_for_tag(*b"PEDL"), Some(TypeId::Dll));
        assert_eq!(type_for_tag(*b"\0RAR"), None, "RAR 4 and 5 share the tag");
        assert_eq!(type_for_tag(*b"TXTA"), None);
    }
}
