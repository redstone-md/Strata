//! THE signature table. Every magic number, extension list, footer and carving cap lives here.
//! Rows are ordered exactly like [`TypeId`] (checked by a unit test).

use super::{Category as C, FileType, Magic, TypeId as T};
use crate::formats::{archive, bdb, document, exec, image, mail, media, ole, sqlite, system, wallet, zip};
use crate::text;

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

const fn m(offset: usize, bytes: &'static [u8]) -> Magic {
    Magic::at(offset, bytes)
}

const BASE: FileType = FileType {
    id: T::Unknown,
    key: "unknown",
    name: "Unknown data",
    category: C::Unknown,
    extensions: &[],
    magics: &[],
    footer: None,
    validator: None,
    parent: None,
    dense: false,
    max_size: 64 * MB,
};

pub(super) const UNKNOWN: FileType = BASE;

const TEXT_EXT: &[&str] = &[
    "txt", "log", "csv", "tsv", "ini", "cfg", "conf", "md", "bat", "cmd", "ps1", "py", "sh", "js",
    "css", "reg", "inf", "nfo", "sql", "yaml", "yml", "asc", "pem", "key", "lst", "dump", "",
];

macro_rules! row {
    ($id:ident, $key:literal, $name:literal, $cat:ident { $($field:ident : $value:expr),* $(,)? }) => {
        FileType { id: T::$id, key: $key, name: $name, category: C::$cat, $($field: $value,)* ..BASE }
    };
}

macro_rules! zip_child {
    ($id:ident, $key:literal, $name:literal, $cat:ident, $ext:expr) => {
        row!($id, $key, $name, $cat { extensions: $ext, parent: Some(T::Zip), dense: true, max_size: 4 * GB })
    };
}

macro_rules! ole_child {
    ($id:ident, $key:literal, $name:literal, $cat:ident, $ext:expr) => {
        row!($id, $key, $name, $cat { extensions: $ext, parent: Some(T::Ole2), max_size: 2 * GB })
    };
}

pub(super) static TYPES: &[FileType] = &[
    row!(Zip, "zip", "ZIP archive", Archive {
        extensions: &["zip", "zipx", "zip64", "kmz", "xpi", "nupkg", "whl", "crx", "appx", "msix", "ipa",
                     "thmx", "eftx", "elmx", "glox", "xps", "oxps", "vsdx", "vsix"],
        magics: &[m(0, b"PK\x03\x04"), m(0, b"PK\x05\x06"), m(0, b"PK\x07\x08PK\x03\x04")],
        validator: Some(zip::validate), dense: true, max_size: 4 * GB,
    }),
    zip_child!(Docx, "docx", "Word OOXML document", Document, &["docx", "docm", "dotx", "dotm"]),
    zip_child!(Xlsx, "xlsx", "Excel OOXML workbook", Document, &["xlsx", "xlsm", "xltx", "xltm", "xlsb"]),
    zip_child!(Pptx, "pptx", "PowerPoint OOXML presentation", Document, &["pptx", "pptm", "ppsx", "potx"]),
    zip_child!(Jar, "jar", "Java archive", Executable, &["jar", "war", "ear"]),
    zip_child!(Apk, "apk", "Android package", Executable, &["apk", "aab"]),
    zip_child!(Odt, "odt", "OpenDocument text", Document, &["odt", "ott", "sxw"]),
    zip_child!(Ods, "ods", "OpenDocument spreadsheet", Document, &["ods", "ots", "sxc"]),
    zip_child!(Odp, "odp", "OpenDocument presentation", Document, &["odp", "otp", "sxi"]),
    zip_child!(Epub, "epub", "EPUB e-book", Document, &["epub"]),
    row!(SevenZip, "7z", "7-Zip archive", Archive {
        extensions: &["7z"], magics: &[m(0, b"7z\xBC\xAF\x27\x1C")],
        validator: Some(archive::seven_zip), dense: true, max_size: 8 * GB,
    }),
    row!(Rar4, "rar4", "RAR 4 archive", Archive {
        extensions: &["rar", "r00", "r01", "cbr"], magics: &[m(0, b"Rar!\x1A\x07\x00")],
        validator: Some(archive::rar4), dense: true, max_size: 8 * GB,
    }),
    row!(Rar5, "rar5", "RAR 5 archive", Archive {
        extensions: &["rar", "cbr"], magics: &[m(0, b"Rar!\x1A\x07\x01\x00")],
        validator: Some(archive::rar5), dense: true, max_size: 8 * GB,
    }),
    row!(Cab, "cab", "Microsoft cabinet", Archive {
        extensions: &["cab", "msu"], magics: &[m(0, b"MSCF\0\0\0\0")],
        validator: Some(archive::cab), dense: true, max_size: 2 * GB,
    }),
    row!(Gzip, "gzip", "GZIP stream", Archive {
        extensions: &["gz", "tgz", "gzip", "svgz"], magics: &[m(0, b"\x1F\x8B\x08")],
        validator: Some(archive::gzip), dense: true, max_size: 4 * GB,
    }),
    row!(Bzip2, "bzip2", "BZIP2 stream", Archive {
        extensions: &["bz2", "tbz2", "tbz"], magics: &[m(0, b"BZh")],
        validator: Some(archive::bzip2), dense: true, max_size: 4 * GB,
    }),
    row!(Xz, "xz", "XZ stream", Archive {
        extensions: &["xz", "txz"], magics: &[m(0, b"\xFD7zXZ\x00")],
        validator: Some(archive::xz), dense: true, max_size: 4 * GB,
    }),
    row!(Tar, "tar", "TAR archive (ustar)", Archive {
        extensions: &["tar"], magics: &[m(257, b"ustar")],
        validator: Some(archive::tar), max_size: 8 * GB,
    }),
    row!(Iso9660, "iso9660", "ISO 9660 image", Archive {
        extensions: &["iso"], magics: &[m(0x8001, b"CD001"), m(0x8801, b"CD001"), m(0x9001, b"CD001")],
        validator: Some(archive::iso), max_size: 16 * GB,
    }),
    row!(Pdf, "pdf", "PDF document", Document {
        extensions: &["pdf", "ai"], magics: &[m(0, b"%PDF-")], footer: Some(b"%%EOF"),
        validator: Some(document::pdf), max_size: 512 * MB,
    }),
    row!(Ole2, "ole2", "OLE2 compound file", Document {
        extensions: &["ole", "cfb", "doc", "dot", "xls", "xlt", "ppt", "pps", "pot", "msg", "msi", "msp", "db", "pub", "vsd", "mpp", "wps",
                     "feed-ms", "feedsdb-ms", "ilg", "suo", "ost", "max", "sldprt", "dwg"],
        magics: &[m(0, b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")],
        validator: Some(ole::validate), max_size: 2 * GB,
    }),
    ole_child!(Doc, "doc", "Word 97-2003 document", Document, &["doc", "dot", "wps", "wiz"]),
    ole_child!(Xls, "xls", "Excel 97-2003 workbook", Document, &["xls", "xlt", "xla", "xlw"]),
    ole_child!(Ppt, "ppt", "PowerPoint 97-2003 presentation", Document, &["ppt", "pps", "pot"]),
    ole_child!(Msg, "msg", "Outlook message", Mail, &["msg", "oft"]),
    ole_child!(ThumbsDb, "thumbs_db", "Windows thumbnail cache", System, &["db"]),
    row!(Rtf, "rtf", "Rich Text Format", Document {
        extensions: &["rtf", "doc", "wri"], magics: &[m(0, b"{\\rtf")],
        validator: Some(document::rtf), max_size: 256 * MB,
    }),
    row!(Pe, "pe", "Windows PE image", Executable {
        extensions: &["exe", "dll", "sys", "ocx", "cpl", "scr", "drv", "efi", "mui", "ax", "tlb", "com", "msstyles",
                     "acm", "tsp", "ime", "ds", "rll", "iec", "dlm", "flt", "ppd", "nls", "vbx", "xll", "wll", "pyd", "bpl", "fon", "dpl", "api", "lex", "spl", "sfx", "bin", "ocx"],
        magics: &[m(0, b"MZ")], validator: Some(exec::pe), max_size: 2 * GB,
    }),
    row!(Exe, "exe", "Windows executable", Executable {
        extensions: &["exe", "scr", "com", "efi"], parent: Some(T::Pe), max_size: 2 * GB,
    }),
    row!(Dll, "dll", "Windows DLL", Executable {
        extensions: &["dll", "ocx", "cpl", "ax", "mui", "drv", "tlb", "msstyles",
                     "acm", "tsp", "ime", "ds", "rll", "iec", "dlm", "flt", "ppd", "nls", "vbx", "xll", "wll", "pyd", "bpl", "fon", "dpl", "api", "lex", "spl", "sfx", "bin", "ocx"], parent: Some(T::Pe), max_size: 2 * GB,
    }),
    row!(Sys, "sys", "Windows driver", Executable {
        extensions: &["sys", "drv"], parent: Some(T::Pe), max_size: 256 * MB,
    }),
    row!(Elf, "elf", "ELF executable", Executable {
        extensions: &["", "so", "o", "elf", "bin", "ko", "axf", "out"], magics: &[m(0, b"\x7FELF")],
        validator: Some(exec::elf), max_size: 2 * GB,
    }),
    row!(Jpeg, "jpeg", "JPEG image", Image {
        extensions: &["jpg", "jpeg", "jpe", "jfif"], magics: &[m(0, b"\xFF\xD8\xFF")], footer: Some(b"\xFF\xD9"),
        validator: Some(image::jpeg), dense: true, max_size: 64 * MB,
    }),
    row!(Png, "png", "PNG image", Image {
        extensions: &["png"], magics: &[m(0, b"\x89PNG\r\n\x1A\n")], footer: Some(b"IEND\xAE\x42\x60\x82"),
        validator: Some(image::png), dense: true, max_size: 256 * MB,
    }),
    row!(Gif, "gif", "GIF image", Image {
        extensions: &["gif"], magics: &[m(0, b"GIF87a"), m(0, b"GIF89a")], footer: Some(b"\x00\x3B"),
        validator: Some(image::gif), dense: true, max_size: 64 * MB,
    }),
    row!(Bmp, "bmp", "BMP image", Image {
        extensions: &["bmp", "dib"], magics: &[m(0, b"BM")], validator: Some(image::bmp), max_size: 256 * MB,
    }),
    row!(Tiff, "tiff", "TIFF image", Image {
        extensions: &["tif", "tiff", "nef", "cr2", "dng", "arw"], magics: &[m(0, b"II*\0"), m(0, b"MM\0*")],
        validator: Some(image::tiff), max_size: 512 * MB,
    }),
    row!(Webp, "webp", "WebP image", Image {
        extensions: &["webp"], magics: &[m(8, b"WEBP")], validator: Some(image::webp), dense: true, max_size: 64 * MB,
    }),
    row!(Ico, "ico", "Windows icon", Image {
        extensions: &["ico", "cur"], magics: &[m(0, b"\0\0\x01\0"), m(0, b"\0\0\x02\0")],
        validator: Some(image::ico), max_size: 16 * MB,
    }),
    row!(Mp3, "mp3", "MP3 audio", Media {
        extensions: &["mp3"], magics: &[m(0, b"ID3"), m(0, b"\xFF\xFB"), m(0, b"\xFF\xF3"), m(0, b"\xFF\xFA")],
        validator: Some(media::mp3), dense: true, max_size: 512 * MB,
    }),
    row!(Wav, "wav", "WAVE audio", Media {
        extensions: &["wav"], magics: &[m(8, b"WAVE")], validator: Some(media::riff), max_size: 4 * GB,
    }),
    row!(Avi, "avi", "AVI video", Media {
        extensions: &["avi", "divx"], magics: &[m(8, b"AVI ")], validator: Some(media::riff), max_size: 4 * GB,
    }),
    row!(Mp4, "mp4", "MPEG-4 / ISO BMFF media", Media {
        extensions: &["mp4", "m4a", "m4v", "3gp", "3g2", "heic", "heif", "avif", "f4v"],
        magics: &[m(4, b"ftyp")], validator: Some(media::mp4), dense: true, max_size: 16 * GB,
    }),
    row!(Mov, "mov", "QuickTime movie", Media {
        extensions: &["mov", "qt"], magics: &[m(4, b"moov"), m(4, b"wide"), m(4, b"mdat")],
        validator: Some(media::mp4), parent: Some(T::Mp4), dense: true, max_size: 16 * GB,
    }),
    row!(Mkv, "mkv", "Matroska / WebM", Media {
        extensions: &["mkv", "webm", "mka", "mk3d"], magics: &[m(0, b"\x1A\x45\xDF\xA3")],
        validator: Some(media::mkv), dense: true, max_size: 16 * GB,
    }),
    row!(Flv, "flv", "Flash video", Media {
        extensions: &["flv"], magics: &[m(0, b"FLV\x01")], validator: Some(media::flv), dense: true, max_size: 4 * GB,
    }),
    row!(Sqlite, "sqlite", "SQLite 3 database", Database {
        extensions: &["sqlite", "sqlite3", "db", "db3", "sdb", "s3db", "dat", "localstorage", ""],
        magics: &[m(0, b"SQLite format 3\0")], validator: Some(sqlite::validate), max_size: 16 * GB,
    }),
    row!(BerkeleyDb, "berkeley_db", "Berkeley DB", Database {
        extensions: &["db", "dat", "bdb", ""],
        magics: &[
            m(12, b"\x62\x31\x05\x00"), m(12, b"\x00\x05\x31\x62"),
            m(12, b"\x61\x15\x06\x00"), m(12, b"\x00\x06\x15\x61"),
            m(12, b"\x53\x22\x04\x00"), m(12, b"\x00\x04\x22\x53"),
        ],
        validator: Some(bdb::validate), max_size: 4 * GB,
    }),
    row!(BitcoinCoreBdb, "bitcoin_core_bdb", "Bitcoin Core wallet (Berkeley DB)", Wallet {
        extensions: &["dat", "wallet", "bak", "db", ""], parent: Some(T::BerkeleyDb), max_size: 4 * GB,
    }),
    row!(BitcoinCoreSqlite, "bitcoin_core_sqlite", "Bitcoin Core descriptor wallet (SQLite)", Wallet {
        extensions: &["dat", "wallet", "bak", "sqlite", ""], parent: Some(T::Sqlite), max_size: 4 * GB,
    }),
    row!(RegistryHive, "registry_hive", "Windows registry hive", Registry {
        extensions: &["dat", "hiv", "hve", "sav", "bak", "old", "alt", "", "log", "log1", "log2"],
        magics: &[m(0, b"regf")], validator: Some(system::regf), max_size: 2 * GB,
    }),
    row!(Evt, "evt", "Windows event log (legacy)", System {
        extensions: &["evt"], magics: &[m(4, b"LfLe")], validator: Some(system::evt), max_size: GB,
    }),
    row!(Evtx, "evtx", "Windows event log", System {
        extensions: &["evtx"], magics: &[m(0, b"ElfFile\0")], validator: Some(system::evtx), max_size: GB,
    }),
    row!(Lnk, "lnk", "Windows shortcut", System {
        extensions: &["lnk"],
        magics: &[m(0, b"\x4C\0\0\0\x01\x14\x02\0\0\0\0\0\xC0\0\0\0\0\0\0\x46")],
        validator: Some(system::lnk), max_size: MB,
    }),
    row!(Prefetch, "prefetch", "Windows prefetch", System {
        extensions: &["pf"], magics: &[m(4, b"SCCA")], validator: Some(system::prefetch), max_size: 4 * MB,
    }),
    row!(PrefetchCompressed, "prefetch_mam", "Windows 10 compressed prefetch", System {
        extensions: &["pf"], magics: &[m(0, b"MAM\x04")], validator: Some(system::prefetch_mam),
        dense: true, max_size: 4 * MB,
    }),
    row!(NtfsMft, "ntfs_mft", "NTFS MFT records", System {
        extensions: &["", "mft"], magics: &[m(0, b"FILE0\0"), m(0, b"FILE*\0")],
        validator: Some(system::mft), max_size: 16 * GB,
    }),
    row!(IeIndexDat, "ie_index_dat", "Internet Explorer index.dat", Browser {
        extensions: &["dat"], magics: &[m(0, b"Client UrlCache MMF Ver ")],
        validator: Some(system::index_dat), max_size: 512 * MB,
    }),
    row!(Pst, "pst", "Outlook PST/OST", Mail {
        extensions: &["pst", "ost"], magics: &[m(0, b"!BDN")], validator: Some(mail::pst), max_size: 50 * GB,
    }),
    row!(Dbx, "dbx", "Outlook Express folder", Mail {
        extensions: &["dbx"], magics: &[m(0, b"\xCF\xAD\x12\xFE")],
        validator: Some(mail::dbx), max_size: 2 * GB,
    }),
    row!(Mbox, "mbox", "Unix mailbox", Mail {
        extensions: &["mbox", "mbx", "mbs", ""], magics: &[m(0, b"From ")],
        validator: Some(mail::mbox), max_size: 8 * GB,
    }),
    row!(Eml, "eml", "E-mail message (RFC 822)", Mail {
        extensions: &["eml", "mht", "mhtml", "nws", "emlx", "txt"], dense: true, validator: Some(text::validate), max_size: 256 * MB,
    }),
    row!(Html, "html", "HTML document", Text {
        extensions: &["html", "htm", "xhtml", "hta", "mht", "php", "asp", "aspx"], dense: true, validator: Some(text::validate),
        max_size: 64 * MB,
    }),
    row!(Xml, "xml", "XML document", Text {
        extensions: &["xml", "xsd", "xsl", "xslt", "svg", "plist", "config", "manifest", "rdf", "rss", "xaml", "csproj", "vcxproj", "resx"],
        magics: &[m(0, b"<?xml "), m(0, b"\xEF\xBB\xBF<?xml ")], dense: true, validator: Some(text::validate), max_size: 256 * MB,
    }),
    row!(Json, "json", "JSON document", Text {
        extensions: &["json", "jsonl", "geojson", "har", "map", "webmanifest"], dense: true, validator: Some(text::validate),
        max_size: 256 * MB,
    }),
    row!(ElectrumWallet, "electrum_wallet", "Electrum wallet (JSON)", Wallet {
        extensions: &["", "json", "wallet", "dat", "bak"], parent: Some(T::Json), dense: true, validator: Some(text::validate),
        max_size: 64 * MB,
    }),
    row!(ElectrumEncrypted, "electrum_encrypted", "Electrum wallet (encrypted)", Wallet {
        extensions: &["", "wallet", "dat", "bak"], magics: &[m(0, b"QklFMQ")],
        validator: Some(wallet::electrum_encrypted), dense: true, max_size: 64 * MB,
    }),
    row!(Text, "text", "Plain text", Text {
        extensions: TEXT_EXT, validator: Some(text::validate), dense: true, max_size: 64 * MB,
    }),
    row!(KeePass1, "keepass1", "KeePass 1 database", Credentials {
        extensions: &["kdb"], magics: &[m(0, b"\x03\xD9\xA2\x9A\x65\xFB\x4B\xB5")],
        validator: Some(wallet::keepass), dense: true, max_size: 256 * MB,
    }),
    row!(KeePass2, "keepass2", "KeePass 2 database", Credentials {
        extensions: &["kdbx"], magics: &[m(0, b"\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5")],
        validator: Some(wallet::keepass), dense: true, max_size: 256 * MB,
    }),
    row!(EncryptedOrRandom, "encrypted_random", "Encrypted or random data (no header)", Encrypted {
        extensions: &["", "tc", "hc", "vc", "bin", "dat", "enc", "aes", "gpg", "pgp", "img"], dense: true,
        max_size: 64 * GB,
    }),
    BASE,
];
