//! End-to-end identification on synthetic files: intact, header-zeroed, half-zeroed, renamed,
//! truncated and garbage inputs.

use strata_identify::testkit as tk;
use strata_identify::{Category, Identifier, InnerKind, Method, Registry, TypeId, TypeVerdict};

fn id(bytes: &[u8]) -> TypeVerdict {
    Identifier::new().identify(bytes, None)
}

fn names(v: &TypeVerdict, kind: InnerKind) -> Vec<String> {
    v.inner.iter().filter(|i| i.kind == kind).map(|i| i.name.clone()).collect()
}

fn sample_zip() -> Vec<u8> {
    let mut members: Vec<(String, Vec<u8>)> =
        (0..6).map(|i| (format!("docs/file{i}.bin"), tk::random(3000 + i * 500, i as u64))).collect();
    members.push(("keys/wallet.dat".into(), tk::random(9000, 4)));
    let refs: Vec<(&str, &[u8], bool)> = members.iter().map(|(n, d)| (n.as_str(), d.as_slice(), true)).collect();
    tk::zip(&refs)
}

fn sample_sqlite() -> Vec<u8> {
    let rows: Vec<Vec<u8>> = (0..40).map(|i| format!("row number {i} with some text").into_bytes()).collect();
    let rows: Vec<&[u8]> = rows.iter().map(Vec::as_slice).collect();
    tk::sqlite(
        &[("users", "CREATE TABLE users(id INTEGER, name TEXT)"), ("logins", "CREATE TABLE logins(url TEXT)")],
        &rows,
        8,
    )
}

fn zero(mut bytes: Vec<u8>, from: usize, to: usize) -> Vec<u8> {
    let to = to.min(bytes.len());
    bytes[from..to].fill(0);
    bytes
}

fn docx() -> Vec<u8> {
    tk::zip(&[("[Content_Types].xml", b"<Types/>", true), ("word/document.xml", b"<w/>", true)])
}

#[test]
fn identifies_intact_files_by_header() {
    let cases: Vec<(Vec<u8>, TypeId)> = vec![
        (sample_zip(), TypeId::Zip),
        (docx(), TypeId::Docx),
        (tk::zip(&[("[Content_Types].xml", b"<Types/>", true), ("xl/workbook.xml", b"<w/>", true)]), TypeId::Xlsx),
        (sample_sqlite(), TypeId::Sqlite),
        (tk::bdb_wallet(6), TypeId::BitcoinCoreBdb),
        (tk::png(64, 64), TypeId::Png),
        (tk::jpeg(20_000), TypeId::Jpeg),
        (tk::pdf(60), TypeId::Pdf),
        (tk::ole(&["WordDocument", "1Table", "\u{5}SummaryInformation"], 4096), TypeId::Doc),
        (tk::ole(&["Workbook"], 4096), TypeId::Xls),
        (tk::ole(&["__substg1.0_0037001F", "__properties_version1.0"], 4096), TypeId::Msg),
        (tk::ole(&["Catalog", "1", "2"], 4096), TypeId::ThumbsDb),
        (tk::pe(false), TypeId::Exe),
        (tk::pe(true), TypeId::Dll),
        (tk::gzip("secret.txt", &tk::lorem(5000)), TypeId::Gzip),
        (tk::tar(&[("a.txt", b"hello"), ("dir/b.bin", &tk::random(700, 1))]), TypeId::Tar),
        (tk::rar4(&[("wallet.dat", &tk::random(1000, 2)), ("notes.txt", b"hi")]), TypeId::Rar4),
        (tk::electrum_json(), TypeId::ElectrumWallet),
    ];
    for (bytes, expected) in cases {
        let v = id(&bytes);
        assert_eq!(v.file_type, expected, "{:?}", v.notes);
        let expected_method = if expected == TypeId::ElectrumWallet { Method::Text } else { Method::Header };
        assert_eq!(v.method, expected_method, "{expected}");
        assert!(v.confidence.get() >= 0.8, "{expected}: {}", v.confidence);
        assert!(v.valid_fraction >= 0.95, "{expected}: valid {} {:?}", v.valid_fraction, v.damage);
        if let Some(len) = v.declared_len {
            assert_eq!(len, bytes.len() as u64, "{expected} declared length");
        }
    }
}

#[test]
fn reports_inner_contents() {
    let v = id(&sample_zip());
    assert!(names(&v, InnerKind::Member).contains(&"keys/wallet.dat".to_string()));
    let v = id(&sample_sqlite());
    assert_eq!(names(&v, InnerKind::Table), vec!["users", "logins"]);
    let v = id(&tk::ole(&["WordDocument", "1Table"], 4096));
    assert!(names(&v, InnerKind::Stream).contains(&"WordDocument".to_string()));
    let v = id(&tk::pdf(30));
    assert!(names(&v, InnerKind::Object).iter().any(|n| n == "30 objects"));
    let v = id(&tk::gzip("secret.txt", b"x"));
    assert_eq!(names(&v, InnerKind::Member), vec!["secret.txt"]);
    let v = id(&tk::bdb_wallet(6));
    assert!(v.notes.iter().any(|n| n.contains("encrypted")));
}

#[test]
fn identifies_text_and_encodings() {
    let utf16: Vec<u8> = "Windows Registry Editor Version 5.00\r\n[HKEY_CURRENT_USER\\Software]\r\n"
        .repeat(20)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let cases: Vec<(Vec<u8>, TypeId, &str)> = vec![
        (tk::lorem(10_000), TypeId::Text, "ascii"),
        ("Пароль от кошелька: correct horse\n".repeat(50).into_bytes(), TypeId::Text, "utf-8"),
        (utf16, TypeId::Text, "utf-16le"),
        (b"<!DOCTYPE html><html><body>hi</body></html>".to_vec(), TypeId::Html, "ascii"),
        (b"<?xml version=\"1.0\"?><config><a/></config>".to_vec(), TypeId::Xml, "ascii"),
        (b"{\"a\": 1, \"b\": [true, null]}".to_vec(), TypeId::Json, "ascii"),
        (b"From: a@b.c\nTo: d@e.f\nSubject: keys\nDate: Mon, 1 Jan 2018\n\nbody".to_vec(), TypeId::Eml, "ascii"),
    ];
    for (bytes, expected, enc) in cases {
        let v = id(&bytes);
        assert_eq!(v.file_type, expected);
        assert!(v.inner.iter().any(|i| i.name == format!("encoding={enc}")), "{expected}: {:?}", v.inner);
    }
    let mut cp1251 = Vec::new();
    for _ in 0..40 {
        // "Мой пароль: x" in CP1251.
        cp1251.extend_from_slice(&[0xCC, 0xEE, 0xE9, 0x20, 0xEF, 0xE0, 0xF0, 0xEE, 0xEB, 0xFC, 0x3A, 0x20, b'x', b'\n']);
    }
    let v = id(&cp1251);
    assert_eq!(v.file_type, TypeId::Text);
    assert!(v.inner.iter().any(|i| i.name == "encoding=cp1251"));
}

#[test]
fn first_4k_zeroed_still_identified_with_lower_confidence() {
    let cases: Vec<(Vec<u8>, TypeId)> = vec![
        (sample_zip(), TypeId::Zip),
        (sample_sqlite(), TypeId::Sqlite),
        (tk::pdf(120), TypeId::Pdf),
        (tk::jpeg(60_000), TypeId::Jpeg),
        (tk::bdb_wallet(8), TypeId::BitcoinCoreBdb),
    ];
    for (bytes, expected) in cases {
        let intact = id(&bytes);
        let v = id(&zero(bytes, 0, 4096));
        assert!(v.file_type.spec().same_family(expected), "{expected}: got {} {:?}", v.file_type, v.notes);
        assert_eq!(v.method, Method::Structure, "{expected}");
        assert!(v.confidence < intact.confidence, "{expected}");
        assert!(v.confidence.get() >= 0.45, "{expected}: {}", v.confidence);
        assert!(v.valid_fraction < 1.0, "{expected}");
    }
}

#[test]
fn half_zeroed_still_identified() {
    let cases: Vec<(Vec<u8>, TypeId)> = vec![
        (sample_zip(), TypeId::Zip),
        (sample_sqlite(), TypeId::Sqlite),
        (tk::pdf(120), TypeId::Pdf),
        (tk::jpeg(60_000), TypeId::Jpeg),
        (tk::png(200, 100), TypeId::Png),
        (tk::bdb_wallet(10), TypeId::BitcoinCoreBdb),
        (tk::lorem(40_000), TypeId::Text),
    ];
    for (bytes, expected) in cases {
        let n = bytes.len();
        for (from, to) in [(n / 2, n), (n / 4, n * 3 / 4)] {
            let v = id(&zero(bytes.clone(), from, to));
            assert!(v.file_type.spec().same_family(expected), "{expected} [{from}..{to}]: got {}", v.file_type);
            assert!(v.valid_fraction < 0.99, "{expected}: {}", v.valid_fraction);
        }
        // Header gone and the second half zeroed as well.
        let v = id(&zero(zero(bytes.clone(), 0, 4096), n / 2, n));
        assert!(v.file_type.spec().same_family(expected), "{expected} headerless half: got {}", v.file_type);
    }
}

#[test]
fn zip_with_zeroed_header_still_lists_members() {
    let v = id(&zero(sample_zip(), 0, 4096));
    let members = names(&v, InnerKind::Member);
    assert!(members.contains(&"keys/wallet.dat".to_string()), "{members:?}");
}

#[test]
fn renamed_extension_flagged() {
    let ident = Identifier::new();
    let wallet = tk::bdb_wallet(6);
    let v = ident.identify(&wallet, Some("D:/Photos/photo.jpg"));
    let m = v.extension_mismatch.clone().expect("mismatch");
    assert!(m.suspicious);
    assert_eq!(m.declared, "jpg");
    assert_eq!(v.category, Category::Wallet);
    assert!(ident.identify(&wallet, Some("wallet.dat")).extension_mismatch.is_none());
    let v = ident.identify(&sample_zip(), Some("driver.sys"));
    assert!(v.extension_mismatch.is_some_and(|m| m.suspicious));
    assert!(ident.identify(&docx(), Some("report.docx")).extension_mismatch.is_none());
    assert!(ident.identify(&docx(), Some("report.zip")).extension_mismatch.is_none());
    let v = ident.identify(&tk::random(1 << 16, 3), Some("holiday.avi"));
    assert_eq!(v.file_type, TypeId::EncryptedOrRandom);
    assert!(v.extension_mismatch.is_some_and(|m| m.suspicious));
}

#[test]
fn random_and_zero_input() {
    let v = id(&tk::random(1 << 16, 11));
    assert_eq!(v.file_type, TypeId::EncryptedOrRandom);
    assert_eq!(v.method, Method::Entropy);
    let v = id(&[0u8; 10_000]);
    assert_eq!(v.file_type, TypeId::Unknown);
    let v = id(&[]);
    assert_eq!(v.file_type, TypeId::Unknown);
    assert!(serde_json::to_string(&v).is_ok());
}

#[test]
fn garbage_with_every_magic_never_panics() {
    for (seed, spec) in Registry::all().iter().enumerate() {
        for magic in spec.magics {
            for len in [magic.end(), magic.end() + 7, 600, 5000, 70_000] {
                let mut g = tk::random(len.max(magic.end()), seed as u64 * 31 + len as u64);
                g[magic.offset..magic.end()].copy_from_slice(magic.bytes);
                let _ = id(&g);
                g[magic.end()..].fill(0);
                let _ = id(&g);
                g[magic.end()..].fill(0xFF);
                let _ = id(&g);
            }
        }
    }
}

#[test]
fn truncated_and_corrupted_samples_never_panic() {
    let samples = vec![
        sample_zip(),
        sample_sqlite(),
        tk::bdb_wallet(4),
        tk::png(32, 32),
        tk::jpeg(5000),
        tk::pdf(20),
        tk::ole(&["WordDocument"], 4096),
        tk::pe(true),
        tk::gzip("a", &tk::lorem(3000)),
        tk::tar(&[("a", b"b")]),
        tk::rar4(&[("a", b"b")]),
        tk::electrum_json(),
    ];
    for (i, s) in samples.iter().enumerate() {
        for cut in (0..s.len()).step_by((s.len() / 40).max(1)) {
            let _ = id(&s[..cut]);
        }
        for k in 0..30 {
            let mut c = s.clone();
            let noise = tk::random(64, (i * 100 + k) as u64);
            let at = (k * 7919) % c.len().max(1);
            let end = (at + 64).min(c.len());
            c[at..end].copy_from_slice(&noise[..end - at]);
            let _ = id(&c);
        }
    }
}
