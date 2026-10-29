//! Unpacker behaviour over synthetic archives of every supported format.

mod fixtures;

use crate::{ArchiveFormat, OpenOptions, UnpackLimits, UnpackReport, Unpacker, open_archive};
use fixtures::*;
use std::ops::ControlFlow;

/// What the visitor saw of one member.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    bytes: Vec<u8>,
    depth: usize,
    encrypted: bool,
    unpacked: bool,
    damaged: bool,
    chain: Vec<String>,
}

fn unpack_with(unpacker: &Unpacker, name: &str, bytes: &[u8]) -> (Vec<Seen>, UnpackReport) {
    let mut seen = Vec::new();
    let report = unpacker.unpack(name, bytes, None, &mut |m| {
        seen.push(Seen {
            path: m.path.to_string(),
            bytes: m.bytes.to_vec(),
            depth: m.depth,
            encrypted: m.entry.encrypted,
            unpacked: m.unpacked,
            damaged: !m.damage.is_empty(),
            chain: m.chain.to_vec(),
        });
        ControlFlow::Continue(())
    });
    (seen, report)
}

fn unpack(name: &str, bytes: &[u8]) -> (Vec<Seen>, UnpackReport) {
    unpack_with(&Unpacker::new(UnpackLimits::default(), OpenOptions::default()), name, bytes)
}

fn find<'a>(seen: &'a [Seen], path: &str) -> &'a Seen {
    seen.iter().find(|s| s.path == path).unwrap_or_else(|| panic!("{path} not in {:?}", seen.iter().map(|s| &s.path).collect::<Vec<_>>()))
}

fn has_wif(s: &Seen) -> bool {
    s.bytes.windows(WIF.len()).any(|w| w == WIF.as_bytes())
}

/// zip in gzip in tar in zip.
fn nested() -> Vec<u8> {
    let inner = zip(&[("secret/keys.txt", &secret_note()), ("readme.txt", b"nothing here")]);
    let gz = gzip(&inner);
    let t = tar(&[("backup/inner.zip.gz", &gz), ("backup/notes.txt", b"plain")]);
    zip(&[("bundle.tar", &t)])
}

#[test]
fn finds_wif_four_levels_deep_with_virtual_path() {
    let (seen, report) = unpack("D:/disk/outer.zip", &nested());
    let path = "D:/disk/outer.zip!/bundle.tar!/backup/inner.zip.gz!/inner.zip!/secret/keys.txt";
    let s = find(&seen, path);
    assert!(has_wif(s));
    assert_eq!(s.depth, 4);
    assert_eq!(s.chain.len(), 4);
    assert_eq!(s.chain[3], "D:/disk/outer.zip!/bundle.tar!/backup/inner.zip.gz!/inner.zip");
    assert!(find(&seen, "D:/disk/outer.zip!/bundle.tar").unpacked);
    assert_eq!(report.archives, 4);
    assert_eq!(report.members, 6);
    assert!(!report.cancelled && report.damage.is_empty());
}

#[test]
fn every_format_opens() {
    let note = secret_note();
    let cases: Vec<(&str, Vec<u8>, ArchiveFormat, &str)> = vec![
        ("a.zip", zip(&[("k.txt", &note)]), ArchiveFormat::Zip, "a.zip!/k.txt"),
        ("a.txt.gz", gzip(&note), ArchiveFormat::Gzip, "a.txt.gz!/a.txt"),
        ("a.txt.bz2", bzip2(&note), ArchiveFormat::Bzip2, "a.txt.bz2!/a.txt"),
        ("a.txt.xz", xz(&note), ArchiveFormat::Xz, "a.txt.xz!/a.txt"),
        ("a.tar", tar(&[("d/k.txt", &note)]), ArchiveFormat::Tar, "a.tar!/d/k.txt"),
        ("a.7z", seven_zip(&[("d/k.txt", &note)], None), ArchiveFormat::SevenZip, "a.7z!/d/k.txt"),
        ("a.cab", cab(&[("k.txt", &note)]), ArchiveFormat::Cab, "a.cab!/k.txt"),
    ];
    for (name, bytes, format, member) in cases {
        let reader = open_archive(&bytes, None).unwrap_or_else(|| panic!("{name} did not open"));
        assert_eq!(reader.format(), format, "{name}");
        let (seen, _) = unpack(name, &bytes);
        assert!(has_wif(find(&seen, member)), "{name}");
    }
}

#[test]
fn seven_zip_holding_a_zip_recurses() {
    let inner = zip(&[("wallet-backup.txt", &secret_note())]);
    let outer = seven_zip(&[("old/stuff.zip", &inner), ("old/a.txt", b"a")], None);
    let (seen, report) = unpack("x.7z", &outer);
    assert!(has_wif(find(&seen, "x.7z!/old/stuff.zip!/wallet-backup.txt")));
    assert_eq!(report.archives, 2);
}

#[test]
fn encrypted_seven_zip_is_listed_as_encrypted() {
    let bytes = seven_zip(&[("k.txt", &secret_note())], Some("pw"));
    let (seen, report) = unpack("e.7z", &bytes);
    let s = find(&seen, "e.7z!/k.txt");
    assert!(s.encrypted && s.bytes.is_empty() && s.damaged);
    assert_eq!(report.encrypted, 1);

    let bytes = seven_zip_with(&[("k.txt", &secret_note())], Some("pw"), true);
    let (seen, report) = unpack("h.7z", &bytes);
    assert!(seen.is_empty());
    assert!(report.damage.iter().any(|d| d.note().contains("encrypted")), "{:?}", report.damage);
}

// The RAR samples come from the `unrar` crate's test data (MIT/Apache-2.0): there is no
// RAR writer to build them here.
#[test]
fn rar4_and_rar5_read_and_nest() {
    let version: &[u8] = include_bytes!("../../testdata/version.rar");
    let solid: &[u8] = include_bytes!("../../testdata/solid.rar");
    let (seen, _) = unpack("v.rar", version);
    assert_eq!(find(&seen, "v.rar!/VERSION").bytes, b"unrar-0.4.0");
    let (seen, _) = unpack("s.rar", solid);
    assert!(!find(&seen, "s.rar!/.gitignore").bytes.is_empty());
    let outer = zip(&[("old/v.rar", version)]);
    let (seen, _) = unpack("o.zip", &outer);
    assert_eq!(find(&seen, "o.zip!/old/v.rar!/VERSION").bytes, b"unrar-0.4.0");
}

#[test]
fn encrypted_rar_is_listed_as_encrypted() {
    let (seen, report) = unpack("c.rar", include_bytes!("../../testdata/crypted.rar"));
    let s = find(&seen, "c.rar!/.gitignore");
    assert!(s.encrypted && s.bytes.is_empty());
    assert_eq!(report.encrypted, 1);
}

#[test]
fn encrypted_zip_members_open_with_the_right_password() {
    let note = secret_note();
    for (kind, bytes) in [("aes", zip_aes("k.txt", &note, "hunter2")), ("traditional", zip_traditional("k.txt", &note, "hunter2"))] {
        let (seen, report) = unpack("e.zip", &bytes);
        let s = find(&seen, "e.zip!/k.txt");
        assert!(s.encrypted && s.bytes.is_empty(), "{kind}");
        assert_eq!(report.encrypted, 1, "{kind}");

        let options = OpenOptions { passwords: vec!["wrong".into(), "hunter2".into()], ..OpenOptions::default() };
        let (seen, report) = unpack_with(&Unpacker::new(UnpackLimits::default(), options), "e.zip", &bytes);
        let s = find(&seen, "e.zip!/k.txt");
        assert_eq!(s.bytes, note, "{kind}");
        assert!(!s.damaged, "{kind}");
        assert_eq!(report.encrypted, 0, "{kind}");

        let options = OpenOptions { passwords: vec!["nope".into()], ..OpenOptions::default() };
        let (seen, _) = unpack_with(&Unpacker::new(UnpackLimits::default(), options), "e.zip", &bytes);
        assert!(find(&seen, "e.zip!/k.txt").bytes.is_empty(), "{kind}");
    }
}

#[test]
fn ratio_guard_caps_a_bomb_member() {
    let bomb = zip(&[("zeros.bin", &vec![0u8; 8 << 20])]);
    let limits = UnpackLimits { ratio_floor: 1 << 20, max_ratio: 20, ..UnpackLimits::default() };
    let (seen, report) = unpack_with(&Unpacker::new(limits, OpenOptions::default()), "b.zip", &bomb);
    let s = find(&seen, "b.zip!/zeros.bin");
    assert_eq!(s.bytes.len(), 1 << 20);
    assert!(s.damaged);
    assert_eq!(report.limited, 1);
}

#[test]
fn total_budget_and_member_cap_hold() {
    let blob = vec![7u8; 300_000];
    let many: Vec<(String, &[u8])> = (0..10).map(|i| (format!("f{i}.bin"), blob.as_slice())).collect();
    let refs: Vec<(&str, &[u8])> = many.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    let bytes = zip(&refs);
    let limits = UnpackLimits { max_total: 1_000_000, ..UnpackLimits::default() };
    let (seen, report) = unpack_with(&Unpacker::new(limits, OpenOptions::default()), "t.zip", &bytes);
    assert_eq!(report.expanded, 1_000_000);
    assert!(seen.iter().map(|s| s.bytes.len()).sum::<usize>() <= 1_000_000);
    assert!(report.limited >= 1);

    let limits = UnpackLimits { max_members: 3, ..UnpackLimits::default() };
    let (seen, report) = unpack_with(&Unpacker::new(limits, OpenOptions::default()), "t.zip", &bytes);
    assert_eq!(seen.len(), 3);
    assert!(report.limited >= 1);
}

#[test]
fn depth_limit_stops_recursion() {
    let mut bytes = zip(&[("core.txt", &secret_note())]);
    for i in 0..9 {
        bytes = zip(&[(&format!("level{i}.zip"), &bytes)]);
    }
    let (seen, _) = unpack("deep.zip", &bytes);
    assert_eq!(seen.iter().map(|s| s.depth).max(), Some(UnpackLimits::default().max_depth));
    assert!(!seen.iter().any(has_wif));
    assert!(seen.iter().filter(|s| s.depth == 6).all(|s| !s.unpacked));
}

#[test]
fn visitor_can_stop_the_walk() {
    let mut n = 0;
    let report = Unpacker::new(UnpackLimits::default(), OpenOptions::default()).unpack("o.zip", &nested(), None, &mut |_| {
        n += 1;
        ControlFlow::Break(())
    });
    assert_eq!(n, 1);
    assert!(report.cancelled);
}

#[test]
fn renamed_zip_is_still_unpacked() {
    let bytes = zip(&[("k.txt", &secret_note())]);
    let outer = zip(&[("holiday.jpg", &bytes)]);
    let (seen, _) = unpack("o.zip", &outer);
    assert!(has_wif(find(&seen, "o.zip!/holiday.jpg!/k.txt")));
}

#[test]
fn damaged_archives_never_panic() {
    let note = secret_note();
    let samples = vec![
        nested(),
        zip_aes("k.txt", &note, "pw"),
        zip_traditional("k.txt", &note, "pw"),
        gzip(&note),
        bzip2(&note),
        xz(&note),
        tar(&[("k.txt", &note)]),
        seven_zip(&[("k.txt", &note), ("b.txt", b"b")], None),
        cab(&[("k.txt", &note)]),
        include_bytes!("../../testdata/version.rar").to_vec(),
        include_bytes!("../../testdata/solid.rar").to_vec(),
    ];
    let options = OpenOptions { passwords: vec!["pw".into()], ..OpenOptions::default() };
    let unpacker = Unpacker::new(UnpackLimits::default(), options);
    for sample in &samples {
        for bad in mutations(sample) {
            let _ = unpack_with(&unpacker, "bad", &bad);
        }
    }
}

#[test]
fn truncated_zip_keeps_what_survives() {
    let note = secret_note();
    let bytes = zip(&[("a.txt", &note), ("big.bin", &vec![1u8; 100_000])]);
    let cut = &bytes[..bytes.len() / 2];
    let (seen, _) = unpack("cut.zip", cut);
    assert!(has_wif(find(&seen, "cut.zip!/a.txt")));
}
