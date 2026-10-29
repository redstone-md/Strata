//! Whole-message tests on synthetic mail: Cyrillic charsets, attachments, damage.

use crate::{Container, Message};

/// "Привет" in Windows-1251 and KOI8-R.
const CP1251: &[u8] = &[0xCF, 0xF0, 0xE8, 0xE2, 0xE5, 0xF2];
const KOI8R: &[u8] = &[0xF0, 0xD2, 0xC9, 0xD7, 0xC5, 0xD4];

fn multipart() -> Vec<u8> {
    let mut m = b"From: =?koi8-r?B?8NLJ18XU?= <sender@example.ru>\r\nTo: rcpt@example.com\r\nCc: copy@example.com\r\n\
Subject: =?windows-1251?B?z/Do4uXy?=\r\nDate: Sat, 14 May 2011 17:36:09 +0400\r\nMessage-ID: <m1@example.ru>\r\n\
MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\npreamble\r\n--b1\r\n\
Content-Type: text/plain; charset=windows-1251\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        .to_vec();
    m.extend_from_slice(CP1251);
    m.extend_from_slice(b" wallet\r\n--b1\r\nContent-Type: text/plain; charset=koi8-r\r\n\r\n");
    m.extend_from_slice(KOI8R);
    m.extend_from_slice(
        b"\r\n--b1\r\nContent-Type: application/octet-stream; name=\"wallet.dat\"\r\nContent-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"wallet.dat\"\r\n\r\naGVsbG8gd2FsbGV0\r\n--b1--\r\n",
    );
    m
}

#[test]
fn multipart_with_cyrillic_bodies_and_an_attachment() {
    let raw = multipart();
    let m = Message::parse(&raw).unwrap();
    let e = &m.envelope;
    assert_eq!(e.subject, "Привет");
    assert_eq!(e.from[0].name.as_deref(), Some("Привет"));
    assert_eq!(e.addresses(), vec!["sender@example.ru", "rcpt@example.com", "copy@example.com"]);
    assert_eq!(e.date.unwrap().to_string(), "2011-05-14 13:36:09");
    assert!(m.body.contains("Привет wallet"), "{}", m.body);
    assert!(m.body.matches("Привет").count() == 2, "both text parts: {}", m.body);
    assert!(!m.body_from_html);
    assert_eq!(m.attachments.len(), 1);
    let a = &m.attachments[0];
    assert_eq!((a.name.as_str(), a.mime.as_str(), a.size), ("wallet.dat", "application/octet-stream", 12));
    let (meta, bytes) = Message::attachment(&raw, 0).unwrap();
    assert_eq!((meta.name, bytes), ("wallet.dat".to_string(), b"hello wallet".to_vec()));
    assert!(Message::attachment(&raw, 1).is_none());
    let header = |name: &str| m.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str());
    assert_eq!(header("Subject"), Some("Привет"));
    assert_eq!(header("From"), Some("Привет <sender@example.ru>"));
    assert_eq!(header("Message-ID"), Some("<m1@example.ru>"), "undecoded headers stay as written");
    assert!(m.notes.is_empty(), "{:?}", m.notes);
}

#[test]
fn html_only_and_undeclared_charset() {
    let html = b"From: a@example.com\r\nSubject: h\r\nContent-Type: text/html\r\n\r\n<html><body><p>Seed words</p><p>below</p></body></html>";
    let m = Message::parse(html).unwrap();
    assert!(m.body_from_html);
    assert!(m.body.contains("Seed words") && !m.body.contains("<p>"), "{}", m.body);
    let mut plain = b"From: a@example.com\r\nSubject: p\r\n\r\n".to_vec();
    plain.extend_from_slice(CP1251);
    assert_eq!(Message::parse(&plain).unwrap().body, "Привет");
}

#[test]
fn damaged_messages_give_partial_results() {
    let raw = multipart();
    let cut = &raw[..raw.len() - 40];
    let m = Message::parse(cut).unwrap();
    assert_eq!(m.envelope.subject, "Привет");
    assert!(m.body.contains("wallet"));
    assert!(!m.notes.is_empty(), "a missing closing boundary is noted");
    let mut zeroed = raw.clone();
    let mid = zeroed.len() / 2;
    zeroed[mid..mid + 200].fill(0);
    let m = Message::parse(&zeroed).unwrap();
    assert!(m.notes.iter().any(|n| n.contains("200 bytes zeroed")), "{:?}", m.notes);
    for end in (0..raw.len()).step_by(7) {
        let _ = Message::parse(&raw[..end]);
        let _ = Message::attachment(&raw[..end], 0);
    }
    assert!(Message::parse(b"\0\0\0\0").is_none());
    assert!(Message::parse(b"").is_none());
}

#[test]
fn mbox_of_several_messages() {
    let mut mbox = Vec::new();
    for i in 0..3 {
        mbox.extend_from_slice(format!("From - Mon Jan {} 10:00:00 2011\r\nFrom: s{i}@example.com\r\nSubject: m{i}\r\n\r\nbody {i}\r\n\r\n", i + 1).as_bytes());
    }
    assert_eq!(Container::sniff(&mbox), Some(Container::Mbox));
    let (spans, _) = crate::split_mbox(&mbox, true);
    let subjects: Vec<String> =
        spans.iter().map(|s| Message::parse(&mbox[s.offset as usize..(s.offset + s.len) as usize]).unwrap().envelope.subject).collect();
    assert_eq!(subjects, vec!["m0", "m1", "m2"]);
}
