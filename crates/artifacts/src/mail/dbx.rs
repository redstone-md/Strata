//! Outlook Express `.dbx` folders (best effort): message bodies live in 0x200-byte chunks with
//! a 16-byte header (self offset, body size, data length, next chunk). Chains are rebuilt from
//! every self-consistent chunk header, so deleted-but-unwiped messages are found too.

use super::rfc822::MailHeaders;
use crate::results::Recorder;
use std::collections::{HashMap, HashSet};
use strata_kernel::bytes::u32_le;
use strata_kernel::{ByteRange, Damage};

pub(crate) const DBX_MAGIC: [u8; 4] = [0xCF, 0xAD, 0x12, 0xFE];
const CHUNK: usize = 0x200;
const MAX_CHAIN: usize = 2048;

pub(crate) struct Dbx;

impl Dbx {
    pub fn is_dbx(data: &[u8]) -> bool {
        data.starts_with(&DBX_MAGIC)
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        if !Self::is_dbx(data) {
            rec.damage(Damage::corrupt(ByteRange::new(0, 4), "DBX signature missing; scanning chunks anyway"));
        }
        // offset -> (data length, next)
        let mut chunks: HashMap<usize, (usize, usize)> = HashMap::new();
        let mut p = 0;
        while p + 16 <= data.len() {
            if u32_le(data, p) == Some(p as u32) && u32_le(data, p + 4) == Some(CHUNK as u32) {
                let len = u32_le(data, p + 8).unwrap_or(0) as usize;
                if len <= CHUNK {
                    chunks.insert(p, (len, u32_le(data, p + 12).unwrap_or(0) as usize));
                }
            }
            p += 4;
        }
        let referenced: HashSet<usize> = chunks.values().map(|c| c.1).collect();
        let mut heads: Vec<usize> = chunks.keys().copied().filter(|o| !referenced.contains(o)).collect();
        heads.sort_unstable();
        for head in heads {
            let body = Self::assemble(data, &chunks, head);
            let text = String::from_utf8_lossy(&body);
            if let Some(h) = MailHeaders::parse(&text) {
                h.record(rec, "Outlook Express");
            }
        }
    }

    fn assemble(data: &[u8], chunks: &HashMap<usize, (usize, usize)>, head: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = head;
        let mut seen = HashSet::new();
        while let Some(&(len, next)) = chunks.get(&cur) {
            if !seen.insert(cur) || seen.len() > MAX_CHAIN {
                break;
            }
            if let Some(b) = data.get(cur + 16..cur + 16 + len) {
                out.extend_from_slice(b);
            }
            if next == 0 {
                break;
            }
            cur = next;
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(messages: &[&str]) -> Vec<u8> {
        let mut d = vec![0u8; 0x24BC];
        d[..4].copy_from_slice(&DBX_MAGIC);
        for m in messages {
            let parts: Vec<&[u8]> = m.as_bytes().chunks(CHUNK).collect();
            let base = d.len();
            for (i, part) in parts.iter().enumerate() {
                let off = base + i * (CHUNK + 16);
                let next = if i + 1 < parts.len() { off + CHUNK + 16 } else { 0 };
                let mut c = vec![0u8; CHUNK + 16];
                c[0..4].copy_from_slice(&(off as u32).to_le_bytes());
                c[4..8].copy_from_slice(&(CHUNK as u32).to_le_bytes());
                c[8..12].copy_from_slice(&(part.len() as u32).to_le_bytes());
                c[12..16].copy_from_slice(&(next as u32).to_le_bytes());
                c[16..16 + part.len()].copy_from_slice(part);
                d.extend_from_slice(&c);
            }
        }
        d
    }

    #[test]
    fn rebuilds_messages() {
        let long_subject = "x".repeat(700);
        let m1 = format!("From: a@mail.ru\r\nTo: b@mail.ru\r\nSubject: {long_subject}\r\nDate: Sat, 14 May 2011 17:36:09 +0000\r\n\r\nhi");
        let m2 = "From: webmoney <noreply@wmtransfer.com>\r\nSubject: WMID\r\n\r\n";
        let data = build(&[&m1, m2]);
        let mut rec = Recorder::new("outlook_express.dbx");
        Dbx::parse(&data, &mut rec);
        let out = rec.finish();
        assert_eq!(out.events.len(), 1);
        assert_eq!(out.events[0].title(), long_subject);
        assert!(out.facts.iter().any(|f| f.value == "WMID"));
        assert!(out.identities.iter().any(|i| i.value == "noreply@wmtransfer.com"));
        for cut in (0..data.len()).step_by(101) {
            Dbx::parse(&data[..cut], &mut Recorder::new("t"));
        }
    }
}
