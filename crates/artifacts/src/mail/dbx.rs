//! Outlook Express `.dbx` folders: every message chain the mail context rebuilds (deleted but
//! unwiped ones included) goes to the timeline.

use super::rfc822::MailHeaders;
use crate::results::Recorder;
use strata_kernel::{ByteRange, Damage};

pub(crate) struct Dbx;

impl Dbx {
    pub fn is_dbx(data: &[u8]) -> bool {
        strata_mail::Dbx::is_dbx(data)
    }

    pub fn parse(data: &[u8], rec: &mut Recorder) {
        if !Self::is_dbx(data) {
            rec.damage(Damage::corrupt(ByteRange::new(0, 4), "DBX signature missing; scanning chunks anyway"));
        }
        let dbx = strata_mail::Dbx::scan(data);
        for head in dbx.heads() {
            if let Some(h) = MailHeaders::parse(&dbx.message(data, head)) {
                h.record(rec, "Outlook Express");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder file holding `messages` as 0x200-byte chunk chains.
    fn build(messages: &[&str]) -> Vec<u8> {
        const CHUNK: usize = 0x200;
        let mut d = vec![0u8; 0x24BC];
        d[..4].copy_from_slice(&[0xCF, 0xAD, 0x12, 0xFE]);
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
        let m1 = format!("From: a@example.ru\r\nTo: b@example.ru\r\nSubject: {long_subject}\r\nDate: Sat, 14 May 2011 17:36:09 +0000\r\n\r\nhi");
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
