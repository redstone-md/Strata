//! `/var/log/wtmp` and `btmp`: fixed 384-byte `utmp` records (x86 and x86-64 glibc layout).
//! USER_PROCESS = login, DEAD_PROCESS = logout, BOOT_TIME = boot; btmp holds failed logins.

use crate::results::Recorder;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{i32_le, u16_le};
use strata_timeline::EventKind;

const RECORD: usize = 384;
const BOOT_TIME: u16 = 2;
const USER_PROCESS: u16 = 7;
const DEAD_PROCESS: u16 = 8;

pub(crate) struct Wtmp;

impl Wtmp {
    pub fn parse(data: &[u8], failed: bool, rec: &mut Recorder) {
        for r in data.chunks_exact(RECORD) {
            let Some(kind) = u16_le(r, 0) else { continue };
            let text = |range: std::ops::Range<usize>| {
                let raw = r.get(range).unwrap_or_default();
                let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                String::from_utf8_lossy(&raw[..end]).into_owned()
            };
            let (line, user, host) = (text(8..40), text(44..76), text(76..332));
            let at = i32_le(r, 340).and_then(|s| Timestamp::from_unix_secs(i64::from(s)));
            let from = if host.is_empty() { line.clone() } else { format!("{line} from {host}") };
            match kind {
                USER_PROCESS if failed => rec.dated(at, EventKind::Login, format!("Failed login {user}"), from),
                USER_PROCESS => rec.dated(at, EventKind::Login, format!("Login {user}"), from),
                DEAD_PROCESS => rec.dated(at, EventKind::Login, format!("Logout on {line}"), ""),
                BOOT_TIME => rec.dated(at, EventKind::SystemLog, "System boot", text(332..340)),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_record() {
        let mut r = vec![0u8; RECORD];
        r[0..2].copy_from_slice(&USER_PROCESS.to_le_bytes());
        r[8..12].copy_from_slice(b"tty7");
        r[44..50].copy_from_slice(b"andrew");
        r[340..344].copy_from_slice(&1_367_000_000i32.to_le_bytes());
        let mut rec = Recorder::new("linux.wtmp");
        Wtmp::parse(&r, false, &mut rec);
        assert_eq!(rec.finish().events[0].title(), "Login andrew");
    }
}
