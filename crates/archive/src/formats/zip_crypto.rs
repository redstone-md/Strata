//! ZIP decryption with passwords the user supplies for their own archives: traditional PKWARE
//! encryption and WinZip AES (AE-1/AE-2). No password generation happens here.

use aes::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use strata_identify::ZipEntry;
use strata_kernel::bytes::{u16_le, u8_at};

/// Decrypted, still compressed member data.
pub(crate) struct Plain {
    pub data: Vec<u8>,
    /// Compression method of `data` (AES members store the real one in an extra field).
    pub method: u16,
    /// Whether the entry CRC applies (false for AE-2).
    pub crc_checked: bool,
}

const AES_EXTRA: u16 = 0x9901;
const AES_MAC_LEN: usize = 10;

/// Try `password` on `entry`, whose raw bytes are `raw`. `None` when the password is wrong
/// or the member cannot be decrypted.
pub(crate) fn decrypt(archive: &[u8], entry: &ZipEntry, raw: &[u8], password: &str) -> Option<Plain> {
    match aes_extra(archive, entry) {
        Some(aes) => aes.decrypt(raw, password.as_bytes()),
        None if entry.flags & 1 != 0 => traditional(entry, raw, password.as_bytes()),
        None => None,
    }
}

// ---- traditional PKWARE ----

const fn crc_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static CRC: [u32; 256] = crc_table();

struct Keys([u32; 3]);

impl Keys {
    fn new(password: &[u8]) -> Self {
        let mut k = Self([0x1234_5678, 0x2345_6789, 0x3456_7890]);
        for b in password {
            k.update(*b);
        }
        k
    }

    fn crc(c: u32, b: u8) -> u32 {
        CRC[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8)
    }

    fn update(&mut self, b: u8) {
        self.0[0] = Self::crc(self.0[0], b);
        self.0[1] = self.0[1].wrapping_add(self.0[0] & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
        self.0[2] = Self::crc(self.0[2], (self.0[1] >> 24) as u8);
    }

    fn decrypt(&mut self, c: u8) -> u8 {
        let t = (self.0[2] | 2) & 0xFFFF;
        let p = c ^ ((t.wrapping_mul(t ^ 1) >> 8) & 0xFF) as u8;
        self.update(p);
        p
    }
}

fn traditional(entry: &ZipEntry, raw: &[u8], password: &[u8]) -> Option<Plain> {
    let header = raw.get(..12)?;
    let mut keys = Keys::new(password);
    let mut last = 0;
    for b in header {
        last = keys.decrypt(*b);
    }
    // Check byte: high byte of the CRC, or of the DOS time when sizes follow the data.
    let by_crc = (entry.crc32 >> 24) as u8;
    let by_time = (entry.dos_time >> 8) as u8;
    if last != by_crc && !(entry.flags & 8 != 0 && last == by_time) {
        return None;
    }
    let data = raw[12..].iter().map(|c| keys.decrypt(*c)).collect();
    Some(Plain { data, method: entry.method, crc_checked: true })
}

// ---- WinZip AES ----

struct AesExtra {
    version: u16,
    strength: u8,
    method: u16,
}

/// The 0x9901 extra field of the member's local header.
fn aes_extra(archive: &[u8], entry: &ZipEntry) -> Option<AesExtra> {
    let lh = entry.local_header?;
    let name_len = usize::from(u16_le(archive, lh + 26)?);
    let extra_len = usize::from(u16_le(archive, lh + 28)?);
    let extra = archive.get(lh + 30 + name_len..lh + 30 + name_len + extra_len)?;
    let mut pos = 0;
    while let (Some(id), Some(len)) = (u16_le(extra, pos), u16_le(extra, pos + 2)) {
        let body = pos + 4;
        if id == AES_EXTRA && len >= 7 {
            return Some(AesExtra { version: u16_le(extra, body)?, strength: u8_at(extra, body + 4)?, method: u16_le(extra, body + 5)? });
        }
        pos = body + usize::from(len);
    }
    None
}

type Ctr<C> = ctr::Ctr128LE<C>;

impl AesExtra {
    fn decrypt(&self, raw: &[u8], password: &[u8]) -> Option<Plain> {
        let key_len = match self.strength {
            1 => 16,
            2 => 24,
            3 => 32,
            _ => return None,
        };
        let salt_len = key_len / 2;
        let body_end = raw.len().checked_sub(AES_MAC_LEN)?;
        let (salt, verifier) = (raw.get(..salt_len)?, raw.get(salt_len..salt_len + 2)?);
        let cipher = raw.get(salt_len + 2..body_end)?;
        let mut derived = vec![0u8; key_len * 2 + 2];
        pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut derived);
        if &derived[key_len * 2..] != verifier {
            return None;
        }
        let (key, mac_key) = (&derived[..key_len], &derived[key_len..key_len * 2]);
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(mac_key).ok()?;
        mac.update(cipher);
        if mac.finalize().into_bytes()[..AES_MAC_LEN] != raw[body_end..] {
            return None;
        }
        let mut data = cipher.to_vec();
        let mut iv = [0u8; 16];
        iv[0] = 1;
        match key_len {
            16 => Ctr::<aes::Aes128>::new_from_slices(key, &iv).ok()?.apply_keystream(&mut data),
            24 => Ctr::<aes::Aes192>::new_from_slices(key, &iv).ok()?.apply_keystream(&mut data),
            _ => Ctr::<aes::Aes256>::new_from_slices(key, &iv).ok()?.apply_keystream(&mut data),
        }
        Some(Plain { data, method: self.method, crc_checked: self.version == 1 })
    }
}

/// Traditional encryption of `plain` (test fixtures only): 12-byte header + ciphertext.
#[cfg(test)]
pub(crate) fn encrypt_traditional(password: &str, crc: u32, plain: &[u8]) -> Vec<u8> {
    let mut keys = Keys::new(password.as_bytes());
    let mut header = [0x5Au8; 12];
    header[11] = (crc >> 24) as u8;
    let mut out = Vec::with_capacity(12 + plain.len());
    for p in header.iter().chain(plain) {
        let t = (keys.0[2] | 2) & 0xFFFF;
        out.push(p ^ ((t.wrapping_mul(t ^ 1) >> 8) & 0xFF) as u8);
        keys.update(*p);
    }
    out
}
