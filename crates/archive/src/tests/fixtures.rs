//! Synthetic archives built in memory with the formats' own writers.

use std::io::{Cursor, Write};

/// A real mainnet WIF (the well-known example key), planted in nested members.
pub const WIF: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

pub fn secret_note() -> Vec<u8> {
    format!("my old wallet backup\nkey: {WIF}\n").into_bytes()
}

pub fn zip(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in members {
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub fn zip_aes(name: &str, data: &[u8], password: &str) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .with_aes_encryption(zip::AesMode::Aes256, password);
    w.start_file(name, opts).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap().into_inner()
}

/// One stored member with traditional PKWARE encryption, records written by hand.
pub fn zip_traditional(name: &str, data: &[u8], password: &str) -> Vec<u8> {
    let crc = crc32fast::hash(data);
    let body = crate::formats::zip_crypto::encrypt_traditional(password, crc, data);
    let header = |sig: &[u8], central: bool| {
        let mut h = sig.to_vec();
        if central {
            h.extend_from_slice(&20u16.to_le_bytes());
        }
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&1u16.to_le_bytes()); // flags: encrypted
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&0u32.to_le_bytes()); // dos time
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&(body.len() as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        if central {
            h.extend_from_slice(&[0u8; 10]); // comment, disk, attributes
            h.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        }
        h.extend_from_slice(name.as_bytes());
        h
    };
    let mut out = header(b"PK\x03\x04", false);
    out.extend_from_slice(&body);
    let cd_start = out.len() as u32;
    let cd = header(b"PK\x01\x02", true);
    out.extend_from_slice(&cd);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0");
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_start.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn xz(data: &[u8]) -> Vec<u8> {
    let mut w = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap()
}

pub fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in members {
        let mut h = tar::Header::new_ustar();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(1_600_000_000);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    b.into_inner().unwrap()
}

pub fn seven_zip(members: &[(&str, &[u8])], password: Option<&str>) -> Vec<u8> {
    seven_zip_with(members, password, false)
}

pub fn seven_zip_with(members: &[(&str, &[u8])], password: Option<&str>, encrypt_header: bool) -> Vec<u8> {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderMethod, Password, encoder_options::AesEncoderOptions};
    let mut w = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    if let Some(pw) = password {
        w.set_content_methods(vec![AesEncoderOptions::new(Password::new(pw)).into(), EncoderMethod::LZMA2.into()]);
        w.set_encrypt_header(encrypt_header);
    }
    for (name, data) in members {
        w.push_archive_entry(ArchiveEntry::new_file(name), Some(*data)).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub fn cab(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = cab::CabinetBuilder::new();
    let folder = b.add_folder(cab::CompressionType::MsZip);
    for (name, _) in members {
        folder.add_file(*name);
    }
    let mut w = b.build(Cursor::new(Vec::new())).unwrap();
    let mut i = 0;
    while let Some(mut f) = w.next_file().unwrap() {
        f.write_all(members[i].1).unwrap();
        i += 1;
    }
    w.finish().unwrap().into_inner()
}

/// Deterministic damage: truncations and byte flips.
pub fn mutations(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for cut in [1, 7, 31, bytes.len() / 3, bytes.len() / 2, bytes.len().saturating_sub(5)] {
        out.push(bytes[..cut.min(bytes.len())].to_vec());
    }
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..24 {
        let mut b = bytes.to_vec();
        for _ in 0..4 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            if let Some(x) = b.get_mut((seed % bytes.len().max(1) as u64) as usize) {
                *x ^= (seed >> 32) as u8 | 1;
            }
        }
        out.push(b);
    }
    out
}
