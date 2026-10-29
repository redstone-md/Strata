//! `cargo run -p strata-workbench --example demo_disk -- <out.img>`: write a synthetic 64 MiB
//! disk for trying the Disks, Search and Files screens. Everything on it is made up.
//!
//! - MBR partition 1: FAT16 with folders, live, deleted and overwritten files
//! - a FAT16 volume whose MBR entry was wiped (found by the deep scan)
//! - an NTFS volume whose first sector is gone, only its backup boot sector left
//! - text in free space outside every volume

use strata_fs::testkit::{FatVolume, NtfsVolume};
use strata_workbench::Encoding;

const MIB: usize = 1 << 20;

fn text(e: Encoding, s: &str) -> Vec<u8> {
    e.encode(s).unwrap_or_default()
}

fn main() {
    let out = std::env::args().nth(1).expect("usage: demo_disk <out.img>");
    let mut notes = b"Shopping list: bread, milk.\r\nRemember: the old laptop backup is on the blue drive.\r\n".to_vec();
    notes.extend(text(Encoding::Utf16Le, "Заметка: пароль от архива записан в блокноте"));
    let mut letter = text(Encoding::Cp1251, "Привет! Пароль от архива я поменял, новый в блокноте. ");
    letter.extend(b"Sent from a demo machine.");
    let main = FatVolume::new()
        .file_in("Documents", "todo.txt", b"1. renew passport\r\n2. call the bank\r\n")
        .file_in("Documents", "budget 2014.csv", b"month,amount\r\njan,120\r\nfeb,95\r\n")
        .deleted_file_in("Documents", "notes old.txt", &notes)
        .file_in("Pictures", "holiday.jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0])
        .deleted_file_in("Pictures", "scan 001.jpg", &[0xFF, 0xD8, 0xFF, 0xE1, 0, 8, 1, 2, 3])
        .file("readme.txt", b"Demo disk for Strata. Nothing here is real.")
        .deleted_file("letter.txt", &letter)
        .overwritten_file("draft.doc", &[0x42; 3000], "new draft.txt", b"Rewritten draft over the old clusters.")
        .finish();
    let lost = FatVolume::new()
        .file_in("Backup", "archive index.txt", b"photos 2012\r\nphotos 2013\r\npassword hint: the usual one\r\n")
        .deleted_file_in("Backup", "keys backup.txt", b"wallet backup moved to the blue drive")
        .file("about.txt", b"Second partition, deleted from the table but still on the disk.")
        .finish();
    let mut ntfs = NtfsVolume::new().file("journal.txt", b"day 1: set up the new machine").deleted_file("old passwords.txt", b"see the notebook").finish();
    ntfs[..512].fill(0);

    let mut disk = vec![0u8; 64 * MIB];
    // MBR with one entry; the second partition's entry was wiped.
    disk[446 + 4] = 0x06;
    disk[446 + 8..446 + 12].copy_from_slice(&((MIB / 512) as u32).to_le_bytes());
    disk[446 + 12..446 + 16].copy_from_slice(&((main.len() / 512) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let put = |disk: &mut Vec<u8>, at: usize, bytes: &[u8]| disk[at..at + bytes.len()].copy_from_slice(bytes);
    put(&mut disk, MIB, &main);
    put(&mut disk, 9 * MIB + 64 * 1024, &lost);
    put(&mut disk, 20 * MIB + 128 * 1024, &ntfs);
    put(&mut disk, 40 * MIB + 4096, b"lost note in free space: meet at the station at nine, bring the notebook");
    put(&mut disk, 40 * MIB + 8192, &text(Encoding::Utf16Le, "черновик письма: блокнот лежит в ящике стола"));
    std::fs::write(&out, &disk).expect("write image");
    println!("{out}: {} MiB", disk.len() / MIB);
}
