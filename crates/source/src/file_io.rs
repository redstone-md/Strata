//! Positional reads that do not need `&mut File` (safe to share across threads).

use std::fs::File;
use std::io;

#[cfg(windows)]
pub fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

#[cfg(unix)]
pub fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

/// Read until `buf` is full or EOF.
pub fn read_full_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while !buf.is_empty() {
        match read_at(file, offset, buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                offset += n as u64;
                buf = &mut buf[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
