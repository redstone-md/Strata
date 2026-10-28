//! Direct, read-only access to a physical drive (`\\.\PhysicalDriveN`).
//!
//! Failing media: a failed read is split in halves down to one sector; sectors that still fail
//! read back as zeros and are remembered as damage (same strategy as the old imaging scripts).

use crate::file_io::read_at;
use crate::{BlockSource, SourceInfo, SourceKind};
use parking_lot::Mutex;
use std::fs::File;
use strata_kernel::{ByteRange, Error, Result};

pub struct PhysicalDrive {
    path: String,
    file: File,
    len: u64,
    sector: u32,
    bad: Mutex<Vec<ByteRange>>,
}

impl PhysicalDrive {
    pub fn open(index: u32) -> Result<Self> {
        Self::open_path(&format!(r"\\.\PhysicalDrive{index}"))
    }

    pub fn open_path(path: &str) -> Result<Self> {
        let file = File::open(path)?;
        let (len, sector) = geometry(&file)?;
        Ok(Self { path: path.to_string(), file, len, sector, bad: Mutex::new(Vec::new()) })
    }

    /// Enumerate `\\.\PhysicalDrive0..31` that can be opened.
    pub fn list() -> Vec<(u32, u64)> {
        (0..32).filter_map(|i| Self::open(i).ok().map(|d| (i, d.len))).collect()
    }

    /// Aligned read with recursive halving on error.
    fn read_aligned(&self, offset: u64, buf: &mut [u8]) {
        if crate::file_io::read_full_at(&self.file, offset, buf).is_ok() {
            return;
        }
        let sector = self.sector as usize;
        if buf.len() <= sector {
            // One retry for transient errors, then give up on this sector.
            if read_at(&self.file, offset, buf).is_err() {
                buf.fill(0);
                self.bad.lock().push(ByteRange::new(offset, buf.len() as u64));
            }
            return;
        }
        let half = (buf.len() / 2).div_ceil(sector) * sector;
        let (a, b) = buf.split_at_mut(half);
        self.read_aligned(offset, a);
        self.read_aligned(offset + half as u64, b);
    }
}

impl BlockSource for PhysicalDrive {
    fn info(&self) -> SourceInfo {
        SourceInfo {
            kind: SourceKind::PhysicalDrive,
            label: self.path.trim_start_matches(r"\\.\").to_string(),
            location: self.path.clone(),
            len: self.len,
            sector_size: self.sector,
        }
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - offset) as usize);
        let sector = u64::from(self.sector);
        let start = offset / sector * sector;
        let end = (offset + want as u64).div_ceil(sector) * sector;
        let mut aligned = vec![0u8; (end - start) as usize];
        self.read_aligned(start, &mut aligned);
        let skip = (offset - start) as usize;
        buf[..want].copy_from_slice(&aligned[skip..skip + want]);
        Ok(want)
    }

    fn damage(&self) -> Vec<ByteRange> {
        ByteRange::coalesce(self.bad.lock().clone())
    }
}

#[cfg(windows)]
fn geometry(file: &File) -> Result<(u64, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        DISK_GEOMETRY_EX, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_LENGTH_INFO,
    };

    let handle = file.as_raw_handle();
    let mut len_info: GET_LENGTH_INFORMATION = unsafe { std::mem::zeroed() };
    let mut returned = 0u32;
    // SAFETY: valid handle, output buffer sized for the structure.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(),
            0,
            (&mut len_info as *mut GET_LENGTH_INFORMATION).cast(),
            std::mem::size_of::<GET_LENGTH_INFORMATION>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    let mut geo: DISK_GEOMETRY_EX = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            std::ptr::null(),
            0,
            (&mut geo as *mut DISK_GEOMETRY_EX).cast(),
            std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let sector = if ok != 0 && geo.Geometry.BytesPerSector >= 512 { geo.Geometry.BytesPerSector } else { 512 };
    Ok((len_info.Length as u64, sector))
}

#[cfg(not(windows))]
fn geometry(file: &File) -> Result<(u64, u32)> {
    use std::io::{Seek, SeekFrom};
    let mut f = file.try_clone()?;
    Ok((f.seek(SeekFrom::End(0))?, 512))
}
