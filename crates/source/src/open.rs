use crate::{BlockSource, PhysicalDrive, RawImage, RdrImage};
use std::path::Path;
use std::sync::Arc;
use strata_kernel::Result;

/// Open any supported evidence location by sniffing its content, not its extension.
///
/// `\\.\PhysicalDriveN` opens the live drive; files starting with the R-Studio magic open as
/// `.rdr`; everything else is treated as a raw image.
pub fn open_source(location: &str, cache_dir: Option<&Path>) -> Result<Arc<dyn BlockSource>> {
    if location.starts_with(r"\\.\") {
        return Ok(Arc::new(PhysicalDrive::open_path(location)?));
    }
    let path = Path::new(location);
    let mut magic = [0u8; 4];
    let file = std::fs::File::open(path)?;
    crate::file_io::read_full_at(&file, 0, &mut magic)?;
    if magic == [0x33, 0xDA, 0x54, 0xD7] {
        return Ok(Arc::new(RdrImage::open_with_cache(path, cache_dir)?));
    }
    Ok(Arc::new(RawImage::open(path)?))
}
