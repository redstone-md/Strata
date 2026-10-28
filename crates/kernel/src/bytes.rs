//! Checked little/big-endian reads over untrusted byte slices. Never panics.

/// Read a fixed-size array at `off`, or `None` when out of bounds.
pub fn array<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    data.get(off..off.checked_add(N)?)?.try_into().ok()
}

pub fn u8_at(data: &[u8], off: usize) -> Option<u8> {
    data.get(off).copied()
}

macro_rules! readers {
    ($($le:ident, $be:ident => $t:ty),*) => {$(
        pub fn $le(data: &[u8], off: usize) -> Option<$t> {
            array(data, off).map(<$t>::from_le_bytes)
        }
        pub fn $be(data: &[u8], off: usize) -> Option<$t> {
            array(data, off).map(<$t>::from_be_bytes)
        }
    )*};
}

readers!(u16_le, u16_be => u16, u32_le, u32_be => u32, u64_le, u64_be => u64, i64_le, i64_be => i64);

/// Little-endian unsigned integer of `width` (1..=8) bytes, used by NTFS run lists.
pub fn uint_le_var(data: &[u8], off: usize, width: usize) -> Option<u64> {
    if width == 0 || width > 8 {
        return None;
    }
    let bytes = data.get(off..off.checked_add(width)?)?;
    Some(bytes.iter().rev().fold(0u64, |acc, b| (acc << 8) | u64::from(*b)))
}

/// Signed little-endian integer of `width` (1..=8) bytes with sign extension.
pub fn int_le_var(data: &[u8], off: usize, width: usize) -> Option<i64> {
    let raw = uint_le_var(data, off, width)?;
    let shift = 64 - 8 * width as u32;
    Some(((raw << shift) as i64) >> shift)
}

/// Decode UTF-16LE, stopping at the first NUL, replacing invalid units.
pub fn utf16le(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Shannon entropy in bits per byte (0..=8).
pub fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f32;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f32 / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_ints() {
        assert_eq!(uint_le_var(&[0x34, 0x12], 0, 2), Some(0x1234));
        assert_eq!(int_le_var(&[0xff], 0, 1), Some(-1));
        assert_eq!(int_le_var(&[0x00, 0x80], 0, 2), Some(-32768));
        assert_eq!(uint_le_var(&[1], 0, 2), None);
    }

    #[test]
    fn out_of_bounds_is_none() {
        assert_eq!(u32_le(&[1, 2, 3], 0), None);
        assert_eq!(u16_le(&[1, 2, 3], usize::MAX), None);
    }
}
