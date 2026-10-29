//! Checked sequential reader for Bitcoin serialization (compact sizes, little-endian ints).

use strata_kernel::bytes;

#[derive(Debug, Clone)]
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let out = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        self.pos += n;
        Some(out)
    }

    pub fn u8(&mut self) -> Option<u8> {
        let v = bytes::u8_at(self.data, self.pos)?;
        self.pos += 1;
        Some(v)
    }

    pub fn u16_le(&mut self) -> Option<u16> {
        let v = bytes::u16_le(self.data, self.pos)?;
        self.pos += 2;
        Some(v)
    }

    pub fn u32_le(&mut self) -> Option<u32> {
        let v = bytes::u32_le(self.data, self.pos)?;
        self.pos += 4;
        Some(v)
    }

    pub fn i32_le(&mut self) -> Option<i32> {
        self.u32_le().map(|v| v as i32)
    }

    pub fn u64_le(&mut self) -> Option<u64> {
        let v = bytes::u64_le(self.data, self.pos)?;
        self.pos += 8;
        Some(v)
    }

    pub fn i64_le(&mut self) -> Option<i64> {
        self.u64_le().map(|v| v as i64)
    }

    /// Bitcoin CompactSize.
    pub fn compact_size(&mut self) -> Option<u64> {
        match self.u8()? {
            0xfd => self.u16_le().map(u64::from),
            0xfe => self.u32_le().map(u64::from),
            0xff => self.u64_le(),
            n => Some(u64::from(n)),
        }
    }

    /// CompactSize-prefixed byte vector.
    pub fn var_bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.compact_size()?).ok()?;
        self.bytes(len)
    }

    /// CompactSize-prefixed string (lossy UTF-8).
    pub fn var_string(&mut self) -> Option<String> {
        self.var_bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_bounds() {
        let mut c = Cursor::new(&[0x03, b'a', b'b', b'c', 0xfd, 0x01]);
        assert_eq!(c.var_string().as_deref(), Some("abc"));
        assert_eq!(c.compact_size(), None);
        let mut c = Cursor::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(c.var_bytes(), None);
    }
}
