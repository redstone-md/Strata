//! Object groups (`TONI`, and `ESNI` for the scanned device): R-Studio's device tree.
//!
//! A group is a list of property records terminated by a record whose length is `FFFFFFFF`:
//! ```text
//! u32 object id | u32 property id | 4-byte class | u32 flags | u32 len | len bytes
//! ```
//! Classes read backwards like group tags (`TRAP` = PART, `EZIS` = SIZE, `AVRD` = DRVA,
//! `SFCR` = RCFS, `ESAB` = BASE). Properties used here:
//! `DRVA 0x02` own id, `DRVA 0x10` parent id, `PART 0x02` start, `PART 0x01` size,
//! `PART 0x201` partition type, `SIZE 0x01` size, `SIZE 0x02` sector size,
//! `RCFS 0x01` filesystem name (UTF-16), `BASE 0x20` display name (UTF-16).

use strata_kernel::bytes::{u32_le, utf16le};

const RECORD_HEADER: usize = 20;
const END: u32 = u32::MAX;

#[derive(Debug, Clone, Copy)]
struct Prop<'a> {
    class: [u8; 4],
    id: u32,
    value: &'a [u8],
}

/// One object's properties.
#[derive(Debug, Clone, Default)]
pub(crate) struct Object<'a> {
    props: Vec<Prop<'a>>,
}

/// Reads a class written backwards on disk, e.g. `class(b"PART")` matches stored `TRAP`.
fn class(readable: &[u8; 4]) -> [u8; 4] {
    [readable[3], readable[2], readable[1], readable[0]]
}

impl<'a> Object<'a> {
    /// Parse the property records of one object group; stops at the terminator or at the
    /// first record that runs past the payload. Returns the object and whether it ended cleanly.
    pub fn parse(payload: &'a [u8]) -> (Self, bool) {
        let mut props = Vec::new();
        let mut pos = 0;
        loop {
            let (Some(id), Some(len)) = (u32_le(payload, pos + 4), u32_le(payload, pos + 16)) else { return (Self { props }, false) };
            if len == END {
                return (Self { props }, true);
            }
            let start = pos + RECORD_HEADER;
            let Some(value) = payload.get(start..start + len as usize) else { return (Self { props }, false) };
            let Some(class) = payload.get(pos + 8..pos + 12).and_then(|c| c.try_into().ok()) else { return (Self { props }, false) };
            props.push(Prop { class, id, value });
            pos = start + len as usize;
        }
    }

    fn get(&self, readable: &[u8; 4], id: u32) -> Option<&'a [u8]> {
        let stored = class(readable);
        self.props.iter().find(|p| p.class == stored && p.id == id).map(|p| p.value)
    }

    fn number(&self, readable: &[u8; 4], id: u32) -> Option<u64> {
        let v = self.get(readable, id)?;
        match v.len() {
            4 => u32_le(v, 0).map(u64::from),
            8 => Some(u64::from_le_bytes(v.try_into().ok()?)),
            _ => None,
        }
    }

    fn text(&self, readable: &[u8; 4], id: u32) -> Option<String> {
        let s = utf16le(self.get(readable, id)?);
        let s = s.trim_end_matches('\0').trim().to_string();
        (!s.is_empty()).then_some(s)
    }

    pub fn id(&self) -> Option<u64> {
        self.number(b"DRVA", 0x02)
    }

    pub fn parent(&self) -> Option<u64> {
        self.number(b"DRVA", 0x10)
    }

    pub fn start(&self) -> Option<u64> {
        self.number(b"PART", 0x02)
    }

    pub fn size(&self) -> Option<u64> {
        self.number(b"PART", 0x01).or_else(|| self.number(b"SIZE", 0x01))
    }

    pub fn sector_size(&self) -> Option<u64> {
        self.number(b"SIZE", 0x02).or_else(|| self.number(b"PART", 0x12))
    }

    pub fn partition_type(&self) -> Option<u64> {
        self.number(b"PART", 0x201)
    }

    pub fn fs_name(&self) -> Option<String> {
        self.text(b"RCFS", 0x01)
    }

    pub fn name(&self) -> Option<String> {
        self.text(b"BASE", 0x20)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scn::testkit::ObjectBuilder;

    #[test]
    fn reads_properties_and_stops_at_terminator() {
        let payload = ObjectBuilder::new(7).parent(3).partition(0x7E00, 1 << 30, 7).fs_name("NTFS").name("disk one").finish();
        let (o, clean) = Object::parse(&payload);
        assert!(clean);
        assert_eq!((o.id(), o.parent(), o.start(), o.size()), (Some(7), Some(3), Some(0x7E00), Some(1 << 30)));
        assert_eq!(o.partition_type(), Some(7));
        assert_eq!(o.fs_name().as_deref(), Some("NTFS"));
        assert_eq!(o.name().as_deref(), Some("disk one"));
        let (cut, clean) = Object::parse(&payload[..payload.len() - 30]);
        assert!(!clean);
        assert_eq!(cut.id(), Some(7));
    }
}
