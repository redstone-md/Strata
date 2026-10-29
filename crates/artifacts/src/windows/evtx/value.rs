//! Typed substitution values of BinXML template instances.

use super::binxml::Node;
use crate::text::utf16_at;
use strata_kernel::Timestamp;
use strata_kernel::bytes::{array, i64_le, u8_at, u16_le, u32_le, u64_le};

pub(super) const TYPE_NULL: u8 = 0x00;
pub(super) const TYPE_STRING: u8 = 0x01;
pub(super) const TYPE_BINXML: u8 = 0x21;
const ARRAY: u8 = 0x80;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Value {
    Null,
    Str(String),
    Int(i64),
    UInt(u64),
    Hex(u64),
    Real(f64),
    Bool(bool),
    Bin(Vec<u8>),
    Guid(String),
    Time(Timestamp),
    Sid(String),
    /// Nested BinXML (already parsed by the caller).
    Xml(Vec<Node>),
    List(Vec<Value>),
}

impl Value {
    /// Decode a non-BinXML value of `ty` from exactly its bytes.
    pub(super) fn decode(ty: u8, b: &[u8]) -> Value {
        if ty & ARRAY != 0 {
            return Self::array(ty & !ARRAY, b);
        }
        let int = |v: Option<i64>| v.map_or(Value::Null, Value::Int);
        let uint = |v: Option<u64>| v.map_or(Value::Null, Value::UInt);
        match ty {
            TYPE_NULL => Value::Null,
            TYPE_STRING => Value::Str(utf16_at(b, 0, b.len())),
            0x02 => Value::Str(crate::text::ansi(b)),
            0x03 => int(u8_at(b, 0).map(|v| i64::from(v as i8))),
            0x04 => uint(u8_at(b, 0).map(u64::from)),
            0x05 => int(u16_le(b, 0).map(|v| i64::from(v as i16))),
            0x06 => uint(u16_le(b, 0).map(u64::from)),
            0x07 => int(u32_le(b, 0).map(|v| i64::from(v as i32))),
            0x08 => uint(u32_le(b, 0).map(u64::from)),
            0x09 => int(i64_le(b, 0)),
            0x0A => uint(u64_le(b, 0)),
            0x0B => u32_le(b, 0).map_or(Value::Null, |v| Value::Real(f64::from(f32::from_bits(v)))),
            0x0C => u64_le(b, 0).map_or(Value::Null, |v| Value::Real(f64::from_bits(v))),
            0x0D => u32_le(b, 0).map_or(Value::Null, |v| Value::Bool(v != 0)),
            0x0F => guid(b).map_or(Value::Null, Value::Guid),
            0x10 => match b.len() {
                4 => u32_le(b, 0).map_or(Value::Null, |v| Value::Hex(u64::from(v))),
                _ => u64_le(b, 0).map_or(Value::Null, Value::Hex),
            },
            0x11 => u64_le(b, 0).and_then(Timestamp::from_filetime).map_or(Value::Null, Value::Time),
            0x12 => systemtime(b).map_or(Value::Null, Value::Time),
            0x13 => sid(b).map_or(Value::Null, Value::Sid),
            0x14 => u32_le(b, 0).map_or(Value::Null, |v| Value::Hex(u64::from(v))),
            0x15 => u64_le(b, 0).map_or(Value::Null, Value::Hex),
            _ => Value::Bin(b.to_vec()),
        }
    }

    fn array(ty: u8, b: &[u8]) -> Value {
        let items = match ty {
            TYPE_STRING => crate::text::utf16_list(b, 1024).into_iter().map(Value::Str).collect(),
            _ => match fixed_size(ty) {
                Some(n) => b.chunks_exact(n).take(1024).map(|c| Self::decode(ty, c)).collect(),
                None => vec![Value::Bin(b.to_vec())],
            },
        };
        Value::List(items)
    }

    pub(super) fn is_null(&self) -> bool {
        matches!(self, Value::Null) || matches!(self, Value::Str(s) if s.is_empty())
    }

    /// Text form as shown in Event Viewer's XML view.
    pub(super) fn text(&self) -> String {
        match self {
            Value::Null => String::new(),
            Value::Str(s) | Value::Guid(s) | Value::Sid(s) => s.clone(),
            Value::Int(v) => v.to_string(),
            Value::UInt(v) => v.to_string(),
            Value::Hex(v) => format!("0x{v:x}"),
            Value::Real(v) => v.to_string(),
            Value::Bool(v) => v.to_string(),
            Value::Bin(b) => b.iter().map(|x| format!("{x:02X}")).collect(),
            Value::Time(t) => t.to_string(),
            Value::Xml(nodes) => nodes.iter().map(Node::text).collect(),
            Value::List(items) => items.iter().map(Value::text).collect::<Vec<_>>().join(", "),
        }
    }

    pub(super) fn time(&self) -> Option<Timestamp> {
        match self {
            Value::Time(t) => Some(*t),
            Value::Str(s) => crate::text::parse_iso8601(s),
            _ => None,
        }
    }
}

fn fixed_size(ty: u8) -> Option<usize> {
    Some(match ty {
        0x03 | 0x04 => 1,
        0x05 | 0x06 => 2,
        0x07 | 0x08 | 0x0B | 0x0D | 0x14 => 4,
        0x09 | 0x0A | 0x0C | 0x11 | 0x15 => 8,
        0x0F | 0x12 => 16,
        _ => return None,
    })
}

fn guid(b: &[u8]) -> Option<String> {
    let raw: [u8; 16] = array(b, 0)?;
    let d1 = u32_le(&raw, 0)?;
    let d2 = u16_le(&raw, 4)?;
    let d3 = u16_le(&raw, 6)?;
    let tail: String = raw[10..].iter().map(|x| format!("{x:02X}")).collect();
    Some(format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{tail}}}", raw[8], raw[9]))
}

/// `S-1-5-21-…`: revision, sub-authority count, 48-bit big-endian authority, u32 sub-authorities.
fn sid(b: &[u8]) -> Option<String> {
    let rev = u8_at(b, 0)?;
    let count = usize::from(u8_at(b, 1)?);
    let auth = b.get(2..8)?.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x));
    let subs: Option<Vec<String>> = (0..count.min(15)).map(|i| u32_le(b, 8 + 4 * i).map(|v| v.to_string())).collect();
    let mut s = format!("S-{rev}-{auth}");
    for sub in subs? {
        s.push('-');
        s.push_str(&sub);
    }
    Some(s)
}

fn systemtime(b: &[u8]) -> Option<Timestamp> {
    let w = |i: usize| u16_le(b, 2 * i).map(u32::from);
    crate::text::civil(i64::from(w(0)?), w(1)?, w(3)?, w(4)?, w(5)?, w(6)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_common_types() {
        let sid_bytes = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        assert_eq!(Value::decode(0x13, &sid_bytes).text(), "S-1-5-32-544");
        let g = [0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(Value::decode(0x0F, &g).text(), "{00112233-4455-6677-8899-AABBCCDDEEFF}");
        assert_eq!(Value::decode(0x08, &2u32.to_le_bytes()).text(), "2");
        assert_eq!(Value::decode(0x14, &0x3e7u32.to_le_bytes()).text(), "0x3e7");
        let list: Vec<u8> = "a\0bc\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(Value::decode(0x81, &list).text(), "a, bc");
        assert_eq!(Value::decode(0x13, &[1]), Value::Null);
        assert_eq!(Value::decode(0x11, &[0; 3]), Value::Null);
    }
}
