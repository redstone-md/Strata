//! Binary XML of EVTX records: tokens, inline/shared names, template definitions (cached per
//! chunk by offset) and template instances with typed substitutions, expanded into a small
//! element tree. Offsets are chunk-relative, so the parser always works on the whole chunk.

use super::value::{TYPE_BINXML, TYPE_NULL, Value};
use std::collections::HashMap;
use std::rc::Rc;
use strata_kernel::bytes::{u8_at, u16_le, u32_le};

const MAX_DEPTH: u8 = 24;
const MAX_NODES: usize = 20_000;
const MAX_VALUES: usize = 1024;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Node {
    Element(Element),
    Value(Value),
    /// Placeholder inside a template definition.
    Sub(u16),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub(super) struct Element {
    pub(super) name: String,
    pub(super) attrs: Vec<(String, Vec<Node>)>,
    pub(super) children: Vec<Node>,
}

impl Node {
    pub(super) fn text(&self) -> String {
        match self {
            Node::Element(e) => e.text(),
            Node::Value(v) => v.text(),
            Node::Sub(_) => String::new(),
        }
    }
}

impl Element {
    /// Concatenated text content.
    pub(super) fn text(&self) -> String {
        self.children.iter().map(Node::text).collect()
    }

    pub(super) fn child(&self, name: &str) -> Option<&Element> {
        self.elements().find(|e| e.name == name)
    }

    pub(super) fn elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    pub(super) fn attr(&self, name: &str) -> Option<&[Node]> {
        self.attrs.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_slice())
    }

    pub(super) fn attr_text(&self, name: &str) -> Option<String> {
        self.attr(name).map(|v| v.iter().map(Node::text).collect())
    }
}

/// Parses BinXML inside one chunk; template definitions are shared across its records.
pub(super) struct BinXml<'c> {
    chunk: &'c [u8],
    templates: HashMap<usize, Rc<Vec<Node>>>,
    nodes: usize,
}

impl<'c> BinXml<'c> {
    pub(super) fn new(chunk: &'c [u8]) -> Self {
        Self { chunk, templates: HashMap::new(), nodes: 0 }
    }

    /// Parse the fragment at `[start, end)` (a record's event XML).
    pub(super) fn fragment(&mut self, start: usize, end: usize) -> Vec<Node> {
        self.nodes = 0;
        let mut pos = start;
        self.content(&mut pos, end.min(self.chunk.len()), 0)
    }

    fn u8(&self, pos: usize) -> Option<u8> {
        u8_at(self.chunk, pos)
    }

    /// Nodes until end-of-element / end-of-fragment. Stops quietly on damaged tokens.
    fn content(&mut self, pos: &mut usize, end: usize, depth: u8) -> Vec<Node> {
        let mut out = Vec::new();
        if depth > MAX_DEPTH {
            return out;
        }
        while *pos < end && self.nodes < MAX_NODES {
            let Some(token) = self.u8(*pos) else { break };
            self.nodes += 1;
            let node = match token & 0xBF {
                0x00 => {
                    *pos += 1;
                    break;
                }
                0x04 => {
                    *pos += 1;
                    break;
                }
                0x0F => {
                    *pos += 4;
                    continue;
                }
                0x01 => self.element(pos, end, depth).map(Node::Element),
                0x05 | 0x0D | 0x0E | 0x08 | 0x09 | 0x07 => self.value_token(pos),
                0x0A => self.name(*pos + 1).map(|(_, len)| {
                    *pos += 5 + len;
                    Node::Value(Value::Null)
                }),
                0x0B => u16_le(self.chunk, *pos + 1).map(|n| {
                    *pos += 3 + 2 * usize::from(n);
                    Node::Value(Value::Null)
                }),
                0x0C => self.template_instance(pos, end, depth),
                _ => None,
            };
            match node {
                Some(Node::Value(Value::Null)) => {}
                Some(n) => out.push(n),
                None => break,
            }
        }
        out
    }

    /// A name at chunk offset `at`: (name, bytes it occupies when stored inline here).
    fn name(&self, at: usize) -> Option<(String, usize)> {
        let offset = u32_le(self.chunk, at)? as usize;
        let read = |o: usize| -> Option<(String, usize)> {
            let chars = usize::from(u16_le(self.chunk, o + 6)?);
            let raw = self.chunk.get(o + 8..o + 8 + 2 * chars)?;
            Some((crate::text::utf16_at(raw, 0, raw.len()), 8 + 2 * chars + 2))
        };
        let (name, size) = read(offset)?;
        // Stored right after the reference: skip over it.
        Some((name, if offset == at + 4 { size } else { 0 }))
    }

    fn element(&mut self, pos: &mut usize, end: usize, depth: u8) -> Option<Element> {
        let has_attrs = self.u8(*pos)? & 0x40 != 0;
        // token, dependency id (2), data size (4), name offset (4)
        let (name, inline) = self.name(*pos + 7)?;
        *pos += 11 + inline;
        if has_attrs {
            *pos += 4;
        }
        let mut el = Element { name, ..Element::default() };
        while matches!(self.u8(*pos)?, 0x06 | 0x46) {
            let (attr, inline) = self.name(*pos + 1)?;
            *pos += 5 + inline;
            let mut value = Vec::new();
            while matches!(self.u8(*pos)? & 0xBF, 0x05 | 0x0D | 0x0E | 0x08 | 0x09 | 0x07) {
                value.push(self.value_token(pos)?);
            }
            el.attrs.push((attr, value));
        }
        match self.u8(*pos)? {
            0x02 => {
                *pos += 1;
                el.children = self.content(pos, end, depth + 1);
            }
            0x03 => *pos += 1,
            _ => return None,
        }
        Some(el)
    }

    fn value_token(&mut self, pos: &mut usize) -> Option<Node> {
        let token = self.u8(*pos)? & 0xBF;
        let at = *pos + 1;
        Some(match token {
            // Value text (type byte, then a counted string) and CDATA (counted string).
            0x05 | 0x07 => {
                let skip = usize::from(token == 0x05);
                let chars = usize::from(u16_le(self.chunk, at + skip)?);
                let raw = self.chunk.get(at + skip + 2..at + skip + 2 + 2 * chars)?;
                *pos = at + skip + 2 + 2 * chars;
                Node::Value(Value::Str(crate::text::utf16_at(raw, 0, raw.len())))
            }
            0x0D | 0x0E => {
                let id = u16_le(self.chunk, at)?;
                *pos = at + 3;
                Node::Sub(id)
            }
            0x08 => {
                let c = u16_le(self.chunk, at)?;
                *pos = at + 2;
                Node::Value(Value::Str(char::from_u32(u32::from(c)).map(String::from).unwrap_or_default()))
            }
            0x09 => {
                let (name, inline) = self.name(at)?;
                *pos = at + 4 + inline;
                let s = match name.as_str() {
                    "amp" => "&",
                    "lt" => "<",
                    "gt" => ">",
                    "quot" => "\"",
                    "apos" => "'",
                    _ => "",
                };
                Node::Value(Value::Str(s.to_string()))
            }
            _ => return None,
        })
    }

    /// Template instance: definition (inline or by offset), then the substitution values.
    fn template_instance(&mut self, pos: &mut usize, end: usize, depth: u8) -> Option<Node> {
        let def_offset = u32_le(self.chunk, *pos + 6)? as usize;
        *pos += 10;
        if def_offset == *pos {
            let size = u32_le(self.chunk, def_offset + 20)? as usize;
            *pos = def_offset.checked_add(24 + size)?;
        }
        let template = self.definition(def_offset, depth)?;
        let count = u32_le(self.chunk, *pos)? as usize;
        if count > MAX_VALUES {
            return None;
        }
        let descriptors: Vec<(usize, u8)> = (0..count)
            .map(|i| Some((usize::from(u16_le(self.chunk, *pos + 4 + 4 * i)?), self.u8(*pos + 6 + 4 * i)?)))
            .collect::<Option<_>>()?;
        *pos += 4 + 4 * count;
        let mut values = Vec::with_capacity(count);
        for (size, ty) in descriptors {
            let start = *pos;
            let stop = start.checked_add(size).filter(|s| *s <= end)?;
            let bytes = self.chunk.get(start..stop)?;
            values.push(match ty {
                TYPE_BINXML => {
                    let mut inner = start;
                    Value::Xml(self.content(&mut inner, stop, depth + 1))
                }
                TYPE_NULL => Value::Null,
                _ => Value::decode(ty, bytes),
            });
            *pos = stop;
        }
        let mut expanded = substitute(&template, &values);
        Some(if expanded.len() == 1 {
            expanded.remove(0)
        } else {
            Node::Element(Element { name: String::new(), attrs: Vec::new(), children: expanded })
        })
    }

    fn definition(&mut self, offset: usize, depth: u8) -> Option<Rc<Vec<Node>>> {
        if let Some(t) = self.templates.get(&offset) {
            return Some(t.clone());
        }
        let size = u32_le(self.chunk, offset + 20)? as usize;
        let start = offset.checked_add(24)?;
        let end = start.checked_add(size)?.min(self.chunk.len());
        let mut pos = start;
        let nodes = Rc::new(self.content(&mut pos, end, depth + 1));
        self.templates.insert(offset, nodes.clone());
        Some(nodes)
    }
}

/// Replace substitution placeholders with values; nested BinXML is spliced in, empty optional
/// values disappear.
fn substitute(nodes: &[Node], values: &[Value]) -> Vec<Node> {
    let mut out = Vec::new();
    for n in nodes {
        match n {
            Node::Sub(id) => match values.get(usize::from(*id)) {
                Some(Value::Xml(inner)) => out.extend(inner.iter().cloned()),
                Some(v) if !v.is_null() => out.push(Node::Value(v.clone())),
                _ => {}
            },
            Node::Element(e) => out.push(Node::Element(Element {
                name: e.name.clone(),
                attrs: e.attrs.iter().map(|(k, v)| (k.clone(), substitute(v, values))).collect(),
                children: substitute(&e.children, values),
            })),
            Node::Value(v) => out.push(Node::Value(v.clone())),
        }
    }
    out
}
