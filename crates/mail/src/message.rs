//! A whole message: envelope, every header, the body as readable text and what is attached.
//! Damaged messages (cut off, zeroed, broken MIME) still give whatever parsed, with notes.

use crate::envelope::Envelope;
use mail_parser::{Charset, MessageParser, MessagePart, MessageRef, PartKind};
use serde::{Deserialize, Serialize};

/// Body text kept per message; longer bodies are cut with a note.
pub const BODY_LIMIT: usize = 512 * 1024;
/// Headers kept per message (trace headers of a mail loop can run into thousands).
const HEADER_LIMIT: usize = 200;
/// A run of zero bytes this long inside a message means overwritten sectors.
const ZERO_RUN: usize = 64;

/// Metadata of one attachment; the bytes are extracted on demand ([`Message::attachment`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub mime: String,
    /// Decoded size in bytes.
    pub size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub envelope: Envelope,
    /// Every header as `(name, value)`, values unfolded and decoded where the form is known.
    pub headers: Vec<(String, String)>,
    /// Plain-text body; an HTML-only message is converted to text.
    pub body: String,
    /// The body came from an HTML part.
    pub body_from_html: bool,
    pub attachments: Vec<Attachment>,
    /// What was damaged or cut.
    pub notes: Vec<String>,
}

impl Message {
    /// Parse a message. `None` only when the bytes hold no recognisable header at all.
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let parsed = MessageParser::new().parse(raw)?;
        let root = parsed.root();
        let envelope = Envelope::of(root);
        if envelope.is_empty() {
            return None;
        }
        let mut msg = Message { envelope, headers: headers(root), ..Default::default() };
        msg.read_body(root);
        msg.attachments = root.attachments().enumerate().map(|(i, p)| attachment(i, p)).collect();
        for part in parsed.parts() {
            msg.notes.extend(part.flags().names().map(|f| format!("MIME structure: {}", f.replace('_', " ").to_lowercase())));
        }
        msg.notes.extend(zero_note(raw));
        msg.notes.dedup();
        Some(msg)
    }

    /// Decoded bytes of the `index`-th attachment of the message in `raw`.
    pub fn attachment(raw: &[u8], index: usize) -> Option<(Attachment, Vec<u8>)> {
        let parsed = MessageParser::new().parse(raw)?;
        let part = parsed.root().attachments().nth(index)?;
        Some((attachment(index, part), part.decoded().into_owned()))
    }

    fn read_body(&mut self, root: MessageRef<'_>) {
        let mut text = String::new();
        for part in root.text_body() {
            let (piece, html) = match part.kind() {
                PartKind::Text => (part_text(part, &mut self.notes), false),
                PartKind::Html => (part_text(part, &mut self.notes).map(|h| mail_parser::html_to_text(&h)), true),
                _ => (None, false),
            };
            if let Some(piece) = piece {
                self.body_from_html |= html;
                if !text.is_empty() {
                    text.push_str("\n\n");
                }
                text.push_str(&piece);
            }
        }
        let text = text.replace("\r\n", "\n");
        if text.len() > BODY_LIMIT {
            let cut = (0..=BODY_LIMIT).rev().find(|i| text.is_char_boundary(*i)).unwrap_or(0);
            self.body = text[..cut].to_string();
            self.notes.push(format!("body cut at {} KiB", BODY_LIMIT / 1024));
        } else {
            self.body = text;
        }
    }

    /// Readable one-line summary for logs.
    pub fn summary(&self) -> String {
        let e = &self.envelope;
        format!("{} → {}: {}", crate::envelope::join(&e.from), crate::envelope::join(&e.to), e.subject)
    }
}

/// Text of a body part. A part without a declared charset that is not valid UTF-8 is read as
/// Windows-1251 (Russian mail clients of the 2000s often left the charset out).
fn part_text(part: MessagePart<'_>, notes: &mut Vec<String>) -> Option<String> {
    let declared = part.content_type().and_then(|c| c.attribute("charset")).is_some();
    let (text, problems) = part.text_checked()?;
    if !problems.is_empty() {
        notes.extend(problems.names().map(|p| format!("body: {}", p.replace('_', " ").to_lowercase())));
    }
    if !declared && text.contains('\u{FFFD}') {
        let bytes = part.decoded();
        if std::str::from_utf8(&bytes).is_err() {
            return Some(Charset::Windows1251.decode(&bytes).into_owned());
        }
    }
    Some(text.into_owned())
}

fn attachment(index: usize, part: MessagePart<'_>) -> Attachment {
    let mime = part
        .content_type()
        .map(|c| match c.subtype() {
            Some(sub) => format!("{}/{sub}", c.ctype()),
            None => c.ctype().to_string(),
        })
        .unwrap_or_else(|| "application/octet-stream".into())
        .to_ascii_lowercase();
    let name = part.attachment_name().map(str::trim).filter(|n| !n.is_empty()).map_or_else(|| format!("attachment-{}", index + 1), str::to_string);
    Attachment { name, mime, size: part.decoded_len() as u64 }
}

/// Headers as written (unfolded); encoded words are decoded where the value parses as text or
/// as addresses.
fn headers(root: MessageRef<'_>) -> Vec<(String, String)> {
    root.headers()
        .iter()
        .take(HEADER_LIMIT)
        .map(|h| {
            let raw = String::from_utf8_lossy(h.raw_value()).split_whitespace().collect::<Vec<_>>().join(" ");
            let value = h.value();
            let decoded = if raw.contains("=?") {
                value.as_text().map(str::to_string).or_else(|| value.as_address().map(|a| crate::envelope::join(&crate::envelope::parties(Some(a)))))
            } else {
                None
            };
            (h.raw_name().to_string(), decoded.unwrap_or(raw))
        })
        .collect()
}

/// A note when runs of zero bytes sit inside the message (overwritten or never written).
fn zero_note(raw: &[u8]) -> Option<String> {
    let mut zeroed = 0usize;
    let mut run = 0usize;
    for &b in raw {
        if b == 0 {
            run += 1;
        } else {
            if run >= ZERO_RUN {
                zeroed += run;
            }
            run = 0;
        }
    }
    if run >= ZERO_RUN {
        zeroed += run;
    }
    (zeroed > 0).then(|| format!("{zeroed} bytes zeroed (overwritten or unwritten sectors)"))
}
