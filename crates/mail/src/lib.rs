//! Mail context: e-mail messages recovered from evidence.
//!
//! - [`Message`]: one message parsed from raw bytes with `mail-parser` (full MIME, base64 and
//!   quoted-printable, RFC 2047 words, single-byte Cyrillic charsets): [`Envelope`] (who, to
//!   whom, when, subject), every header, the body as readable text (HTML converted when there
//!   is no plain part) and attachment metadata. Attachments are re-extracted on demand from
//!   the raw message ([`Message::attachment`]).
//! - [`Container`]: what holds messages — `.eml`, mbox ([`MboxReader`], windowed), Outlook
//!   Express `.dbx` ([`Dbx`]) — recognised by name and by content.
//! - [`carve`]: message boundaries in free space.
//!
//! Damaged input never panics: cut or zeroed messages give what parsed plus notes.

pub mod carve;
mod container;
mod dbx;
mod envelope;
mod lines;
mod mbox;
mod message;
#[cfg(test)]
mod tests;

pub use container::Container;
pub use dbx::Dbx;
pub use envelope::{Envelope, Party, join};
pub use mbox::{MboxMessage, MboxReader, Span, WINDOW as MBOX_WINDOW, split as split_mbox};
pub use message::{Attachment, BODY_LIMIT, Message};
