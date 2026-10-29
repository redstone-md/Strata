//! Report context: one [`CaseReport`] model, several renderers.

mod model;
mod render;

pub use model::{CaseReport, EvidenceSummary};
pub use render::{CsvRenderer, HtmlRenderer, JsonRenderer, MarkdownRenderer, Renderer, renderer_for};
