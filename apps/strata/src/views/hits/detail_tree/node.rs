//! The detail tree's data model, independent of GPUI so the JSON → tree mapping is testable.

/// What sits right of a row's label.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    /// Plain UI text.
    Text(String),
    /// A data value (key, address, hex, path, phrase): data face.
    Data(String),
    /// Secondary text ("never used", "none").
    Quiet(String),
    /// Small state label; `true` = inverted (warnings).
    Badge(String, bool),
    /// 0..=1 as a thin bar plus its percentage.
    Bar(f32),
}

#[derive(Debug, Clone, PartialEq)]
pub struct TreeNode {
    pub label: String,
    pub cell: Option<Cell>,
    /// Text put on the clipboard by the row's Copy button.
    pub copy: Option<String>,
    pub children: Vec<TreeNode>,
    /// Groups start open unless closed here; the user's toggles override it.
    pub open: bool,
    /// An outlined note spanning the row (no label column).
    pub note: bool,
}

impl TreeNode {
    pub fn row(label: impl Into<String>, cell: Cell) -> Self {
        Self { label: label.into(), cell: Some(cell), copy: None, children: Vec::new(), open: true, note: false }
    }

    pub fn text(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::row(label, Cell::Text(value.into()))
    }

    /// A data value with a Copy button.
    pub fn data(label: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        Self { copy: Some(value.clone()), ..Self::row(label, Cell::Data(value)) }
    }

    pub fn quiet(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self::row(label, Cell::Quiet(value.into()))
    }

    pub fn yes_no(label: impl Into<String>, value: bool) -> Self {
        Self::text(label, if value { "yes" } else { "no" })
    }

    pub fn note(text: impl Into<String>) -> Self {
        Self { note: true, ..Self::text("", text) }
    }

    pub fn group(label: impl Into<String>, children: Vec<TreeNode>) -> Self {
        Self { label: label.into(), cell: None, copy: None, children, open: true, note: false }
    }

    /// Summary shown on the group row itself.
    pub fn summary(mut self, cell: Cell) -> Self {
        self.cell = Some(cell);
        self
    }

    pub fn closed(mut self) -> Self {
        self.open = false;
        self
    }

    pub fn open_if(mut self, open: bool) -> Self {
        self.open = open;
        self
    }

    pub fn is_group(&self) -> bool {
        !self.children.is_empty()
    }

    /// Depth-first search by label.
    #[cfg(test)]
    pub fn find(&self, label: &str) -> Option<&TreeNode> {
        if self.label == label {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find(label))
    }
}

/// Find a node by label anywhere in a forest.
#[cfg(test)]
pub fn find<'a>(nodes: &'a [TreeNode], label: &str) -> Option<&'a TreeNode> {
    nodes.iter().find_map(|n| n.find(label))
}

/// Drop empty groups (a group whose source field was absent).
pub fn non_empty(nodes: Vec<TreeNode>) -> Vec<TreeNode> {
    nodes.into_iter().filter(|n| n.cell.is_some() || n.is_group() || n.note).collect()
}
