//! Programs that matter for consistency, as data: cleaners and wipers (they explain missing
//! history and unrecoverable free space) and third-party browsers (installed but without
//! history is a cleaned or moved profile). The application layer queries with the words and
//! file stems listed here; the checks match precisely.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ToolKind {
    /// Deletes histories, temporary files and recent-document lists.
    Cleaner,
    /// Overwrites deleted files, free space or whole disks.
    Wiper,
}

#[derive(Debug)]
pub struct Tool {
    pub name: &'static str,
    pub kind: ToolKind,
    /// Lowercase words that name the program in install and run titles.
    pub titles: &'static [&'static str],
    /// Lowercase starts of its program or boot-image file names.
    pub files: &'static [&'static str],
}

pub const TOOLS: &[Tool] = &[
    Tool { name: "CCleaner", kind: ToolKind::Cleaner, titles: &["ccleaner"], files: &["ccleaner"] },
    Tool { name: "BleachBit", kind: ToolKind::Cleaner, titles: &["bleachbit"], files: &["bleachbit"] },
    Tool { name: "PrivaZer", kind: ToolKind::Cleaner, titles: &["privazer"], files: &["privazer"] },
    Tool { name: "Wise Disk Cleaner", kind: ToolKind::Cleaner, titles: &["wise disk cleaner"], files: &["wisediskcleaner"] },
    Tool { name: "Evidence Eliminator", kind: ToolKind::Cleaner, titles: &["evidence eliminator"], files: &[] },
    Tool { name: "Window Washer", kind: ToolKind::Cleaner, titles: &["window washer"], files: &["windowwasher"] },
    Tool { name: "Eraser", kind: ToolKind::Wiper, titles: &["eraser"], files: &["eraser"] },
    Tool { name: "SDelete", kind: ToolKind::Wiper, titles: &["sdelete"], files: &["sdelete"] },
    Tool { name: "DBAN", kind: ToolKind::Wiper, titles: &["dban", "darik's boot and nuke"], files: &["dban"] },
    Tool { name: "KillDisk", kind: ToolKind::Wiper, titles: &["killdisk"], files: &["killdisk"] },
    Tool { name: "HDShredder", kind: ToolKind::Wiper, titles: &["hdshredder"], files: &["hdshredder"] },
    Tool { name: "File Shredder", kind: ToolKind::Wiper, titles: &["file shredder"], files: &["fileshredder"] },
    Tool { name: "Blancco", kind: ToolKind::Wiper, titles: &["blancco"], files: &["blancco"] },
];

/// File extensions a tool's file must have (programs and boot images).
const TOOL_EXTENSIONS: &[&str] = &[".exe", ".iso"];

#[derive(Debug)]
pub struct Browser {
    pub name: &'static str,
    /// Lowercase words of its install title.
    pub titles: &'static [&'static str],
    /// Lowercase program file names.
    pub files: &'static [&'static str],
    /// Parsers that store its history (artifact name starts).
    pub artifacts: &'static [&'static str],
}

/// Browsers whose history Strata reads. Built-in browsers (Internet Explorer, Edge) are left
/// out: they are present on every Windows whether anyone used them or not.
pub const BROWSERS: &[Browser] = &[
    Browser { name: "Google Chrome", titles: &["google chrome"], files: &["chrome.exe"], artifacts: &["chrome."] },
    Browser { name: "Mozilla Firefox", titles: &["mozilla firefox"], files: &["firefox.exe"], artifacts: &["firefox."] },
    Browser { name: "Opera", titles: &["opera"], files: &["opera.exe"], artifacts: &["opera."] },
];

/// Every title word to query program events with (a superset; checks match precisely).
pub fn program_words() -> Vec<&'static str> {
    TOOLS.iter().flat_map(|t| t.titles.iter()).chain(BROWSERS.iter().flat_map(|b| b.titles.iter())).copied().collect()
}

/// Every file-name start to query the file index with.
pub fn file_stems() -> Vec<&'static str> {
    TOOLS.iter().flat_map(|t| t.files.iter()).chain(BROWSERS.iter().flat_map(|b| b.files.iter())).copied().collect()
}

/// `word` appears in `text` (lowercase) at the start of a word.
pub(crate) fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| text[..i].chars().next_back().is_none_or(|c| !c.is_alphanumeric()))
}

impl Tool {
    pub fn names_title(&self, title: &str) -> bool {
        let lower = title.to_lowercase();
        self.titles.iter().any(|w| has_word(&lower, w))
    }

    pub fn names_file(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        TOOL_EXTENSIONS.iter().any(|e| lower.ends_with(e)) && self.files.iter().any(|s| lower.starts_with(s))
    }
}

impl Browser {
    pub fn names_title(&self, title: &str) -> bool {
        let lower = title.to_lowercase();
        self.titles.iter().any(|w| has_word(&lower, w))
    }

    pub fn names_file(&self, name: &str) -> bool {
        let lower = name.to_lowercase();
        self.files.iter().any(|f| lower == *f)
    }

    pub fn stores(&self, artifact: &str) -> bool {
        self.artifacts.iter().any(|a| artifact.starts_with(a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_match_at_word_starts_only() {
        let eraser = TOOLS.iter().find(|t| t.name == "Eraser").unwrap();
        assert!(eraser.names_title("Eraser 6.2.0.2993"));
        assert!(eraser.names_title(r"C:\Program Files\Eraser\Eraser.exe"));
        assert!(!eraser.names_title("Photo BackgroundEraser"));
        assert!(eraser.names_file("Eraser.exe"));
        assert!(!eraser.names_file("eraser.dll"));
        let chrome = &BROWSERS[0];
        assert!(chrome.names_title("Google Chrome"));
        assert!(chrome.names_file("chrome.exe") && !chrome.names_file("chrome.exe.bak"));
        assert!(chrome.stores("chrome.history") && !chrome.stores("firefox.places"));
        assert!(program_words().contains(&"ccleaner") && file_stems().contains(&"sdelete"));
    }
}
