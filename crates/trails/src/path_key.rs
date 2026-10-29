//! One spelling for a path however a trace wrote it: `C:\Documents and Settings\A\wallet.dat`
//! (LNK), `\DEVICE\HARDDISKVOLUME1\DOCUMENTS AND SETTINGS\A\WALLET.DAT` (Prefetch),
//! `Documents and Settings/A/wallet.dat` (file table) and `/home/a/.bitcoin/wallet.dat` all
//! become `documents and settings/a/wallet.dat` or `home/a/.bitcoin/wallet.dat`.

/// A normalised path: lower case, `/`, no drive, device or leading slash. A bare name (no
/// folder) is kept as is; the trace did not say where the file was.
/// Equal when the paths are; the drive letter is only a hint (disks get other letters).
#[derive(Debug, Clone)]
pub(crate) struct PathKey {
    key: String,
    /// Drive letter the trace named (`c`), if any.
    drive: Option<char>,
}

impl PartialEq for PathKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for PathKey {}

impl PathKey {
    pub fn of(path: &str) -> Self {
        let mut p = path.trim().replace('\\', "/").to_lowercase();
        for prefix in ["//?/", "/??/", "file:///"] {
            if let Some(rest) = p.strip_prefix(prefix) {
                p = rest.to_string();
            }
        }
        let mut drive = None;
        let trimmed = p.trim_start_matches('/');
        let p = if let Some(rest) = trimmed.strip_prefix("device/harddiskvolume") {
            rest.trim_start_matches(|c: char| c.is_ascii_digit()).trim_start_matches('/').to_string()
        } else {
            match trimmed.as_bytes() {
                [d, b':', b'/', ..] if d.is_ascii_alphabetic() => {
                    drive = Some(*d as char);
                    trimmed[3..].to_string()
                }
                _ => trimmed.to_string(),
            }
        };
        Self { key: p, drive }
    }

    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// The last component (`wallet.dat`); inside an archive, the member's own name.
    pub fn name(&self) -> &str {
        self.key.rsplit('/').find(|s| !s.is_empty()).unwrap_or(&self.key)
    }

    /// Only a name: the trace did not say which folder.
    pub fn is_bare(&self) -> bool {
        !self.key.contains('/')
    }

    pub fn drive(&self) -> Option<char> {
        self.drive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spellings_meet() {
        let want = "documents and settings/a/wallet.dat";
        for p in [
            "C:\\Documents and Settings\\A\\wallet.dat",
            "\\DEVICE\\HARDDISKVOLUME1\\DOCUMENTS AND SETTINGS\\A\\WALLET.DAT",
            "Documents and Settings/A/wallet.dat",
            "\\\\?\\C:\\Documents and Settings\\A\\wallet.dat",
        ] {
            assert_eq!(PathKey::of(p).as_str(), want, "{p}");
        }
        assert_eq!(PathKey::of("/home/a/.bitcoin/wallet.dat").as_str(), "home/a/.bitcoin/wallet.dat");
        assert_eq!(PathKey::of("D:\\backup\\w.dat").drive(), Some('d'));
        let bare = PathKey::of("wallet.dat");
        assert!(bare.is_bare() && bare.name() == "wallet.dat");
        assert_eq!(PathKey::of("old.zip!/keys/wallet.dat").name(), "wallet.dat");
    }
}
