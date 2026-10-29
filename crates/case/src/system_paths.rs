//! Where installed operating-system and program files live. Findings inside them are almost
//! always byte patterns that merely look like keys or addresses (class names in `rt.jar`, API
//! names in DLLs, maintainer e-mails in package lists). One rule set, used both in Rust (while
//! a scan stores findings) and in SQL (triage of stored findings).

/// Path prefixes (lower case, `/`-separated) of installed system and program files.
const PREFIXES: &[&str] = &["windows/", "winnt/", "program files/", "program files (x86)/", "programdata/microsoft/", "i386/", "$orphans/$"];

/// Linux system folders (lower case), matched anywhere in the path so copies under
/// container layers (`var/lib/docker/overlay2/<id>/diff/usr/...`) and chroots count too.
const FOLDERS: &[&str] = &[
    "usr/share/", "usr/lib/", "usr/lib32/", "usr/lib64/", "usr/include/", "usr/src/", "usr/bin/", "usr/sbin/",
    "lib/modules/", "lib/firmware/", "var/lib/dpkg/", "var/lib/apt/lists/", "var/cache/apt/", "var/lib/rpm/",
    "var/lib/snapd/", "snap/core", "boot/",
];

/// Extensions of binaries, fonts and linguistic data that never hold user keys.
const EXTENSIONS: &[&str] = &[
    "dll", "exe", "sys", "ocx", "cpl", "drv", "mui", "jar", "class", "ttf", "ttc", "fon", "otf", "nls", "chs", "cht",
    "lex", "dic", "msi", "msp", "cab", "cat", "manifest", "pnf", "inf", "chm", "hlp", "so", "ko", "pm", "pyc", "mo",
    "a", "o", "dylib", "node", "wasm",
];

/// Versioned shared libraries (`libgcrypt.so.20.1.6`): their last extension is a number.
const VERSIONED_LIBRARY: &str = ".so.";

/// Is `path` (as stored in the case, `/`-separated, relative to its volume) a system file?
pub fn is_system_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    PREFIXES.iter().any(|x| p.starts_with(x))
        || FOLDERS.iter().any(|f| p.starts_with(f) || p.contains(&format!("/{f}")))
        || p.rsplit_once('.').is_some_and(|(_, ext)| EXTENSIONS.contains(&ext))
        || p.contains(VERSIONED_LIBRARY)
}

/// The same rule as an SQL condition on `column` (rules are crate constants, not user input).
pub(crate) fn sql_condition(column: &str) -> String {
    let c = format!("lower({column})");
    let rules: Vec<String> = PREFIXES
        .iter()
        .map(|p| format!("{c} LIKE '{p}%'"))
        .chain(FOLDERS.iter().map(|f| format!("{c} LIKE '{f}%' OR {c} LIKE '%/{f}%'")))
        .chain(EXTENSIONS.iter().map(|e| format!("{c} LIKE '%.{e}'")))
        .chain(std::iter::once(format!("{c} LIKE '%{VERSIONED_LIBRARY}%'")))
        .collect();
    format!("({})", rules.join(" OR "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_paths() {
        assert!(is_system_path("WINDOWS/system32/x.txt"));
        assert!(is_system_path("var/lib/docker/overlay2/ab12/diff/usr/share/doc/a/copyright"));
        assert!(is_system_path("var/lib/apt/lists/archive.ubuntu.com_dists_Packages"));
        assert!(is_system_path("home/u/lib/libssl.so"));
        assert!(is_system_path("var/lib/docker/overlay2/b6/diff/lib/x86_64-linux-gnu/libgcrypt.so.20.1.6"));
        assert!(!is_system_path("home/u/Documents/wallet backup.txt"));
        assert!(!is_system_path("Documents and Settings/u/Application Data/Bitcoin/wallet.dat"));
        assert!(!is_system_path("home/u/reboot/notes.txt"));
    }
}
