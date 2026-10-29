//! What a file's name and folder say about wallets: `wallet.dat`, Electrum and MultiBit wallet
//! files, keystores, and notes named like key backups (`privkey.txt`, `сид фраза.docx`). One
//! table for every place that judges names: the wallet-file parse step, timeline signals,
//! confidence triage and wallet trails.

/// Kind of wallet-relevant file a name points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum WalletNameKind {
    /// Bitcoin Core (and forks) `wallet.dat`.
    BitcoinCore,
    Electrum,
    MultiBit,
    Armory,
    /// Blockchain.info `wallet.aes.json`.
    BlockchainInfo,
    /// Ethereum-style keystore (`UTC--…`, `keystore/`).
    Keystore,
    /// A document or archive named like a key, seed or wallet backup.
    KeyNote,
}

impl WalletNameKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::BitcoinCore => "Bitcoin Core wallet",
            Self::Electrum => "Electrum wallet",
            Self::MultiBit => "MultiBit wallet",
            Self::Armory => "Armory wallet",
            Self::BlockchainInfo => "Blockchain.info wallet",
            Self::Keystore => "keystore",
            Self::KeyNote => "key or seed note",
        }
    }

    /// Word the creating program's name contains (`Bitcoin` for `Bitcoin Core`, `Bitcoin-Qt`).
    pub fn software_word(self) -> Option<&'static str> {
        match self {
            Self::BitcoinCore => Some("bitcoin"),
            Self::Electrum => Some("electrum"),
            Self::MultiBit => Some("multibit"),
            Self::Armory => Some("armory"),
            Self::BlockchainInfo => Some("blockchain"),
            Self::Keystore | Self::KeyNote => None,
        }
    }

    /// A wallet program's own file (not a note a person saved).
    pub fn is_wallet_file(self) -> bool {
        !matches!(self, Self::KeyNote)
    }
}

/// How much a word in a file name says on its own.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Weight {
    /// Enough alone (`privkey`, `seed`, `кошелёк`).
    Strong,
    /// Only together with another word (`btc backup.txt`).
    Weak,
}

/// Words (lower case) in names of key and wallet backups. Data: the single place to extend.
const NAME_WORDS: &[(&str, Weight)] = &[
    ("wallet", Weight::Strong),
    ("privkey", Weight::Strong),
    ("priv_key", Weight::Strong),
    ("private key", Weight::Strong),
    ("private_key", Weight::Strong),
    ("seed", Weight::Strong),
    ("mnemonic", Weight::Strong),
    ("bitcoin", Weight::Strong),
    ("биткоин", Weight::Strong),
    ("биткойн", Weight::Strong),
    ("кошел", Weight::Strong),
    ("мнемон", Weight::Strong),
    ("приватн", Weight::Strong),
    ("priv", Weight::Weak),
    ("btc", Weight::Weak),
    ("backup", Weight::Weak),
    ("ключ", Weight::Weak),
];

/// Extensions a person saves notes and backups in; other files named `wallet` are program
/// parts (icons, pages, scripts).
const NOTE_EXTENSIONS: &[&str] = &[
    "", "txt", "text", "doc", "docx", "rtf", "odt", "xls", "xlsx", "ods", "csv", "pdf", "json", "bak", "zip", "rar", "7z", "gz", "tgz", "tar", "aes",
    "gpg", "pgp", "asc", "key",
];

/// Substrings (lower case) of text that mentions a wallet file by name.
const MENTION_WORDS: &[&str] = &["wallet.dat", ".wallet", "wallet.aes.json", "default_wallet", "multibit.key", "electrum.dat", ".kwm"];

/// Folder fragments (lower case, `/`) whose files are wallets whatever their name.
const WALLET_FOLDERS: &[(&str, WalletNameKind)] = &[
    ("electrum/wallets/", WalletNameKind::Electrum),
    (".electrum/wallets/", WalletNameKind::Electrum),
    ("/keystore/", WalletNameKind::Keystore),
];

/// Classifies file names and paths by what they say about wallets.
pub struct WalletFileName;

impl WalletFileName {
    /// Kind of wallet-relevant file at `path` (`C:\…`, `/home/…` or a case path), if any.
    pub fn classify(path: &str) -> Option<WalletNameKind> {
        let p = path.replace('\\', "/").to_lowercase();
        let name = p.rsplit('/').next().unwrap_or(&p);
        let framed = format!("/{p}");
        if name.is_empty() {
            return None;
        }
        let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
        let kind = if name == "wallet.dat" || ext == "dat" && name.contains("wallet") {
            WalletNameKind::BitcoinCore
        } else if name.starts_with("armory_") && ext == "wallet" {
            WalletNameKind::Armory
        } else if name.contains("wallet.aes.json") {
            WalletNameKind::BlockchainInfo
        } else if ext == "wallet" || name.ends_with(".wallet.aes") || name == "multibit.key" || framed.contains("/multibit") && ext == "key" {
            WalletNameKind::MultiBit
        } else if name == "default_wallet" || name == "electrum.dat" {
            WalletNameKind::Electrum
        } else if name.starts_with("utc--") {
            WalletNameKind::Keystore
        } else if let Some((_, kind)) = WALLET_FOLDERS.iter().find(|(f, _)| framed.contains(f) && !name.ends_with(".log")) {
            *kind
        } else if Self::is_note_name(name, ext) {
            WalletNameKind::KeyNote
        } else {
            return None;
        };
        Some(kind)
    }

    /// A name like `privkey.txt`, `btc backup.zip`, `Кошелёк.docx`.
    fn is_note_name(name: &str, ext: &str) -> bool {
        if !NOTE_EXTENSIONS.contains(&ext) {
            return false;
        }
        let stem = name.strip_suffix(&format!(".{ext}")).unwrap_or(name);
        let strong = NAME_WORDS.iter().any(|(w, weight)| *weight == Weight::Strong && stem.contains(w));
        let weak = NAME_WORDS.iter().filter(|(w, weight)| *weight == Weight::Weak && stem.contains(w)).count();
        strong || weak >= 2
    }

    /// Does `text` (any case) name a wallet file (`C:\backup\wallet.dat`, `x.wallet`)?
    pub fn mentioned_in(text: &str) -> bool {
        let lower = text.to_lowercase();
        MENTION_WORDS.iter().any(|w| lower.contains(w))
    }

    /// Should the wallet-file step read this file whole and try the parsers? Wider than
    /// [`Self::classify`]: the parser confirms the content.
    pub fn is_parse_candidate(path: &str, name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        let path = path.to_ascii_lowercase();
        name.contains("wallet")
            || name.ends_with(".key")
            || name.ends_with(".dat") && (path.contains("bitcoin") || path.contains("litecoin"))
            || path.contains("electrum") && path.contains("wallets")
            || path.contains("multibit")
            || path.contains("armory")
    }

    /// Every name word (lower case), strong and weak: files named with any of them are
    /// treated as possible key backups.
    pub fn name_words() -> impl Iterator<Item = &'static str> {
        NAME_WORDS.iter().map(|(w, _)| *w)
    }

    /// Substrings one of which every name [`Self::classify`] accepts contains, for a cheap
    /// prefilter (`name LIKE '%…%'`). Non-ASCII words come in the cases a name is written in,
    /// since SQL `LIKE` folds ASCII only.
    pub fn name_terms() -> Vec<String> {
        let mut terms: Vec<String> = ["wallet", "armory_", ".key", "default_wallet", "electrum.dat", "utc--", ".kwm"].iter().map(|s| s.to_string()).collect();
        for w in NAME_WORDS.iter().map(|(w, _)| *w) {
            if w.is_ascii() {
                terms.push(w.to_string());
            } else {
                let mut chars = w.chars();
                let first: String = chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default();
                terms.extend([w.to_string(), first, w.to_uppercase()]);
            }
        }
        terms.sort();
        terms.dedup();
        terms
    }

    /// Folder fragments (lower case, `/`) whose files count whatever their name.
    pub fn folder_terms() -> impl Iterator<Item = &'static str> {
        WALLET_FOLDERS.iter().map(|(f, _)| *f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use WalletNameKind::*;

    #[test]
    fn classifies_names_and_folders() {
        let c = WalletFileName::classify;
        assert_eq!(c("C:\\Documents and Settings\\a\\Application Data\\Bitcoin\\wallet.dat"), Some(BitcoinCore));
        assert_eq!(c("backup/old-wallet.dat"), Some(BitcoinCore));
        assert_eq!(c("Users/a/AppData/Roaming/Electrum/wallets/my_btc"), Some(Electrum));
        assert_eq!(c("home/u/.electrum/wallets/default_wallet"), Some(Electrum));
        assert_eq!(c("Users/a/MultiBit/multibit.wallet"), Some(MultiBit));
        assert_eq!(c("Users/a/Armory/armory_2xYz_.wallet"), Some(Armory));
        assert_eq!(c("Users/a/Desktop/wallet.aes.json"), Some(BlockchainInfo));
        assert_eq!(c("home/u/.ethereum/keystore/UTC--2016-01-01T00-00-00Z--abc"), Some(Keystore));
        assert_eq!(c("Users/a/Desktop/privkey.txt"), Some(KeyNote));
        assert_eq!(c("Users/a/Desktop/Мой Кошелёк.docx"), Some(KeyNote));
        assert_eq!(c("Users/a/Desktop/btc backup.zip"), Some(KeyNote));
        assert_eq!(c("Users/a/Desktop/backup.zip"), None, "one weak word is not enough");
        assert_eq!(c("Program/wallet.png"), None, "program parts are not notes");
        assert_eq!(c("Users/a/Desktop/notes.txt"), None);
        assert_eq!(c(""), None);
    }

    #[test]
    fn mentions_candidates_and_terms() {
        assert!(WalletFileName::mentioned_in("C:\\BACKUP\\WALLET.DAT"));
        assert!(!WalletFileName::mentioned_in("https://example.com/"));
        assert!(WalletFileName::is_parse_candidate("x/Bitcoin/blk0001.dat", "blk0001.dat"));
        assert!(!WalletFileName::is_parse_candidate("x/readme.txt", "readme.txt"));
        let terms = WalletFileName::name_terms();
        assert!(terms.contains(&"Кошел".to_string()) && terms.contains(&"КОШЕЛ".to_string()));
        for name in ["wallet.dat", "x.wallet", "privkey.txt", "Мой Кошелёк.docx", "UTC--1", "armory_x.wallet"] {
            assert!(terms.iter().any(|t| name.to_lowercase().contains(&t.to_lowercase())), "{name}");
        }
    }
}
