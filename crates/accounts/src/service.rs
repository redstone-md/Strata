use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ServiceKind {
    /// Bitcoin exchanges, faucets, web wallets, forums — direct wallet leads.
    Crypto,
    /// E-payment systems (WebMoney, QIWI, PayPal, Yandex.Money).
    Payment,
    Mail,
    Social,
    Other,
}

/// Known service domains (data table, the single place to extend).
const DOMAINS: &[(&str, ServiceKind, &str)] = &[
    ("bitcoin.org", ServiceKind::Crypto, "Bitcoin.org"),
    ("bitcointalk.org", ServiceKind::Crypto, "Bitcointalk"),
    ("mtgox.com", ServiceKind::Crypto, "Mt. Gox"),
    ("blockchain.info", ServiceKind::Crypto, "Blockchain.info wallet"),
    ("blockchain.com", ServiceKind::Crypto, "Blockchain.com wallet"),
    ("instawallet.org", ServiceKind::Crypto, "Instawallet"),
    ("mybitcoin.com", ServiceKind::Crypto, "MyBitcoin"),
    ("slushpool.com", ServiceKind::Crypto, "Slush pool"),
    ("mining.bitcoin.cz", ServiceKind::Crypto, "Slush pool"),
    ("btc-e.com", ServiceKind::Crypto, "BTC-e"),
    ("btce", ServiceKind::Crypto, "BTC-e"),
    ("bitstamp.net", ServiceKind::Crypto, "Bitstamp"),
    ("coinbase.com", ServiceKind::Crypto, "Coinbase"),
    ("electrum.org", ServiceKind::Crypto, "Electrum"),
    ("multibit.org", ServiceKind::Crypto, "MultiBit"),
    ("bitcoinarmory.com", ServiceKind::Crypto, "Armory"),
    ("faucet", ServiceKind::Crypto, "Bitcoin faucet"),
    ("freebitcoins", ServiceKind::Crypto, "Free bitcoins faucet"),
    ("deepbit.net", ServiceKind::Crypto, "DeepBit pool"),
    ("bitcoinica", ServiceKind::Crypto, "Bitcoinica"),
    ("tradehill.com", ServiceKind::Crypto, "TradeHill"),
    ("localbitcoins.com", ServiceKind::Crypto, "LocalBitcoins"),
    ("webmoney", ServiceKind::Payment, "WebMoney"),
    ("wmtransfer.com", ServiceKind::Payment, "WebMoney"),
    ("qiwi", ServiceKind::Payment, "QIWI"),
    ("paypal.com", ServiceKind::Payment, "PayPal"),
    ("money.yandex", ServiceKind::Payment, "Yandex.Money"),
    ("liberty reserve", ServiceKind::Payment, "Liberty Reserve"),
    ("libertyreserve.com", ServiceKind::Payment, "Liberty Reserve"),
    ("mail.ru", ServiceKind::Mail, "Mail.ru"),
    ("yandex.ru", ServiceKind::Mail, "Yandex"),
    ("gmail.com", ServiceKind::Mail, "Gmail"),
    ("rambler.ru", ServiceKind::Mail, "Rambler"),
    ("hotmail.com", ServiceKind::Mail, "Hotmail"),
    ("yahoo.com", ServiceKind::Mail, "Yahoo"),
    ("vkontakte.ru", ServiceKind::Social, "VKontakte"),
    ("vk.com", ServiceKind::Social, "VKontakte"),
    ("odnoklassniki.ru", ServiceKind::Social, "Odnoklassniki"),
    ("facebook.com", ServiceKind::Social, "Facebook"),
    ("icq.com", ServiceKind::Social, "ICQ"),
    ("skype", ServiceKind::Social, "Skype"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub kind: ServiceKind,
    pub name: &'static str,
}

impl Service {
    /// Classify a URL, domain or e-mail against the known-service table. Needles match on
    /// word boundaries only (`proslushivat` is not Slush pool, `vk.com` is not `qvk.community`).
    pub fn classify(text: &str) -> Option<Service> {
        let lower = text.to_ascii_lowercase();
        DOMAINS
            .iter()
            .find(|(needle, _, _)| contains_word(&lower, needle))
            .map(|&(_, kind, name)| Service { kind, name })
    }
}

/// `needle` occurs in `hay` with no letter or digit directly before or after it.
fn contains_word(hay: &str, needle: &str) -> bool {
    let bytes = hay.as_bytes();
    let is_word = |i: usize| bytes.get(i).is_some_and(|b| b.is_ascii_alphanumeric());
    hay.match_indices(needle).any(|(at, _)| (at == 0 || !is_word(at - 1)) && !is_word(at + needle.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_on_word_boundaries() {
        assert!(Service::classify("news/specslujbi_smogut_proslushivat_skype.html").is_some_and(|s| s.name == "Skype"));
        assert!(Service::classify("http://slushpool.com/stats").is_some_and(|s| s.kind == ServiceKind::Crypto));
        assert!(Service::classify("https://www.bitcointalk.org/x").is_some_and(|s| s.name == "Bitcointalk"));
        assert!(Service::classify("user@mail.ru").is_some_and(|s| s.name == "Mail.ru"));
        assert!(Service::classify("hotmail.company.net").is_none());
    }
}
