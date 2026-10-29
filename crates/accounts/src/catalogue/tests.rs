use super::*;

fn cat() -> &'static Catalogue {
    Catalogue::shared()
}

#[test]
fn embedded_catalogue_parses_and_is_large() {
    let c = cat();
    assert_eq!(c.version(), 1);
    assert!(c.entries().len() >= 300, "only {} services", c.entries().len());
    for kind in [ServiceKind::Faucet, ServiceKind::Exchange, ServiceKind::MiningPool, ServiceKind::WebWallet, ServiceKind::WalletSoftware] {
        let n = c.entries().iter().filter(|e| e.kind() == kind).count();
        assert!(n >= 20, "{kind:?}: {n}");
    }
}

#[test]
fn no_duplicate_domains_or_ids() {
    let c = cat();
    let mut domains = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for e in c.entries() {
        assert!(ids.insert(e.id()), "duplicate id {}", e.id());
        assert!(!e.name().is_empty() && e.id() == e.id().to_lowercase());
        for d in e.domains() {
            assert_eq!(d, &d.to_lowercase(), "{d} must be lowercase");
            assert!(!d.starts_with("www.") && !d.contains("://"), "{d}: bare host expected");
            assert!(domains.insert(d.clone()) || e.domains().iter().filter(|x| *x == d).count() > 1, "duplicate domain {d}");
        }
    }
    let dup = "version = 1\nservice = [\n{ id = \"a\", name = \"A\", kind = \"exchange\", domains = [\"x.com\"] },\n\
               { id = \"b\", name = \"B\", kind = \"faucet\", domains = [\"x.com\"] },\n]";
    assert!(Catalogue::parse(dup).err().is_some_and(|e| e.contains("x.com")));
}

#[test]
fn classifies_hosts_urls_and_text() {
    let c = cat();
    let id = |e: Option<&ServiceEntry>| e.map(|e| e.id().to_string());
    assert_eq!(id(c.classify_host("www.mtgox.com")), Some("mtgox".into()));
    assert_eq!(id(c.classify_host("mining.bitcoin.cz")), Some("slush".into()));
    assert_eq!(id(c.classify_host("freebitcoins.appspot.com")), Some("gavin-faucet".into()));
    assert_eq!(id(c.classify_host("free-faucet.example.net")), Some("generic-faucet".into()));
    assert_eq!(id(c.classify_host("hotmail.company.net")), None);
    assert_eq!(id(c.classify_url("https://www.reddit.com/r/Bitcoin/comments/1")), Some("reddit-crypto".into()));
    assert_eq!(id(c.classify_url("https://www.google.com/search?q=mtgox.com")), None);
    assert_eq!(id(c.classify_url("http://forum.bitcoin.org/index.php?topic=1")), Some("bitcointalk".into()));
    assert_eq!(id(c.classify_url("https://money.yandex.ru/x")), Some("yandex-money".into()));
    assert_eq!(id(c.classify_text("C:\\Program Files\\Bitcoin\\bitcoin-qt.exe")), Some("bitcoin-core".into()));
    assert_eq!(id(c.classify_text("Купил через Яндекс.Деньги")), Some("yandex-money".into()));
    assert_eq!(id(c.classify_text("user@bk.ru")), Some("mailru".into()));
    assert_eq!(id(c.classify_text("news/specslujbi_smogut_proslushivat_skype.html")), Some("skype".into()));
}

#[test]
fn lookup_by_name_id_or_host() {
    let c = cat();
    assert_eq!(c.lookup("Mt. Gox").map(|e| e.id()), Some("mtgox"));
    assert_eq!(c.lookup("btce").map(|e| e.id()), Some("btce"));
    assert_eq!(c.lookup("bitcointalk.org").map(|e| e.id()), Some("bitcointalk"));
    assert!(c.lookup("Windows").is_none());
    assert!(c.by_id("mtgox").is_some_and(|e| e.years().is_some_and(|y| y.contains(2012) && y.defunct())));
}

#[test]
fn subjects() {
    let c = cat();
    assert!(c.is_signup_subject("Welcome to Mt. Gox"));
    assert!(c.is_signup_subject("Подтверждение регистрации"));
    assert!(c.is_money_subject("Withdrawal request processed"));
    assert!(!c.is_signup_subject("lunch on friday"));
}

#[test]
fn all_in_text_lists_each_service_once() {
    let mut names: Vec<_> = cat().all_in_text("ran bitcoin-qt then visited mtgox.com and mtgox.com again").iter().map(|e| e.id()).collect();
    names.sort_unstable();
    assert_eq!(names, ["bitcoin-core", "mtgox"]);
}
