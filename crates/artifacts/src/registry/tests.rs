use super::hive::{REG_DWORD, REG_EXPAND_SZ, REG_SZ};
use super::hive_testutil::{DEFAULT_TIME, HiveBuilder, sz};
use super::*;
use crate::results::IdentityKind;
use crate::text::rot13;

const UA: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist";
const EXPLORER: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer";
/// 2012-01-31 19:57:06 UTC.
const FT2: u64 = 129_725_134_260_000_000;

fn xp_ua(count: u32, ft: u64) -> Vec<u8> {
    let mut d = vec![0u8; 16];
    d[4..8].copy_from_slice(&(count + 5).to_le_bytes());
    d[8..16].copy_from_slice(&ft.to_le_bytes());
    d
}

fn win7_ua(count: u32, ft: u64) -> Vec<u8> {
    let mut d = vec![0u8; 72];
    d[4..8].copy_from_slice(&count.to_le_bytes());
    d[60..68].copy_from_slice(&ft.to_le_bytes());
    d
}

fn mru_ex(order: &[u32]) -> Vec<u8> {
    order.iter().chain([&u32::MAX]).flat_map(|i| i.to_le_bytes()).collect()
}

fn ntuser() -> Vec<u8> {
    let mut b = HiveBuilder::new();
    b.key("Control Panel").key("Environment");
    let xp = format!("{UA}\\{{75048700-EF1F-11D0-9888-006097DEACF9}}\\Count");
    b.value(&xp, &rot13("UEME_RUNPATH:C:\\Program Files\\Bitcoin\\bitcoin.exe"), 3, &xp_ua(4, DEFAULT_TIME));
    b.value(&xp, &rot13("UEME_CTLSESSION"), 3, &[0; 8]);
    let w7 = format!("{UA}\\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\\Count");
    b.value(&w7, &rot13("{6D809377-6AF0-444B-8957-A3773F02200E}\\Electrum\\electrum.exe"), 3, &win7_ua(2, FT2));
    let rd = format!("{EXPLORER}\\RecentDocs");
    b.value(&rd, "0", 3, &sz("old.txt"));
    b.value(&rd, "1", 3, &sz("wallet.dat"));
    b.value(&rd, "MRUListEx", 3, &mru_ex(&[1, 0]));
    b.key_time(&rd, FT2);
    let run = format!("{EXPLORER}\\RunMRU");
    b.value(&run, "a", REG_SZ, &sz("cmd\\1"));
    b.value(&run, "b", REG_SZ, &sz("regedit\\1"));
    b.value(&run, "MRUList", REG_SZ, &sz("ba"));
    b.value("Software\\Microsoft\\Internet Explorer\\TypedURLs", "url1", REG_SZ, &sz("http://mtgox.com/"));
    b.value("Software\\Microsoft\\Internet Explorer\\TypedURLs", "url2", REG_SZ, &sz("http://ya.ru/"));
    b.value("Software\\Microsoft\\Internet Explorer\\TypedURLsTime", "url2", 3, &FT2.to_le_bytes());
    let osp = format!("{EXPLORER}\\ComDlg32\\OpenSavePidlMRU\\dat");
    let mut pidl = vec![0x19, 0, 0x2F];
    pidl.extend_from_slice(b"D:\\");
    pidl.resize(0x19, 0);
    pidl.extend(crate::pidl::file_item("WALLET~1.DAT", "wallet.dat"));
    pidl.extend_from_slice(&[0, 0]);
    b.value(&osp, "0", 3, &pidl);
    b.value(&osp, "MRUListEx", 3, &mru_ex(&[0]));
    b.value(&format!("{EXPLORER}\\WordWheelQuery"), "0", 3, &sz("биткоин"));
    b.value("Software\\Microsoft\\Internet Explorer\\Main", "Start Page", REG_SZ, &sz("http://www.yandex.ru/"));
    b.value("Software\\Bitcoin\\Bitcoin-Qt", "strDataDir", REG_SZ, &sz("D:\\BitcoinData"));
    let acct = "Software\\Microsoft\\Internet Account Manager\\Accounts\\00000001";
    b.value(acct, "SMTP Email Address", REG_SZ, &sz("anna.test3@mail.ru"));
    b.value(acct, "POP3 Server", REG_SZ, &sz("pop.mail.ru"));
    b.build()
}

#[test]
fn ntuser_artifacts() {
    let out = parse_hive(&ntuser());
    assert!(out.damage.is_empty(), "{:?}", out.damage);
    let find = |k: EventKind, t: &str| out.events.iter().find(|e| e.kind() == k && e.title().contains(t));
    let xp = find(EventKind::ProgramRun, "bitcoin.exe").expect("xp userassist");
    assert_eq!(xp.title(), "C:\\Program Files\\Bitcoin\\bitcoin.exe");
    assert!(xp.detail().contains("run count 4"));
    assert_eq!(xp.at().to_string(), "2011-05-14 17:36:09");
    let w7 = find(EventKind::ProgramRun, "electrum.exe").expect("win7 userassist");
    assert_eq!(w7.title(), "%ProgramFiles%\\Electrum\\electrum.exe");
    assert_eq!(w7.at().to_string(), "2012-01-31 19:57:06");
    assert!(!out.events.iter().any(|e| e.title().contains("UEME_CTL")));
    let doc = find(EventKind::DocumentOpened, "wallet.dat").expect("recent docs");
    assert_eq!(doc.at().to_string(), "2012-01-31 19:57:06");
    assert!(out.facts.iter().any(|f| f.key == "recent_doc" && f.value == "old.txt"));
    assert!(find(EventKind::ProgramRun, "regedit").is_some());
    assert!(out.facts.iter().any(|f| f.key == "run_mru" && f.value == "cmd"));
    assert!(find(EventKind::UrlVisited, "mtgox").is_some());
    assert_eq!(find(EventKind::UrlVisited, "ya.ru").unwrap().at().to_string(), "2012-01-31 19:57:06");
    assert!(find(EventKind::DocumentOpened, "D:\\wallet.dat").is_some());
    assert!(find(EventKind::Search, "биткоин").is_some());
    assert!(out.facts.iter().any(|f| f.key == "ie_start_page"));
    let wallet = find(EventKind::WalletActivity, "Bitcoin-Qt").expect("wallet key");
    assert!(wallet.is_crypto() && wallet.detail().contains("D:\\BitcoinData"));
    assert!(out.facts.iter().any(|f| f.key == "wallet_data_dir" && f.value == "D:\\BitcoinData"));
    assert!(out.identities.iter().any(|i| i.value == "anna.test3@mail.ru" && i.kind == IdentityKind::Email));
}

#[test]
fn system_software_sam() {
    let mut b = HiveBuilder::new();
    b.value("Select", "Current", REG_DWORD, &1u32.to_le_bytes());
    b.value("ControlSet001\\Control\\ComputerName\\ComputerName", "ComputerName", REG_SZ, &sz("ADMIN-PC"));
    b.value("ControlSet001\\Control\\TimeZoneInformation", "StandardName", REG_SZ, &sz("Russian Standard Time"));
    b.value("ControlSet001\\Control\\Windows", "ShutdownTime", 3, &FT2.to_le_bytes());
    let usb = "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00\\5B8A1C2D&0";
    b.value(usb, "FriendlyName", REG_SZ, &sz("Kingston DataTraveler USB Device"));
    let mut mounted = sz("\\??\\STORAGE#RemovableMedia#7&1a2b&0&RM#{53f5630d}");
    mounted.truncate(mounted.len() - 2);
    b.value("MountedDevices", "\\DosDevices\\F:", 3, &mounted);
    let out = parse_hive(&b.build());
    assert!(out.facts.iter().any(|f| f.key == "computer_name" && f.value == "ADMIN-PC"));
    assert!(out.facts.iter().any(|f| f.key == "timezone" && f.value.contains("Russian")));
    assert!(out.facts.iter().any(|f| f.key == "mounted_device" && f.value.starts_with("F:")));
    let usb = out.events.iter().find(|e| e.kind() == EventKind::UsbDevice).unwrap();
    assert!(usb.detail().contains("serial 5B8A1C2D"));
    assert!(out.events.iter().any(|e| e.title() == "System shutdown"));

    let mut b = HiveBuilder::new();
    b.key("Classes").key("Policies");
    let nt = "Microsoft\\Windows NT\\CurrentVersion";
    b.value(nt, "ProductName", REG_SZ, &sz("Microsoft Windows XP"));
    b.value(nt, "RegisteredOwner", REG_SZ, &sz("Admin"));
    b.value(nt, "InstallDate", REG_DWORD, &1_200_000_000u32.to_le_bytes());
    b.value(&format!("{nt}\\ProfileList\\S-1-5-21-1-2-3-1003"), "ProfileImagePath", REG_EXPAND_SZ, &sz("%SystemDrive%\\Documents and Settings\\Admin"));
    let un = "Microsoft\\Windows\\CurrentVersion\\Uninstall\\Electrum";
    b.value(un, "DisplayName", REG_SZ, &sz("Electrum"));
    b.value(un, "InstallDate", REG_SZ, &sz("20120131"));
    b.value("Classes\\bitcoin", "URL Protocol", REG_SZ, &sz(""));
    let out = parse_hive(&b.build());
    assert!(out.facts.iter().any(|f| f.key == "registered_owner" && f.value == "Admin"));
    assert!(out.identities.iter().any(|i| i.value == "Admin" && i.service.as_deref() == Some("Windows")));
    let inst = out.events.iter().find(|e| e.title() == "Electrum").unwrap();
    assert_eq!(inst.at().to_string(), "2012-01-31 00:00:00");
    assert!(out.events.iter().any(|e| e.title().contains("Windows XP installed")));
    assert!(out.events.iter().any(|e| e.kind() == EventKind::WalletActivity && e.title().contains("bitcoin")));

    let mut b = HiveBuilder::new();
    let names = "SAM\\Domains\\Account\\Users\\Names\\Admin";
    b.value(names, "", 0x3EB, &[]);
    let mut f = vec![0u8; 80];
    f[8..16].copy_from_slice(&FT2.to_le_bytes());
    f[48..52].copy_from_slice(&0x3EBu32.to_le_bytes());
    f[66..68].copy_from_slice(&42u16.to_le_bytes());
    b.value("SAM\\Domains\\Account\\Users\\000003EB", "F", 3, &f);
    let out = parse_hive(&b.build());
    let login = out.events.iter().find(|e| e.kind() == EventKind::Login).unwrap();
    assert!(login.detail().contains("logon count 42"));
    assert_eq!(login.at().to_string(), "2012-01-31 19:57:06");
}

#[test]
fn garbage_hives_never_panic() {
    let bytes = ntuser();
    for cut in (0..bytes.len()).step_by(97) {
        let _ = parse_hive(&bytes[..cut]);
    }
    let mut junk = bytes.clone();
    for (i, b) in junk.iter_mut().enumerate().skip(0x1100).step_by(3) {
        *b = (i * 31 % 256) as u8;
    }
    let _ = parse_hive(&junk);
    assert!(!parse_hive(b"not a hive").damage.is_empty());
}
