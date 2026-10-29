//! Mail tools against a synthetic case holding one live and one carved message.

mod support;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::Value;
use strata_case::{FoundMessage, MessageLocation, MessageState};
use strata_mail::{Container, Message};
use strata_mcp::StrataServer;
use strata_mcp::tools::mail::{GetMailParams, ListMailParams};
use strata_workbench::Workbench;
use support::{dump, synthetic_case};

const LIVE: &[u8] = b"Message-ID: <a1@example.com>\r\nDate: Tue, 14 Jun 2011 12:00:00 +0000\r\nFrom: Shop <noreply@shop.example.com>\r\n\
To: olga.test1@example.ru\r\nSubject: Your wallet backup\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nKeep the file wallet.dat safe.\r\n";
const CARVED: &[u8] = b"Message-ID: <b2@example.com>\r\nDate: Wed, 01 Feb 2012 08:30:00 +0000\r\nFrom: ivan.test2@example.ru\r\n\
To: olga.test1@example.ru\r\nSubject: =?utf-8?B?0L/RgNC40LLQtdGC?=\r\n\r\nseed words are in the notebook\r\n";

fn found(raw: &[u8], state: MessageState, path: Option<&str>, offset: u64) -> FoundMessage {
    let container = if path.is_some() { Container::Eml } else { Container::Carved };
    let location = MessageLocation { state, container, volume: Some(0), file_idx: None, path: path.map(str::to_string), offset, len: raw.len() as u64 };
    FoundMessage { location, folder: String::new(), message: Message::parse(raw).unwrap() }
}

fn json(reply: Result<String, String>) -> Value {
    serde_json::from_str(&reply.expect("tool succeeds")).expect("tool returns JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_and_reads_mail() {
    let dir = tempfile::tempdir().unwrap();
    let root = synthetic_case(dir.path());
    {
        let wb = Workbench::open_idle(&root).unwrap();
        let disk = wb.evidence().unwrap()[0].id;
        let mail = [found(LIVE, MessageState::Live, Some("Mail/inbox.eml"), 0), found(CARVED, MessageState::Carved, None, 0x40000)];
        wb.case().write(|w| w.messages(disk, &mail)).unwrap();
    }
    let before = dump(&root);
    let s = StrataServer::open(&root).unwrap();

    let all = json(s.list_mail(Parameters(ListMailParams::default())).await);
    let rows = all["items"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!((rows[0]["subject"].as_str(), rows[0]["state"].as_str()), (Some("Your wallet backup"), Some("live")));
    assert_eq!(rows[1]["subject"], "привет");

    let carved = json(s.list_mail(Parameters(ListMailParams { state: Some("carved".into()), ..Default::default() })).await);
    assert_eq!(carved["items"].as_array().unwrap().len(), 1);
    let to_olga = json(s.list_mail(Parameters(ListMailParams { address: Some("Olga.Test1@example.ru".into()), ..Default::default() })).await);
    assert_eq!(to_olga["items"].as_array().unwrap().len(), 2);
    let in_2012 = json(s.list_mail(Parameters(ListMailParams { from: Some("2012".into()), ..Default::default() })).await);
    assert_eq!(in_2012["items"].as_array().unwrap().len(), 1);
    assert!(s.list_mail(Parameters(ListMailParams { state: Some("lost".into()), ..Default::default() })).await.is_err());

    let id = rows[0]["id"].as_i64().unwrap();
    let one = json(s.get_mail(Parameters(GetMailParams { id, all_headers: true, body_chars: Some(8) })).await);
    assert_eq!((one["body"].as_str(), one["body_truncated"].as_bool()), (Some("Keep the"), Some(true)));
    assert!(one["headers"].as_array().unwrap().iter().any(|h| h[0] == "Message-ID"));
    assert!(s.get_mail(Parameters(GetMailParams { id: 999_999, ..Default::default() })).await.unwrap_err().contains("no message"));

    drop(s);
    assert_eq!(dump(&root), before, "reading mail leaves the case unchanged");
}
