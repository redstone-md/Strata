use super::*;
use strata_mail::Message;

fn message(id: &str, subject: &str, body: &str) -> Message {
    let raw = format!(
        "Message-ID: <{id}>\r\nDate: Sat, 14 May 2011 17:36:09 +0000\r\nFrom: Anna <anna@example.com>\r\nTo: ivan@example.com\r\n\
         Cc: olga@example.ru\r\nSubject: {subject}\r\n\r\n{body}"
    );
    Message::parse(raw.as_bytes()).unwrap()
}

fn at(state: MessageState, path: Option<&str>, offset: u64) -> MessageLocation {
    let container = if path.is_some() { Container::Mbox } else { Container::Carved };
    MessageLocation { state, container, volume: path.map(|_| 0), file_idx: path.map(|_| 3), path: path.map(str::to_string), offset, len: 100 }
}

fn found(location: MessageLocation, message: Message) -> FoundMessage {
    FoundMessage { location, folder: "Inbox".into(), message }
}

#[test]
fn stores_queries_and_merges_copies() {
    let dir = tempfile::tempdir().unwrap();
    let case = Case::open(&dir.path().join("c.strata")).unwrap();
    let image = dir.path().join("disk.img");
    std::fs::write(&image, vec![0u8; 4096]).unwrap();
    let e = case.add_evidence(&image.display().to_string()).unwrap().id;
    let first = case
        .write(|w| {
            w.messages(
                e,
                &[
                    found(at(MessageState::Carved, None, 0x1000), message("a@example.com", "wallet backup", "the seed is in the drawer")),
                    found(at(MessageState::Live, Some("Mail/Inbox"), 0), message("b@example.com", "lunch", "noon?")),
                ],
            )
        })
        .unwrap();
    assert_eq!(first, StoredBatch { added: 2, merged: 0 });
    // The live copy of the carved message takes over its row; the carved one becomes a place.
    let second = case
        .write(|w| {
            w.messages(
                e,
                &[
                    found(at(MessageState::Live, Some("Mail/Inbox"), 500), message("a@example.com", "wallet backup", "the seed is in the drawer")),
                    found(at(MessageState::Carved, None, 0x1000), message("a@example.com", "wallet backup", "cut")),
                    found(at(MessageState::Carved, None, 0x9000), message("b@example.com", "lunch", "noon?")),
                ],
            )
        })
        .unwrap();
    assert_eq!(second, StoredBatch { added: 0, merged: 2 }, "the same place twice is not a copy");

    let all = case.messages(&MessageQuery::default()).unwrap();
    assert_eq!(all.len(), 2);
    let wallet = all.iter().find(|m| m.subject == "wallet backup").unwrap();
    assert_eq!((wallet.location.state, wallet.location.offset, wallet.copies), (MessageState::Live, 500, 1));
    assert_eq!(wallet.from, "Anna <anna@example.com>");
    assert_eq!(wallet.to, "ivan@example.com, olga@example.ru");
    let full = case.message(wallet.id).unwrap().unwrap();
    assert_eq!(full.message.body, "the seed is in the drawer");
    assert_eq!(full.places, vec![at(MessageState::Carved, None, 0x1000)]);
    assert_eq!(full.places[0].describe(), "free space 0x1000");

    let q = |text: Option<&str>, address: Option<&str>| MessageQuery { text: text.map(Into::into), address: address.map(Into::into), ..Default::default() };
    assert_eq!(case.message_count(&q(Some("drawer"), None)).unwrap(), 1);
    assert_eq!(case.message_count(&q(Some("100%"), None)).unwrap(), 0);
    assert_eq!(case.message_count(&q(None, Some("OLGA@example.ru"))).unwrap(), 2);
    assert_eq!(case.message_count(&q(None, Some("nobody@example.com"))).unwrap(), 0);
    let carved = MessageQuery { state: Some(MessageState::Carved), ..Default::default() };
    assert_eq!(case.message_count(&carved).unwrap(), 0);
    let paged = MessageQuery { limit: 1, offset: 1, ..Default::default() };
    assert_eq!(case.messages(&paged).unwrap().len(), 1);
    assert!(case.message(999).unwrap().is_none());

    case.write(|w| w.clear_messages(e)).unwrap();
    assert_eq!(case.message_count(&MessageQuery::default()).unwrap(), 0);
    assert_eq!(case.message_count(&q(None, Some("olga@example.ru"))).unwrap(), 0);
}
