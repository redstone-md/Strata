//! SAM hive: local user accounts with last logon, logon count and password change.

use super::hive::Hive;
use crate::host::{UserRecord, keys};
use crate::results::{IdentityKind, Recorder};
use crate::text::filetime_at;
use strata_kernel::bytes::{u16_le, u32_le};
use strata_timeline::EventKind;

/// `V` value: offset table entries are relative to the end of the 0xCC-byte header.
const V_DATA: usize = 0xCC;
/// Full name entry (offset, length) in the `V` header.
const V_FULL_NAME: usize = 0x18;

pub(crate) struct SamHive<'h, 'a> {
    hive: &'h Hive<'a>,
}

impl<'h, 'a> SamHive<'h, 'a> {
    pub fn new(hive: &'h Hive<'a>) -> Self {
        Self { hive }
    }

    /// User names (`Names\<name>`, RID in the default value's type) and the `F` value of
    /// `Users\<RID>`: last logon @8, password set @24, last failed @40, logon count @66.
    pub fn parse(&self, rec: &mut Recorder) {
        let h = self.hive;
        let Some(names) = h.open("SAM\\Domains\\Account\\Users\\Names") else { return };
        let users = h.open("SAM\\Domains\\Account\\Users");
        for n in h.subkeys(&names) {
            let rid = h.values(&n).into_iter().find(|v| v.name.is_empty()).map(|v| v.kind);
            rec.identity(IdentityKind::Login, &n.name, Some("Windows"), n.last_write);
            let account = rid.and_then(|rid| users.as_ref().and_then(|u| h.subkey(u, &format!("{rid:08X}"))));
            let mut user = UserRecord { name: n.name.clone(), id: rid.map(|r| format!("RID {r}")), ..Default::default() };
            user.full_name = account.as_ref().and_then(|k| h.value(k, "V")).and_then(|v| full_name(&v.data));
            if let Some(f) = account.as_ref().and_then(|k| h.value(k, "F")) {
                let count = u16_le(&f.data, 66).unwrap_or(0);
                let rid = u32_le(&f.data, 48).unwrap_or(0);
                user.last_logon = filetime_at(&f.data, 8);
                user.password_set = filetime_at(&f.data, 24);
                user.logon_count = Some(u32::from(count));
                rec.dated(user.last_logon, EventKind::Login, format!("Windows logon: {}", n.name), format!("RID {rid}; logon count {count}"));
                rec.dated(user.password_set, EventKind::Other, format!("Password set: {}", n.name), "SAM F value");
                rec.dated(filetime_at(&f.data, 40), EventKind::Other, format!("Failed logon: {}", n.name), "SAM F value");
            }
            rec.record(keys::USER, &user);
        }
    }
}

/// Full name from the `V` value (UTF-16 at the offset its header names).
fn full_name(v: &[u8]) -> Option<String> {
    let off = V_DATA.checked_add(u32_le(v, V_FULL_NAME)? as usize)?;
    let len = u32_le(v, V_FULL_NAME + 4)? as usize;
    let raw = v.get(off..off.checked_add(len)?)?;
    let name = strata_kernel::bytes::utf16le(raw).trim().to_string();
    (!name.is_empty()).then_some(name)
}
