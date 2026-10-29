//! Orchestrates identification: header magic + validator, headerless structure inference,
//! text analysis, entropy profile, damage accounting and extension-mismatch detection.

use crate::evidence;
use crate::extension;
use crate::probe::Probe;
use crate::profile::BlockProfile;
use crate::registry::{Registry, TypeId};
use crate::text;
use crate::verdict::{Method, TypeVerdict};
use strata_kernel::{Confidence, Damage, DamageKind};

/// Below this validated fraction a header match is double-checked against structure evidence.
const WEAK_STRUCTURE: f32 = 0.5;

/// Stateless type identifier. Cheap to construct; share freely.
#[derive(Debug, Default, Clone, Copy)]
pub struct Identifier;

impl Identifier {
    pub fn new() -> Self {
        Self
    }

    /// Identify `bytes` (the content of one file, possibly damaged or truncated).
    /// `declared_name` is the name/path the file carried, used for extension-mismatch checks.
    pub fn identify(&self, bytes: &[u8], declared_name: Option<&str>) -> TypeVerdict {
        let profile = BlockProfile::of(bytes);
        let (probe, method) = Self::best_probe(bytes, &profile);
        let spec = probe.id.spec();
        let mut verdict = TypeVerdict {
            file_type: probe.id,
            type_name: spec.name.to_string(),
            category: spec.category,
            confidence: probe.confidence,
            method,
            valid_fraction: probe.structure,
            damage: probe.damage,
            extension_mismatch: None,
            declared_len: probe.declared_len,
            notes: probe.notes,
            inner: probe.inner,
            profile,
        };
        Self::account_zero_blocks(&mut verdict, spec.dense);
        verdict.extension_mismatch = extension::check(declared_name, verdict.file_type, verdict.confidence);
        verdict
    }

    fn best_probe(bytes: &[u8], profile: &BlockProfile) -> (Probe, Method) {
        let header = Registry::header_candidates(bytes)
            .filter_map(|t| t.validate(bytes))
            .max_by(|a, b| a.score().total_cmp(&b.score()));
        let header = match header {
            Some(h) if h.structure >= WEAK_STRUCTURE => return (h, Method::Header),
            other => other,
        };
        let structural = evidence::infer(bytes);
        match (header, structural) {
            (Some(mut h), Some(s)) => {
                if s.score() > h.score() && !h.id.spec().same_family(s.id) {
                    return (s, Method::Structure);
                }
                if h.inner.is_empty() {
                    h.inner = s.inner;
                }
                (h, Method::Header)
            }
            (Some(h), None) => (h, Method::Header),
            (None, Some(s)) => (s, Method::Structure),
            (None, None) => match text::validate(bytes) {
                Some(t) => (t, Method::Text),
                None => Self::by_entropy(profile),
            },
        }
    }

    fn by_entropy(profile: &BlockProfile) -> (Probe, Method) {
        let content = profile.blocks.saturating_sub(profile.zero + profile.fill);
        let random = profile.random_share_of_content();
        if content > 0 && random >= 0.9 {
            let c = if content >= 4 { 0.6 } else { 0.5 };
            let mut p = Probe::new(TypeId::EncryptedOrRandom, Confidence::new(c)).with_structure(random);
            p.note("no recognisable header or structure; content is uniformly high-entropy (encrypted volume, wiped area or headerless compressed data)");
            return (p, Method::Entropy);
        }
        (Self::unknown(profile), Method::None)
    }

    fn unknown(profile: &BlockProfile) -> Probe {
        let mut p = Probe::new(TypeId::Unknown, Confidence::NONE).with_structure(0.0);
        if profile.blocks > 0 && profile.zero == profile.blocks {
            p.note("all zero bytes");
        }
        p
    }

    /// Zero-filled 4 KiB blocks are what our sources return for unreadable sectors. In dense
    /// formats they are damage; elsewhere they may be sparse content and are only noted.
    fn account_zero_blocks(v: &mut TypeVerdict, dense: bool) {
        let zero = v.profile.zero_fraction();
        if v.profile.zero == 0 || v.profile.zero == v.profile.blocks {
            return;
        }
        if dense {
            for r in &v.profile.zero_ranges {
                v.damage.push(Damage::new(
                    DamageKind::Unreadable,
                    Some(*r),
                    "zero-filled block(s): likely unreadable sector or overwritten area",
                ));
            }
            v.valid_fraction = v.valid_fraction.min(v.profile.intact_fraction());
        } else {
            v.notes.push(format!(
                "{} of {} 4 KiB blocks are zero-filled (sparse content or unreadable sectors)",
                v.profile.zero, v.profile.blocks
            ));
            v.valid_fraction = v.valid_fraction.min(1.0 - zero / 2.0);
        }
    }
}
