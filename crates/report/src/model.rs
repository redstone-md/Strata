use serde::Serialize;
use strata_case::{Case, CorrelationService, FileComplement, HitQuery, SharedFinding, StoredHit};
use strata_chain::AddressBalance;
use strata_kernel::Result;
use strata_kernel::scan::HitCategory;

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceSummary {
    pub id: String,
    pub label: String,
    pub location: String,
    pub bytes: u64,
    pub volumes: Vec<String>,
    pub scanned_fraction: f64,
    pub scan_completed: bool,
    pub findings: Vec<(HitCategory, u64)>,
}

/// Everything a report shows, gathered once from the case.
#[derive(Debug, Clone, Serialize)]
pub struct CaseReport {
    pub case_name: String,
    pub generated_at: i64,
    pub evidence: Vec<EvidenceSummary>,
    pub wallet_findings: Vec<StoredHit>,
    pub identity_findings: Vec<StoredHit>,
    pub balances: Vec<AddressBalance>,
    pub shared: Vec<SharedFinding>,
    pub complements: Vec<FileComplement>,
}

impl CaseReport {
    pub const WALLET_CATEGORIES: [HitCategory; 5] =
        [HitCategory::PrivateKey, HitCategory::ExtendedKey, HitCategory::Mnemonic, HitCategory::Wallet, HitCategory::Address];

    pub fn gather(case: &Case, min_confidence: f32) -> Result<Self> {
        let mut evidence = Vec::new();
        for e in case.evidence()? {
            let scan = case.scan_state(e.id)?;
            evidence.push(EvidenceSummary {
                id: e.id.to_string(),
                label: e.info.label.clone(),
                location: e.info.location.clone(),
                bytes: e.info.len,
                volumes: e.volumes.iter().map(|v| format!("{:?} {:?} @{:#x} {} B", v.fs, v.origin, v.range.start(), v.range.len())).collect(),
                scanned_fraction: scan.map_or(0.0, |(mark, total, _)| if total == 0 { 0.0 } else { mark as f64 / total as f64 }),
                scan_completed: scan.is_some_and(|s| s.2),
                findings: case.hit_counts(Some(e.id))?,
            });
        }
        let query = |cats: &[HitCategory]| HitQuery { categories: cats.to_vec(), min_confidence, limit: 20_000, group_by_value: true, ..Default::default() };
        let correlation = CorrelationService::new(case);
        Ok(Self {
            case_name: case.name(),
            generated_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64),
            evidence,
            wallet_findings: case.hits(&query(&Self::WALLET_CATEGORIES))?,
            identity_findings: case.hits(&query(&[HitCategory::Identity, HitCategory::Url]))?,
            balances: case.balances()?,
            shared: correlation.shared_findings(&[
                HitCategory::PrivateKey,
                HitCategory::ExtendedKey,
                HitCategory::Mnemonic,
                HitCategory::Address,
                HitCategory::Identity,
                HitCategory::Url,
            ])?,
            complements: correlation.file_complements()?,
        })
    }

    pub fn used_balances(&self) -> impl Iterator<Item = &AddressBalance> {
        self.balances.iter().filter(|b| b.ever_used())
    }
}
