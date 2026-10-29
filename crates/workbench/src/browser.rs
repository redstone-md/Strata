//! Workbench use cases for browser history: the lists, the per-profile and per-site
//! overview and cookies by site. Thin over the case; GUI and MCP share them.

use crate::workbench::Workbench;
use strata_case::{BrowserFilter, BrowserOverview, BrowserQuery, BrowserRow, CookieSite};
use strata_kernel::Result;

impl Workbench {
    /// One page of a browser list (history, searches, downloads, logins and forms, cookies).
    pub fn browser_rows(&self, q: &BrowserQuery) -> Result<Vec<BrowserRow>> {
        self.case.browser_rows(q)
    }

    pub fn browser_count(&self, q: &BrowserQuery) -> Result<u64> {
        self.case.browser_count(q)
    }

    /// Browser profiles per disk and the sites visited, crypto-related sites first.
    pub fn browser_overview(&self, f: &BrowserFilter) -> Result<BrowserOverview> {
        self.case.browser_overview(f)
    }

    pub fn browser_cookie_sites(&self, f: &BrowserFilter) -> Result<Vec<CookieSite>> {
        self.case.browser_cookie_sites(f)
    }
}
