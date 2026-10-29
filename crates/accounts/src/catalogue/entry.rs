use super::ServiceKind;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Approximate years a service was active (`"2010-2014"`, `"2013-"`, `"2011"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Years {
    from: u16,
    /// `None`: still running, or the end is unknown.
    to: Option<u16>,
}

impl Years {
    pub fn new(from: u16, to: Option<u16>) -> Option<Self> {
        (to.is_none_or(|t| t >= from) && from >= 1800).then_some(Self { from, to })
    }

    pub fn from(self) -> u16 {
        self.from
    }

    pub fn to(self) -> Option<u16> {
        self.to
    }

    /// The service existed in `year` (open-ended ranges contain every later year).
    pub fn contains(self, year: i64) -> bool {
        year >= i64::from(self.from) && self.to.is_none_or(|t| year <= i64::from(t))
    }

    /// The service is known to have closed.
    pub fn defunct(self) -> bool {
        self.to.is_some()
    }
}

impl TryFrom<String> for Years {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        let bad = || format!("years must look like 2010-2014, 2013- or 2011, got {s:?}");
        let year = |t: &str| t.trim().parse::<u16>().map_err(|_| bad());
        let years = match s.split_once('-') {
            Some((a, "")) => Self::new(year(a)?, None),
            Some((a, b)) => Self::new(year(a)?, Some(year(b)?)),
            None => {
                let y = year(&s)?;
                Self::new(y, Some(y))
            }
        };
        years.ok_or_else(bad)
    }
}

impl From<Years> for String {
    fn from(y: Years) -> String {
        match y.to {
            Some(t) if t == y.from => y.from.to_string(),
            Some(t) => format!("{}-{t}", y.from),
            None => format!("{}-", y.from),
        }
    }
}

impl fmt::Display for Years {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to {
            Some(t) if t == self.from => write!(f, "{t}"),
            Some(t) => write!(f, "{}–{t}", self.from),
            None => write!(f, "since {}", self.from),
        }
    }
}

/// One catalogued service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEntry {
    id: String,
    name: String,
    kind: ServiceKind,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    host_keywords: bool,
    #[serde(default)]
    years: Option<Years>,
    #[serde(default)]
    notes: String,
}

impl ServiceEntry {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> ServiceKind {
        self.kind
    }

    /// Host names and `host/path` prefixes, current and historical.
    pub fn domains(&self) -> &[String] {
        &self.domains
    }

    pub fn keywords(&self) -> &[String] {
        &self.keywords
    }

    /// Keywords may classify a bare host too (generic faucet words).
    pub fn host_keywords(&self) -> bool {
        self.host_keywords
    }

    pub fn years(&self) -> Option<Years> {
        self.years
    }

    /// Free-text remarks; anything uncertain is flagged here.
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// The service existed in `year`; `true` when the catalogue does not know its years.
    pub fn active_in(&self, year: i64) -> bool {
        self.years.is_none_or(|y| y.contains(year))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn years_parse_and_show() {
        let y = Years::try_from("2010-2014".to_string()).unwrap();
        assert!(y.contains(2012) && !y.contains(2015) && y.defunct());
        assert_eq!(y.to_string(), "2010–2014");
        let open = Years::try_from("2013-".to_string()).unwrap();
        assert!(open.contains(2030) && !open.defunct());
        assert_eq!(open.to_string(), "since 2013");
        assert_eq!(Years::try_from("2011".to_string()).unwrap().to_string(), "2011");
        assert!(Years::try_from("2014-2010".to_string()).is_err());
        assert!(Years::try_from("soon".to_string()).is_err());
        assert_eq!(String::from(open), "2013-");
    }
}
