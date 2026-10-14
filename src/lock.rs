//! S3 Object Lock: per-version retention (GOVERNANCE / COMPLIANCE) and legal holds.
//!
//! The lock state of a version is kept in its stored headers, under the same names S3 uses
//! for them on GET/HEAD responses, so reads replay it without any special handling. Changes
//! and deletions are checked on the writer thread, atomically with the change itself.

use crate::error::{S3Error, S3Result, err};
use crate::util::{iso8601, parse_iso8601};
use crate::xml::{self, Xml};
use hyper::StatusCode;

pub const MODE: &str = "x-amz-object-lock-mode";
pub const UNTIL: &str = "x-amz-object-lock-retain-until-date";
pub const HOLD: &str = "x-amz-object-lock-legal-hold";
pub const BYPASS: &str = "x-amz-bypass-governance-retention";

const SECS_PER_DAY: u64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Users with the bypass permission may shorten or remove the retention, or delete.
    Governance,
    /// Nobody can shorten the retention or delete the version before it expires.
    Compliance,
}

impl Mode {
    pub fn parse(s: &str) -> S3Result<Self> {
        match s.trim() {
            "GOVERNANCE" => Ok(Mode::Governance),
            "COMPLIANCE" => Ok(Mode::Compliance),
            _ => Err(err::InvalidArgument().with_message("Unknown wormMode directive.")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Governance => "GOVERNANCE",
            Mode::Compliance => "COMPLIANCE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    pub mode: Mode,
    /// Unix seconds.
    pub until: u64,
}

/// Lock state of one object version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct State {
    pub retention: Option<Retention>,
    /// `Some(true)` = ON, `Some(false)` = explicitly OFF, `None` = never set.
    pub legal_hold: Option<bool>,
}

fn get<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

impl State {
    pub fn of(headers: &[(String, String)]) -> State {
        let retention = match (get(headers, MODE), get(headers, UNTIL)) {
            (Some(m), Some(u)) => Mode::parse(m).ok().zip(parse_iso8601(u)).map(|(mode, until)| Retention { mode, until }),
            _ => None,
        };
        let legal_hold = get(headers, HOLD).map(|v| v == "ON");
        State { retention, legal_hold }
    }

    /// Replace the lock headers in `headers` with this state.
    pub fn store(&self, headers: &mut Vec<(String, String)>) {
        headers.retain(|(k, _)| !is_lock_header(k));
        if let Some(r) = self.retention {
            headers.push((MODE.into(), r.mode.as_str().into()));
            headers.push((UNTIL.into(), iso8601(r.until * 1000)));
        }
        if let Some(on) = self.legal_hold {
            headers.push((HOLD.into(), if on { "ON" } else { "OFF" }.into()));
        }
    }

    /// Retention that is still in force at `now` (unix seconds).
    pub fn active(&self, now: u64) -> Option<Retention> {
        self.retention.filter(|r| r.until > now)
    }

    /// May this version be permanently deleted (or its data otherwise discarded)?
    pub fn check_delete(&self, now: u64, bypass: bool) -> S3Result<()> {
        if self.legal_hold == Some(true) {
            return Err(protected());
        }
        match self.active(now) {
            Some(Retention { mode: Mode::Compliance, .. }) => Err(protected()),
            Some(Retention { mode: Mode::Governance, .. }) if !bypass => Err(protected()),
            _ => Ok(()),
        }
    }

    /// May the retention be replaced by `new` (`None` removes it)?
    pub fn check_retention_change(&self, new: Option<Retention>, now: u64, bypass: bool) -> S3Result<()> {
        let Some(old) = self.active(now) else { return Ok(()) };
        // Extending (same mode, later or equal date) is always allowed, as is GOVERNANCE -> COMPLIANCE.
        let extends = new.is_some_and(|n| {
            n.until >= old.until && (n.mode == old.mode || (old.mode == Mode::Governance && n.mode == Mode::Compliance))
        });
        if extends {
            return Ok(());
        }
        match old.mode {
            Mode::Compliance => Err(protected()),
            Mode::Governance if !bypass => Err(protected()),
            Mode::Governance => Ok(()),
        }
    }
}

pub fn is_lock_header(name: &str) -> bool {
    matches!(name, MODE | UNTIL | HOLD)
}

fn protected() -> S3Error {
    err::AccessDenied().with_message("Access Denied because object protected by object lock.")
}

pub fn missing_config() -> S3Error {
    err::InvalidRequest().with_message("Bucket is missing Object Lock Configuration")
}

/// Parse an explicit retention (mode + date) given as text, checking it lies in the future.
pub fn parse_retention(mode: &str, until: &str, now: u64) -> S3Result<Retention> {
    let mode = Mode::parse(mode)?;
    let until = parse_iso8601(until.trim())
        .ok_or_else(|| err::InvalidArgument().with_message("The retain until date must be a valid ISO 8601 date"))?;
    if until <= now {
        return Err(err::InvalidArgument().with_message("The retain until date must be in the future!"));
    }
    Ok(Retention { mode, until })
}

pub fn parse_legal_hold(s: &str) -> S3Result<bool> {
    match s.trim() {
        "ON" => Ok(true),
        "OFF" => Ok(false),
        _ => Err(err::InvalidArgument().with_message("Legal Hold must be either of 'ON' or 'OFF'")),
    }
}

/// Default retention period, in the unit it was configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Period {
    Days(u64),
    Years(u64),
}

impl Period {
    pub fn secs(self) -> u64 {
        match self {
            Period::Days(d) => d * SECS_PER_DAY,
            Period::Years(y) => y * 365 * SECS_PER_DAY,
        }
    }
}

/// A bucket's Object Lock configuration (its presence means Object Lock is enabled).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BucketLock {
    /// Default retention for new versions.
    pub default: Option<(Mode, Period)>,
}

impl BucketLock {
    pub fn parse_xml(doc: &xml::Node) -> S3Result<BucketLock> {
        if doc.name != "ObjectLockConfiguration" {
            return Err(err::MalformedXML());
        }
        if doc.child_text("ObjectLockEnabled").map(str::trim) != Some("Enabled") {
            return Err(err::MalformedXML().with_message("ObjectLockEnabled must be Enabled"));
        }
        let Some(rule) = doc.child("Rule") else { return Ok(BucketLock::default()) };
        let dr = rule.child("DefaultRetention").ok_or_else(err::MalformedXML)?;
        let mode = Mode::parse(dr.child_text("Mode").ok_or_else(err::MalformedXML)?)?;
        let num = |n: &str| -> S3Result<Option<u64>> {
            match dr.child_text(n) {
                None => Ok(None),
                Some(v) => match v.trim().parse::<u64>() {
                    Ok(x) if x > 0 && x <= 36_500 => Ok(Some(x)),
                    _ => Err(err::InvalidArgument().with_message("Default retention period must be a positive integer value")),
                },
            }
        };
        let period = match (num("Days")?, num("Years")?) {
            (Some(d), None) => Period::Days(d),
            (None, Some(y)) if y <= 100 => Period::Years(y),
            _ => return Err(err::MalformedXML().with_message("Default retention needs exactly one of Days or Years")),
        };
        Ok(BucketLock { default: Some((mode, period)) })
    }

    /// Stored (and returned) form of the configuration.
    pub fn to_xml(self) -> String {
        let mut x = Xml::new("ObjectLockConfiguration");
        x.elem("ObjectLockEnabled", "Enabled");
        if let Some((mode, period)) = self.default {
            x.open("Rule").open("DefaultRetention").elem("Mode", mode.as_str());
            match period {
                Period::Days(d) => x.elem("Days", d.to_string()),
                Period::Years(y) => x.elem("Years", y.to_string()),
            };
            x.close("DefaultRetention").close("Rule");
        }
        x.finish("ObjectLockConfiguration")
    }

    /// Parse a stored configuration document.
    pub fn from_stored(v: &[u8]) -> Option<BucketLock> {
        BucketLock::parse_xml(&xml::parse(std::str::from_utf8(v).ok()?)?).ok()
    }
}

pub fn invalid_bucket_state(msg: &str) -> S3Error {
    S3Error::new("InvalidBucketState", StatusCode::CONFLICT, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(mode: Mode, until: u64, hold: Option<bool>) -> State {
        State { retention: Some(Retention { mode, until }), legal_hold: hold }
    }

    #[test]
    fn headers_roundtrip() {
        let s = st(Mode::Compliance, 2_000_000_000, Some(true));
        let mut h = vec![("content-type".to_string(), "x".to_string()), (MODE.into(), "GOVERNANCE".into())];
        s.store(&mut h);
        assert_eq!(State::of(&h), s);
        assert_eq!(h.iter().filter(|(k, _)| k == MODE).count(), 1);
        State::default().store(&mut h);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn delete_rules() {
        let now = 1000;
        assert!(st(Mode::Governance, 2000, None).check_delete(now, false).is_err());
        assert!(st(Mode::Governance, 2000, None).check_delete(now, true).is_ok());
        assert!(st(Mode::Compliance, 2000, None).check_delete(now, true).is_err());
        assert!(st(Mode::Compliance, 500, None).check_delete(now, false).is_ok());
        assert!(st(Mode::Compliance, 500, Some(true)).check_delete(now, true).is_err());
        assert!(State::default().check_delete(now, false).is_ok());
    }

    #[test]
    fn retention_changes() {
        let now = 1000;
        let c = st(Mode::Compliance, 2000, None);
        let r = |mode, until| Some(Retention { mode, until });
        assert!(c.check_retention_change(r(Mode::Compliance, 3000), now, false).is_ok());
        assert!(c.check_retention_change(r(Mode::Compliance, 1500), now, true).is_err());
        assert!(c.check_retention_change(r(Mode::Governance, 3000), now, true).is_err());
        assert!(c.check_retention_change(None, now, true).is_err());
        let g = st(Mode::Governance, 2000, None);
        assert!(g.check_retention_change(r(Mode::Compliance, 2000), now, false).is_ok());
        assert!(g.check_retention_change(r(Mode::Governance, 1500), now, false).is_err());
        assert!(g.check_retention_change(None, now, true).is_ok());
        // Expired retention can be changed freely.
        assert!(st(Mode::Compliance, 900, None).check_retention_change(None, now, false).is_ok());
    }

    #[test]
    fn bucket_config() {
        let doc = |s: &str| xml::parse(s).unwrap();
        let c = BucketLock::parse_xml(&doc("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>3</Days></DefaultRetention></Rule></ObjectLockConfiguration>")).unwrap();
        assert_eq!(c.default, Some((Mode::Governance, Period::Days(3))));
        assert_eq!(Period::Days(3).secs(), 3 * SECS_PER_DAY);
        assert_eq!(BucketLock::from_stored(c.to_xml().as_bytes()), Some(c));
        let y = BucketLock::parse_xml(&doc("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>")).unwrap();
        assert!(y.to_xml().contains("<Years>2</Years>"));
        assert!(BucketLock::parse_xml(&doc("<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days><Years>1</Years></DefaultRetention></Rule></ObjectLockConfiguration>")).is_err());
        assert!(
            BucketLock::parse_xml(&doc(
                "<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>"
            ))
            .is_err()
        );
    }
}
