//! IAM-style policies: per-key identity policies and bucket (resource) policies.
//!
//! Supported: `Effect`, `Principal` / `NotPrincipal` (bucket policies), `Action` / `NotAction`,
//! `Resource` / `NotResource`, and `Condition` with the String*, Numeric*, Date*, Bool,
//! IpAddress / NotIpAddress and Null operators (plus `...IfExists` and the `ForAnyValue:` /
//! `ForAllValues:` set qualifiers). Policy variables such as `${aws:username}` work in resources
//! and condition values. Evaluation follows AWS: an explicit Deny wins over any Allow.

use crate::access::{Json, glob, parse_json};
use crate::error::{S3Error, S3Result};
use crate::util::parse_iso8601;
use hyper::StatusCode;
use std::net::IpAddr;

fn malformed(msg: impl Into<String>) -> S3Error {
    S3Error::new("MalformedPolicy", StatusCode::BAD_REQUEST, msg)
}

/// Who a statement applies to (bucket policies only).
#[derive(Debug, Clone)]
enum Principals {
    Anyone,
    /// Access keys, given as the key itself or as `arn:aws:iam::<account>:user/<key>`.
    Users(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    StringEquals,
    StringNotEquals,
    StringEqualsIgnoreCase,
    StringNotEqualsIgnoreCase,
    StringLike,
    StringNotLike,
    NumericEquals,
    NumericNotEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    DateEquals,
    DateNotEquals,
    DateLessThan,
    DateLessThanEquals,
    DateGreaterThan,
    DateGreaterThanEquals,
    Bool,
    IpAddress,
    NotIpAddress,
    Null,
}

impl Op {
    fn parse(s: &str) -> Option<Op> {
        use Op::*;
        Some(match s {
            "StringEquals" => StringEquals,
            "StringNotEquals" => StringNotEquals,
            "StringEqualsIgnoreCase" => StringEqualsIgnoreCase,
            "StringNotEqualsIgnoreCase" => StringNotEqualsIgnoreCase,
            "StringLike" => StringLike,
            "StringNotLike" => StringNotLike,
            "NumericEquals" => NumericEquals,
            "NumericNotEquals" => NumericNotEquals,
            "NumericLessThan" => NumericLessThan,
            "NumericLessThanEquals" => NumericLessThanEquals,
            "NumericGreaterThan" => NumericGreaterThan,
            "NumericGreaterThanEquals" => NumericGreaterThanEquals,
            "DateEquals" => DateEquals,
            "DateNotEquals" => DateNotEquals,
            "DateLessThan" => DateLessThan,
            "DateLessThanEquals" => DateLessThanEquals,
            "DateGreaterThan" => DateGreaterThan,
            "DateGreaterThanEquals" => DateGreaterThanEquals,
            "Bool" => Bool,
            "IpAddress" => IpAddress,
            "NotIpAddress" => NotIpAddress,
            "Null" => Null,
            _ => return None,
        })
    }

    /// Negated operators match when *no* value matches (and when the key is missing).
    fn negated(self) -> bool {
        use Op::*;
        matches!(
            self,
            StringNotEquals | StringNotEqualsIgnoreCase | StringNotLike | NumericNotEquals | DateNotEquals | NotIpAddress
        )
    }

    /// Does one request value match one policy value (ignoring negation)?
    fn test(self, actual: &str, expected: &str) -> bool {
        use Op::*;
        match self {
            StringEquals | StringNotEquals => actual == expected,
            StringEqualsIgnoreCase | StringNotEqualsIgnoreCase => actual.eq_ignore_ascii_case(expected),
            StringLike | StringNotLike => glob(expected, actual, false),
            NumericEquals
            | NumericNotEquals
            | NumericLessThan
            | NumericLessThanEquals
            | NumericGreaterThan
            | NumericGreaterThanEquals => match (actual.trim().parse::<f64>(), expected.trim().parse::<f64>()) {
                (Ok(a), Ok(e)) => cmp(self, a.partial_cmp(&e)),
                _ => false,
            },
            DateEquals | DateNotEquals | DateLessThan | DateLessThanEquals | DateGreaterThan | DateGreaterThanEquals => {
                match (date(actual), date(expected)) {
                    (Some(a), Some(e)) => cmp(self, Some(a.cmp(&e))),
                    _ => false,
                }
            }
            Bool => actual.eq_ignore_ascii_case(expected.trim()),
            IpAddress | NotIpAddress => ip_in(actual, expected),
            Null => unreachable!("Null is evaluated on key presence"),
        }
    }
}

fn cmp(op: Op, o: Option<std::cmp::Ordering>) -> bool {
    use Op::*;
    use std::cmp::Ordering::*;
    let Some(o) = o else { return false };
    match op {
        NumericEquals | NumericNotEquals | DateEquals | DateNotEquals => o == Equal,
        NumericLessThan | DateLessThan => o == Less,
        NumericLessThanEquals | DateLessThanEquals => o != Greater,
        NumericGreaterThan | DateGreaterThan => o == Greater,
        NumericGreaterThanEquals | DateGreaterThanEquals => o != Less,
        _ => false,
    }
}

/// Dates as ISO 8601 or epoch seconds.
fn date(s: &str) -> Option<u64> {
    let s = s.trim();
    parse_iso8601(s).or_else(|| s.parse().ok())
}

/// Is `ip` inside `cidr` (`10.0.0.0/8`, `2001:db8::/32`, or a single address)?
fn ip_in(ip: &str, cidr: &str) -> bool {
    let Ok(ip) = ip.parse::<IpAddr>() else { return false };
    let (net, bits) = match cidr.trim().split_once('/') {
        Some((n, b)) => (n, b.parse::<u32>().ok()),
        None => (cidr.trim(), None),
    };
    let Ok(net) = net.parse::<IpAddr>() else { return false };
    let to_v6 = |a: IpAddr| match a {
        IpAddr::V4(v4) => (v4.to_ipv6_mapped(), 96),
        IpAddr::V6(v6) => (v6, 0),
    };
    let ((a, _), (n, offset)) = (to_v6(ip), to_v6(net));
    let bits = match bits {
        Some(b) if b + offset <= 128 => b + offset,
        Some(_) => return false,
        None => 128,
    };
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    (u128::from(a) & mask) == (u128::from(n) & mask)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetQualifier {
    Single,
    ForAnyValue,
    ForAllValues,
}

#[derive(Debug, Clone)]
struct Condition {
    op: Op,
    set: SetQualifier,
    if_exists: bool,
    key: String,
    values: Vec<String>,
}

#[derive(Debug, Clone)]
struct Statement {
    allow: bool,
    /// `None` for identity policies (no Principal element).
    principals: Option<Principals>,
    not_principal: bool,
    actions: Vec<String>,
    not_action: bool,
    resources: Vec<String>,
    not_resource: bool,
    conditions: Vec<Condition>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    statements: Vec<Statement>,
}

/// Result of evaluating one policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    /// No statement applies.
    NotApplicable,
}

/// Everything a policy may look at about the current request.
pub struct Ctx<'a> {
    /// Access key of the caller, `None` when anonymous.
    pub username: Option<&'a str>,
    pub source_ip: IpAddr,
    pub secure: bool,
    pub headers: &'a hyper::HeaderMap,
    pub query: &'a [(String, String)],
    /// `REST-HEADER`, `REST-QUERY-STRING` or `POST`.
    pub auth_type: &'static str,
    /// Unix seconds.
    pub now: u64,
}

impl Ctx<'_> {
    /// Values of a condition key in this request (keys are case-insensitive).
    fn value(&self, key: &str) -> Option<Vec<String>> {
        let k = key.to_ascii_lowercase();
        let header = |n: &str| self.headers.get(n).and_then(|v| v.to_str().ok()).map(|v| vec![v.to_string()]);
        let query = |n: &str| self.query.iter().find(|(q, _)| q == n).map(|(_, v)| vec![v.clone()]);
        match k.as_str() {
            "aws:sourceip" => Some(vec![self.source_ip.to_string()]),
            "aws:securetransport" => Some(vec![self.secure.to_string()]),
            "aws:username" | "aws:userid" => self.username.map(|u| vec![u.to_string()]),
            "aws:principaltype" => Some(vec![if self.username.is_some() { "User" } else { "Anonymous" }.to_string()]),
            "aws:useragent" => header("user-agent"),
            "aws:referer" => header("referer"),
            "aws:currenttime" => Some(vec![crate::util::iso8601(self.now * 1000)]),
            "aws:epochtime" => Some(vec![self.now.to_string()]),
            "s3:authtype" => Some(vec![self.auth_type.to_string()]),
            "s3:prefix" => query("prefix"),
            "s3:delimiter" => query("delimiter"),
            "s3:max-keys" => query("max-keys"),
            "s3:versionid" => query("versionId"),
            "s3:x-amz-acl" => header("x-amz-acl"),
            "s3:x-amz-server-side-encryption" => header("x-amz-server-side-encryption"),
            "s3:x-amz-copy-source" => header("x-amz-copy-source"),
            "s3:x-amz-metadata-directive" => header("x-amz-metadata-directive"),
            "s3:x-amz-storage-class" => header("x-amz-storage-class"),
            "s3:object-lock-mode" => header("x-amz-object-lock-mode"),
            "s3:object-lock-legal-hold" => header("x-amz-object-lock-legal-hold"),
            "s3:object-lock-retain-until-date" => header("x-amz-object-lock-retain-until-date"),
            "s3:requestobjecttagkeys" => self.headers.get("x-amz-tagging").and_then(|v| v.to_str().ok()).map(|t| {
                t.split('&')
                    .filter_map(|p| p.split('=').next())
                    .filter(|k| !k.is_empty())
                    .map(|k| crate::util::uri_decode(k, true).unwrap_or_else(|| k.to_string()))
                    .collect()
            }),
            _ => None,
        }
    }

    /// Expand `${aws:username}`-style variables (and `${*}`, `${?}`, `${$}`); `None` when a
    /// variable has no value in this request (the containing element then cannot match).
    fn expand(&self, s: &str) -> Option<String> {
        if !s.contains("${") {
            return Some(s.to_string());
        }
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find("${") {
            out.push_str(&rest[..i]);
            let after = &rest[i + 2..];
            let Some(end) = after.find('}') else {
                out.push_str(&rest[i..]);
                return Some(out);
            };
            let name = &after[..end];
            match name {
                "*" | "?" | "$" => out.push_str(name),
                _ => out.push_str(&self.value(name)?.into_iter().next()?),
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Some(out)
    }
}

/// A string or an array of strings (numbers and booleans become strings, as in IAM).
fn strings(v: &Json) -> Option<Vec<String>> {
    let one = |v: &Json| match v {
        Json::Str(s) => Some(s.clone()),
        Json::Bool(b) => Some(b.to_string()),
        Json::Num(n) => Some(if n.fract() == 0.0 { format!("{}", *n as i64) } else { n.to_string() }),
        _ => None,
    };
    match v {
        Json::Arr(a) => a.iter().map(one).collect(),
        other => one(other).map(|s| vec![s]),
    }
}

/// Which statement elements a policy kind expects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Attached to an access key: no Principal.
    Identity,
    /// Attached to a bucket: Principal required, resources must be inside the bucket.
    Bucket,
}

impl Policy {
    pub fn parse(doc: &str, kind: Kind, bucket: Option<&str>) -> S3Result<Policy> {
        let json = parse_json(doc).ok_or_else(|| malformed("Policies must be valid JSON"))?;
        if let Some(v) = json.get("Version")
            && !matches!(v, Json::Str(s) if s == "2012-10-17" || s == "2008-10-17")
        {
            return Err(malformed("The policy Version must be 2012-10-17 or 2008-10-17"));
        }
        let stmts = match json.get("Statement") {
            Some(Json::Arr(a)) if !a.is_empty() => a.iter().collect::<Vec<_>>(),
            Some(o @ Json::Obj(_)) => vec![o],
            _ => return Err(malformed("Missing required field Statement")),
        };
        let mut statements = Vec::with_capacity(stmts.len());
        for st in stmts {
            let Json::Obj(fields) = st else { return Err(malformed("Each statement must be an object")) };
            for (k, _) in fields {
                if !matches!(
                    k.as_str(),
                    "Sid"
                        | "Effect"
                        | "Principal"
                        | "NotPrincipal"
                        | "Action"
                        | "NotAction"
                        | "Resource"
                        | "NotResource"
                        | "Condition"
                ) {
                    return Err(malformed(format!("Unknown field {k}")));
                }
            }
            let allow = match st.get("Effect") {
                Some(Json::Str(e)) if e == "Allow" => true,
                Some(Json::Str(e)) if e == "Deny" => false,
                _ => return Err(malformed("Invalid effect")),
            };
            let (principals, not_principal) = match (kind, st.get("Principal"), st.get("NotPrincipal")) {
                (Kind::Identity, None, None) => (None, false),
                (Kind::Identity, _, _) => return Err(malformed("Identity policies may not contain a Principal")),
                (Kind::Bucket, Some(p), None) => (Some(parse_principal(p)?), false),
                (Kind::Bucket, None, Some(p)) => (Some(parse_principal(p)?), true),
                (Kind::Bucket, _, _) => return Err(malformed("Each statement needs exactly one of Principal or NotPrincipal")),
            };
            let (actions, not_action) = one_of(st, "Action", "NotAction")?;
            for a in &actions {
                if !(a == "*" || a.to_ascii_lowercase().starts_with("s3:")) {
                    return Err(malformed(format!("Policy has an invalid action: {a}")));
                }
            }
            let (resources, not_resource) = one_of(st, "Resource", "NotResource")?;
            for r in &resources {
                if !(r == "*" || r.starts_with("arn:aws:s3:::")) {
                    return Err(malformed(format!("Policy has an invalid resource: {r}")));
                }
                if let Some(b) = bucket {
                    let arn = format!("arn:aws:s3:::{b}");
                    let inside = r == &arn
                        || r.starts_with(&format!("{arn}/"))
                        || (r.ends_with('*') && arn.starts_with(r.trim_end_matches('*')));
                    if !inside {
                        return Err(malformed("Policy has invalid resource"));
                    }
                }
            }
            let conditions = match st.get("Condition") {
                None => Vec::new(),
                Some(c) => parse_conditions(c)?,
            };
            statements.push(Statement {
                allow,
                principals,
                not_principal,
                actions,
                not_action,
                resources,
                not_resource,
                conditions,
            });
        }
        Ok(Policy { statements })
    }

    /// Evaluate for one request: `action` like `s3:GetObject`, `resource` an S3 ARN.
    pub fn evaluate(&self, action: &str, resource: &str, ctx: &Ctx) -> Decision {
        let mut allowed = false;
        for st in &self.statements {
            if !st.applies(action, resource, ctx) {
                continue;
            }
            if !st.allow {
                return Decision::Deny;
            }
            allowed = true;
        }
        if allowed { Decision::Allow } else { Decision::NotApplicable }
    }

    /// Whether any statement grants access to everyone without conditions.
    pub fn is_public(&self) -> bool {
        self.statements
            .iter()
            .any(|s| s.allow && !s.not_principal && matches!(s.principals, Some(Principals::Anyone)) && s.conditions.is_empty())
    }
}

fn one_of(st: &Json, pos: &str, neg: &str) -> S3Result<(Vec<String>, bool)> {
    match (st.get(pos), st.get(neg)) {
        (Some(v), None) => Ok((strings(v).filter(|v| !v.is_empty()).ok_or_else(|| malformed(format!("Invalid {pos}")))?, false)),
        (None, Some(v)) => Ok((strings(v).filter(|v| !v.is_empty()).ok_or_else(|| malformed(format!("Invalid {neg}")))?, true)),
        _ => Err(malformed(format!("Each statement needs exactly one of {pos} or {neg}"))),
    }
}

fn parse_principal(p: &Json) -> S3Result<Principals> {
    let list = match p {
        Json::Str(s) if s == "*" => return Ok(Principals::Anyone),
        Json::Obj(_) => match p.get("AWS") {
            Some(v) => strings(v).ok_or_else(|| malformed("Invalid principal"))?,
            // Other principal types (services, canonical users) never match a request here.
            None => Vec::new(),
        },
        _ => return Err(malformed("Invalid principal")),
    };
    if list.iter().any(|s| s == "*") {
        return Ok(Principals::Anyone);
    }
    Ok(Principals::Users(list))
}

fn parse_conditions(c: &Json) -> S3Result<Vec<Condition>> {
    let Json::Obj(ops) = c else { return Err(malformed("Invalid Condition")) };
    let mut out = Vec::new();
    for (name, body) in ops {
        let (set, rest) = if let Some(r) = name.strip_prefix("ForAnyValue:") {
            (SetQualifier::ForAnyValue, r)
        } else if let Some(r) = name.strip_prefix("ForAllValues:") {
            (SetQualifier::ForAllValues, r)
        } else {
            (SetQualifier::Single, name.as_str())
        };
        let (base, if_exists) = match rest.strip_suffix("IfExists") {
            Some(b) if b != "Null" => (b, true),
            _ => (rest, false),
        };
        let op = Op::parse(base).ok_or_else(|| malformed(format!("Unknown condition operator {name}")))?;
        let Json::Obj(keys) = body else { return Err(malformed(format!("Invalid condition block {name}"))) };
        for (key, vals) in keys {
            let values = strings(vals).filter(|v| !v.is_empty()).ok_or_else(|| malformed(format!("Invalid values for {key}")))?;
            out.push(Condition { op, set, if_exists, key: key.clone(), values });
        }
    }
    Ok(out)
}

impl Statement {
    fn applies(&self, action: &str, resource: &str, ctx: &Ctx) -> bool {
        if let Some(p) = &self.principals {
            let hit = match p {
                Principals::Anyone => true,
                Principals::Users(list) => ctx
                    .username
                    .is_some_and(|u| list.iter().any(|s| s == u || s.rsplit_once(":user/").is_some_and(|(_, name)| name == u))),
            };
            if hit == self.not_principal {
                return false;
            }
        }
        if self.actions.iter().any(|a| glob(a, action, true)) == self.not_action {
            return false;
        }
        // A resource with an unresolvable variable matches nothing.
        let res_hit = self.resources.iter().any(|r| ctx.expand(r).is_some_and(|r| glob(&r, resource, false)));
        if res_hit == self.not_resource {
            return false;
        }
        self.conditions.iter().all(|c| c.holds(ctx))
    }
}

impl Condition {
    fn holds(&self, ctx: &Ctx) -> bool {
        let actual = ctx.value(&self.key);
        if self.op == Op::Null {
            // "Null": "true" means the key must be absent.
            let absent = actual.is_none();
            return self.values.iter().any(|v| v.eq_ignore_ascii_case("true") == absent);
        }
        let Some(actual) = actual else {
            return self.if_exists || self.op.negated() || self.set == SetQualifier::ForAllValues;
        };
        let expected: Vec<String> = self.values.iter().filter_map(|v| ctx.expand(v)).collect();
        let matches_one = |a: &str| expected.iter().any(|e| self.op.test(a, e));
        let hit = match self.set {
            SetQualifier::Single | SetQualifier::ForAnyValue => actual.iter().any(|a| matches_one(a)),
            SetQualifier::ForAllValues => actual.iter().all(|a| matches_one(a)),
        };
        if self.op.negated() { !hit } else { hit }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    fn ctx<'a>(user: Option<&'a str>, ip: &str, headers: &'a HeaderMap, query: &'a [(String, String)]) -> Ctx<'a> {
        Ctx {
            username: user,
            source_ip: ip.parse().unwrap(),
            secure: true,
            headers,
            query,
            auth_type: "REST-HEADER",
            now: 1_800_000_000,
        }
    }

    #[test]
    fn identity_policy_with_home_prefix() {
        let p = Policy::parse(
            r#"{"Version":"2012-10-17","Statement":[
                {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::home/${aws:username}/*"},
                {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::home",
                 "Condition":{"StringLike":{"s3:prefix":["${aws:username}/*","${aws:username}"]}}},
                {"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["10.0.0.0/8","::1"]}}}
            ]}"#,
            Kind::Identity,
            None,
        )
        .unwrap();
        let h = HeaderMap::new();
        let q = vec![("prefix".to_string(), "alice/docs/".to_string())];
        let c = ctx(Some("alice"), "10.1.2.3", &h, &q);
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::home/alice/x", &c), Decision::Allow);
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::home/bob/x", &c), Decision::NotApplicable);
        assert_eq!(p.evaluate("s3:DeleteObject", "arn:aws:s3:::home/alice/x", &c), Decision::NotApplicable);
        assert_eq!(p.evaluate("s3:ListBucket", "arn:aws:s3:::home", &c), Decision::Allow);
        let q2 = vec![("prefix".to_string(), "bob/".to_string())];
        assert_eq!(
            p.evaluate("s3:ListBucket", "arn:aws:s3:::home", &ctx(Some("alice"), "10.1.2.3", &h, &q2)),
            Decision::NotApplicable
        );
        // No prefix at all: StringLike on a missing key does not match.
        assert_eq!(
            p.evaluate("s3:ListBucket", "arn:aws:s3:::home", &ctx(Some("alice"), "10.1.2.3", &h, &[])),
            Decision::NotApplicable
        );
        // Outside the allowed networks everything is denied.
        assert_eq!(
            p.evaluate("s3:GetObject", "arn:aws:s3:::home/alice/x", &ctx(Some("alice"), "8.8.8.8", &h, &q)),
            Decision::Deny
        );
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::home/alice/x", &ctx(Some("alice"), "::1", &h, &q)), Decision::Allow);
        // Anonymous callers have no username, so the variable resource matches nothing.
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::home//x", &ctx(None, "10.0.0.1", &h, &q)), Decision::NotApplicable);
    }

    #[test]
    fn bucket_policy_principals_and_not_elements() {
        let p = Policy::parse(
            r#"{"Statement":[
                {"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/alice","bob"]},"Action":"s3:*","Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"]},
                {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/public/*"},
                {"Effect":"Deny","NotPrincipal":{"AWS":"alice"},"NotAction":["s3:Get*","s3:List*"],"Resource":"arn:aws:s3:::b/*"}
            ]}"#,
            Kind::Bucket,
            Some("b"),
        )
        .unwrap();
        let h = HeaderMap::new();
        let c = |u| ctx(u, "1.2.3.4", &h, &[]);
        assert_eq!(p.evaluate("s3:PutObject", "arn:aws:s3:::b/k", &c(Some("alice"))), Decision::Allow);
        assert_eq!(p.evaluate("s3:PutObject", "arn:aws:s3:::b/k", &c(Some("bob"))), Decision::Deny);
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::b/k", &c(Some("bob"))), Decision::Allow);
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::b/public/x", &c(None)), Decision::Allow);
        assert_eq!(p.evaluate("s3:GetObject", "arn:aws:s3:::b/private", &c(None)), Decision::NotApplicable);
        assert_eq!(p.evaluate("s3:DeleteObject", "arn:aws:s3:::b/public/x", &c(None)), Decision::Deny);
        assert!(p.is_public());
    }

    #[test]
    fn condition_operators() {
        let mut h = HeaderMap::new();
        h.insert("x-amz-server-side-encryption", "AES256".parse().unwrap());
        let q = vec![("max-keys".to_string(), "50".to_string())];
        let c = ctx(Some("u"), "192.168.1.9", &h, &q);
        let eval = |cond: &str| {
            let doc = format!(r#"{{"Statement":{{"Effect":"Allow","Action":"*","Resource":"*","Condition":{cond}}}}}"#);
            Policy::parse(&doc, Kind::Identity, None).unwrap().evaluate("s3:ListBucket", "arn:aws:s3:::b", &c) == Decision::Allow
        };
        assert!(eval(r#"{"NumericLessThanEquals":{"s3:max-keys":"100"}}"#));
        assert!(!eval(r#"{"NumericGreaterThan":{"s3:max-keys":100}}"#));
        assert!(eval(r#"{"StringEquals":{"s3:x-amz-server-side-encryption":"AES256"}}"#));
        assert!(eval(r#"{"StringNotEquals":{"s3:x-amz-acl":"public-read"}}"#)); // missing key + negated
        assert!(!eval(r#"{"StringEquals":{"s3:x-amz-acl":"private"}}"#)); // missing key
        assert!(eval(r#"{"StringEqualsIfExists":{"s3:x-amz-acl":"private"}}"#));
        assert!(eval(r#"{"Null":{"s3:x-amz-acl":"true"},"Bool":{"aws:SecureTransport":true}}"#));
        assert!(eval(r#"{"IpAddress":{"aws:SourceIp":"192.168.0.0/16"}}"#));
        assert!(!eval(r#"{"IpAddress":{"aws:SourceIp":"192.168.2.0/24"}}"#));
        assert!(eval(r#"{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}"#));
        assert!(eval(r#"{"StringLike":{"aws:username":"u*"}}"#));
        assert!(
            Policy::parse(
                r#"{"Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bogus":{"a":"b"}}}}"#,
                Kind::Identity,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn validation() {
        let bad = |doc: &str, kind| Policy::parse(doc, kind, Some("b")).is_err();
        assert!(bad(r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Principal":"*"}}"#, Kind::Identity));
        assert!(bad(r#"{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}}"#, Kind::Bucket));
        assert!(bad(
            r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::other/*"}}"#,
            Kind::Bucket
        ));
        assert!(bad(
            r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"ec2:*","Resource":"arn:aws:s3:::b/*"}}"#,
            Kind::Bucket
        ));
        assert!(bad(
            r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*","NotAction":"s3:Get*","Resource":"arn:aws:s3:::b/*"}}"#,
            Kind::Bucket
        ));
        assert!(bad(
            r#"{"Version":"2001","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}}"#,
            Kind::Bucket
        ));
        assert!(!bad(
            r#"{"Statement":{"Sid":"x","Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::b*"}}"#,
            Kind::Bucket
        ));
    }

    #[test]
    fn cidr() {
        assert!(ip_in("10.1.2.3", "10.0.0.0/8"));
        assert!(!ip_in("11.1.2.3", "10.0.0.0/8"));
        assert!(ip_in("1.2.3.4", "1.2.3.4"));
        assert!(ip_in("1.2.3.4", "0.0.0.0/0"));
        assert!(ip_in("2001:db8::1", "2001:db8::/32"));
        assert!(!ip_in("2001:db9::1", "2001:db8::/32"));
        assert!(!ip_in("1.2.3.4", "1.2.3.0/33"));
    }
}
