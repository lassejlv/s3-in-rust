//! Access keys managed through the admin API (`/_admin/keys`), stored in the metadata database
//! next to the keys from the command line and the credentials file.

use crate::access::{Json, parse_json};
use crate::auth::Credential;
use crate::error::{S3Result, err};
use crate::iam;
use std::sync::Arc;

/// A stored access key.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub secret: String,
    pub read_only: bool,
    /// Bucket name patterns the key is limited to.
    pub buckets: Option<Vec<String>>,
    /// IAM-style identity policy (JSON text).
    pub policy: Option<String>,
    pub created_ms: u64,
    pub description: String,
    /// A temporary key stops working at this time (unix milliseconds) and is then removed.
    pub expires_ms: Option<u64>,
}

fn strings(v: Option<&Json>) -> Option<Vec<String>> {
    match v? {
        Json::Arr(a) => a.iter().map(|x| if let Json::Str(s) = x { Some(s.clone()) } else { None }).collect(),
        _ => None,
    }
}

fn text(v: Option<&Json>) -> Option<String> {
    match v? {
        Json::Str(s) => Some(s.clone()),
        _ => None,
    }
}

impl Record {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![
            ("secret".to_string(), Json::Str(self.secret.clone())),
            ("read_only".to_string(), Json::Bool(self.read_only)),
            ("created_ms".to_string(), Json::Num(self.created_ms as f64)),
            ("description".to_string(), Json::Str(self.description.clone())),
        ];
        if let Some(b) = &self.buckets {
            o.push(("buckets".into(), Json::Arr(b.iter().cloned().map(Json::Str).collect())));
        }
        if let Some(p) = &self.policy {
            o.push(("policy".into(), Json::Str(p.clone())));
        }
        if let Some(t) = self.expires_ms {
            o.push(("expires_ms".into(), Json::Num(t as f64)));
        }
        Json::Obj(o).to_text().into_bytes()
    }

    pub fn decode(b: &[u8]) -> Option<Record> {
        let j = parse_json(std::str::from_utf8(b).ok()?)?;
        Some(Record {
            secret: text(j.get("secret"))?,
            read_only: matches!(j.get("read_only"), Some(Json::Bool(true))),
            buckets: strings(j.get("buckets")),
            policy: text(j.get("policy")),
            created_ms: match j.get("created_ms") {
                Some(Json::Num(n)) => *n as u64,
                _ => 0,
            },
            description: text(j.get("description")).unwrap_or_default(),
            expires_ms: match j.get("expires_ms") {
                Some(Json::Num(n)) => Some(*n as u64),
                _ => None,
            },
        })
    }

    pub fn expired(&self, now_ms: u64) -> bool {
        self.expires_ms.is_some_and(|t| now_ms >= t)
    }

    pub fn credential(&self, access_key: &str) -> Result<Credential, String> {
        let policy = match &self.policy {
            Some(p) => Some(Arc::new(iam::Policy::parse(p, iam::Kind::Identity, None).map_err(|e| e.message)?)),
            None => None,
        };
        Ok(Credential {
            access_key: access_key.to_string(),
            secret: self.secret.clone(),
            read_only: self.read_only,
            buckets: self.buckets.clone(),
            policy,
            expires_ms: self.expires_ms,
            session: None,
        })
    }
}

/// Characters for generated keys: unambiguous upper-case letters and digits.
const KEY_CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const SECRET_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn random_string(alphabet: &[u8], len: usize) -> String {
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        getrandom::fill(&mut buf).expect("system randomness");
        // Rejection sampling keeps every character equally likely.
        let limit = 256 - 256 % alphabet.len();
        for b in buf {
            if (b as usize) < limit && out.len() < len {
                out.push(alphabet[b as usize % alphabet.len()] as char);
            }
        }
    }
    out
}

pub fn generate_access_key() -> String {
    format!("S3RS{}", random_string(KEY_CHARS, 16))
}

pub fn generate_secret() -> String {
    random_string(SECRET_CHARS, 40)
}

pub fn valid_access_key(k: &str) -> bool {
    (3..=128).contains(&k.len()) && k.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The longest a temporary key may live.
const MAX_LIFETIME_SECS: u64 = 10 * 365 * 86_400;

/// A create request: `{"access_key"?, "secret_key"?, "read_only"?, "buckets"?, "policy"?,
/// "description"?, "expires_in"?}` (`expires_in` in seconds makes a temporary key).
/// Missing keys and secrets are generated. Returns the access key and the record to store.
pub fn parse_request(body: &str, now_ms: u64) -> S3Result<(String, Record)> {
    let bad = |m: &str| err::InvalidArgument().with_message(m.to_string());
    let j = parse_json(body).ok_or_else(|| bad("The request body must be a JSON object"))?;
    let Json::Obj(fields) = &j else { return Err(bad("The request body must be a JSON object")) };
    for (k, _) in fields {
        if !matches!(k.as_str(), "access_key" | "secret_key" | "read_only" | "buckets" | "policy" | "description" | "expires_in")
        {
            return Err(bad(&format!("Unknown field {k}")));
        }
    }
    let access_key = match j.get("access_key") {
        None | Some(Json::Null) => generate_access_key(),
        Some(Json::Str(k)) if valid_access_key(k) => k.clone(),
        _ => return Err(bad("access_key must be 3 to 128 letters, digits, '.', '_' or '-'")),
    };
    let secret = match j.get("secret_key") {
        None | Some(Json::Null) => generate_secret(),
        Some(Json::Str(s)) if s.len() >= 16 && s.len() <= 256 && !s.chars().any(char::is_whitespace) => s.clone(),
        _ => return Err(bad("secret_key must be 16 to 256 characters without spaces")),
    };
    let read_only = match j.get("read_only") {
        None | Some(Json::Null) => false,
        Some(Json::Bool(b)) => *b,
        _ => return Err(bad("read_only must be true or false")),
    };
    let buckets = match j.get("buckets") {
        None | Some(Json::Null) => None,
        v => match strings(v) {
            Some(b) if !b.is_empty() && b.iter().all(|p| !p.is_empty() && p.len() <= 63) => Some(b),
            _ => return Err(bad("buckets must be a non-empty list of bucket names or patterns")),
        },
    };
    let policy = match j.get("policy") {
        None | Some(Json::Null) => None,
        Some(p @ Json::Obj(_)) => Some(p.to_text()),
        Some(Json::Str(p)) => Some(p.clone()),
        _ => return Err(bad("policy must be an IAM policy document")),
    };
    if let Some(p) = &policy {
        iam::Policy::parse(p, iam::Kind::Identity, None)?;
        if read_only {
            return Err(bad("read_only and policy can't be combined: put the restrictions in the policy"));
        }
    }
    let description = match j.get("description") {
        None | Some(Json::Null) => String::new(),
        Some(Json::Str(d)) if d.len() <= 256 => d.clone(),
        _ => return Err(bad("description must be a string of at most 256 characters")),
    };
    let expires_ms = match j.get("expires_in") {
        None | Some(Json::Null) => None,
        Some(Json::Num(n)) if *n >= 1.0 && *n <= MAX_LIFETIME_SECS as f64 && n.fract() == 0.0 => Some(now_ms + *n as u64 * 1000),
        _ => return Err(bad("expires_in must be a number of seconds, at most ten years")),
    };
    Ok((access_key, Record { secret, read_only, buckets, policy, created_ms: now_ms, description, expires_ms }))
}

/// The keys in effect: those from the command line and credentials file, then stored ones.
/// A stored key whose name is also in the file, or that can't be read, is left out (with a
/// warning): the file wins.
pub fn merge(file: &[Credential], stored: &[(String, Vec<u8>)]) -> Vec<Credential> {
    let mut out = file.to_vec();
    for (ak, raw) in stored {
        if file.iter().any(|c| c.access_key == *ak) {
            elog!("warning: access key {ak} is defined both in the credentials file and through the admin API; the file wins");
            continue;
        }
        match Record::decode(raw).ok_or_else(|| "unreadable record".to_string()).and_then(|r| r.credential(ak)) {
            Ok(c) => out.push(c),
            Err(e) => elog!("warning: stored access key {ak} is ignored: {e}"),
        }
    }
    out
}

/// One key as listed by `GET /_admin/keys` (never with its secret).
pub fn describe(access_key: &str, source: &str, record: Option<&Record>, c: Option<&Credential>) -> Json {
    let mut o = vec![
        ("access_key".to_string(), Json::Str(access_key.to_string())),
        ("source".to_string(), Json::Str(source.to_string())),
    ];
    let (read_only, buckets, policy) = match (record, c) {
        (Some(r), _) => (r.read_only, r.buckets.clone(), r.policy.is_some()),
        (None, Some(c)) => (c.read_only, c.buckets.clone(), c.policy.is_some()),
        (None, None) => (false, None, false),
    };
    o.push(("read_only".into(), Json::Bool(read_only)));
    o.push(("buckets".into(), buckets.map_or(Json::Null, |b| Json::Arr(b.into_iter().map(Json::Str).collect()))));
    o.push(("policy".into(), Json::Bool(policy)));
    if let Some(r) = record {
        o.push(("created".into(), Json::Str(crate::util::iso8601(r.created_ms))));
        o.push(("description".into(), Json::Str(r.description.clone())));
        if let Some(t) = r.expires_ms {
            o.push(("expires".into(), Json::Str(crate::util::iso8601(t))));
        }
    }
    Json::Obj(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_records() {
        let (ak, r) = parse_request("{}", 5).unwrap();
        assert!(ak.starts_with("S3RS") && ak.len() == 20 && valid_access_key(&ak));
        assert_eq!(r.secret.len(), 40);
        assert!(!r.read_only && r.buckets.is_none() && r.policy.is_none());
        assert_eq!(Record::decode(&r.encode()).unwrap(), r);

        let (ak, r) = parse_request(
            r#"{"access_key":"app-1","secret_key":"0123456789abcdefXYZ","buckets":["logs-*"],"description":"the \"app\""}"#,
            7,
        )
        .unwrap();
        assert_eq!((ak.as_str(), r.secret.as_str()), ("app-1", "0123456789abcdefXYZ"));
        assert_eq!(r.buckets, Some(vec!["logs-*".to_string()]));
        assert_eq!(Record::decode(&r.encode()).unwrap(), r);

        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;
        let (_, r) = parse_request(&format!(r#"{{"policy":{policy}}}"#), 0).unwrap();
        let c = r.credential("x").unwrap();
        assert!(c.policy.is_some());
        assert_eq!(Record::decode(&r.encode()).unwrap(), r);

        for bad in [
            "[]",
            r#"{"access_key":"a b"}"#,
            r#"{"secret_key":"short"}"#,
            r#"{"read_only":"yes"}"#,
            r#"{"buckets":[]}"#,
            r#"{"policy":{"Statement":"nope"}}"#,
            r#"{"unknown":1}"#,
            r#"{"read_only":true,"policy":{"Version":"2012-10-17","Statement":[]}}"#,
            r#"{"expires_in":0}"#,
            r#"{"expires_in":1.5}"#,
            r#"{"expires_in":"1h"}"#,
        ] {
            assert!(parse_request(bad, 0).is_err(), "{bad}");
        }
    }

    #[test]
    fn temporary_keys() {
        let (_, r) = parse_request(r#"{"expires_in":3600}"#, 1_000).unwrap();
        assert_eq!(r.expires_ms, Some(3_601_000));
        assert_eq!(Record::decode(&r.encode()).unwrap(), r);
        assert!(!r.expired(3_600_999) && r.expired(3_601_000));
        assert_eq!(r.credential("t").unwrap().expires_ms, Some(3_601_000));
    }

    #[test]
    fn file_keys_win() {
        let file = vec![Credential {
            access_key: "a".into(),
            secret: "s".into(),
            read_only: false,
            buckets: None,
            policy: None,
            expires_ms: None,
            session: None,
        }];
        let (_, r) = parse_request(r#"{"secret_key":"0123456789abcdef0","read_only":true}"#, 0).unwrap();
        let stored = vec![("a".to_string(), r.encode()), ("b".to_string(), r.encode()), ("c".to_string(), b"junk".to_vec())];
        let all = merge(&file, &stored);
        assert_eq!(all.iter().map(|c| c.access_key.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert!(!all[0].read_only && all[1].read_only);
    }

    #[test]
    fn generated_keys_are_random() {
        let a: std::collections::HashSet<String> = (0..1000).map(|_| generate_secret()).collect();
        assert_eq!(a.len(), 1000);
        assert!(a.iter().all(|s| s.len() == 40 && s.bytes().all(|b| SECRET_CHARS.contains(&b))));
    }
}
