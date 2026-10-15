//! STS `AssumeRole`: an access key asks for temporary credentials (an access key, a secret
//! and a session token) that act as that key until they expire, optionally narrowed further by
//! a session policy. Applications hand these to jobs, browsers or other users instead of a
//! long-lived secret.
//!
//! Nothing is stored: the session token carries the claims (session access key, the key it
//! was issued for, expiry, session policy), signed with a random server key kept in the
//! metadata database, and the session's secret is derived from the same key. A session works
//! only while the key it was issued for still exists and is allowed what the request needs,
//! so deleting or restricting that key also takes effect on its sessions.

use crate::access::{Json, parse_json};
use crate::auth::hmac;
use crate::error::{S3Error, S3Result};
use crate::iam::{Kind, Policy};
use crate::util;
use crate::xml::Xml;
use hyper::StatusCode;
use std::sync::Arc;

pub const MIN_DURATION_SECS: u64 = 900;
pub const MAX_DURATION_SECS: u64 = 12 * 3600;
const DEFAULT_DURATION_SECS: u64 = 3600;
/// Longest session policy accepted (AWS allows 2048 packed characters).
const MAX_POLICY_LEN: usize = 4096;
const TOKEN_PREFIX: &str = "S3RS1.";

/// What a session credential carries besides the permissions of the key it was issued for.
#[derive(Debug)]
pub struct Session {
    /// The access key the session was issued for (its permissions apply, and it is the
    /// caller's identity in policies, rate limits and logs).
    pub parent: String,
    /// The RoleSessionName it was requested with.
    pub name: String,
    /// The session may only do what this policy allows (on top of the parent's limits).
    pub policy: Option<Arc<Policy>>,
}

/// The claims inside a session token.
#[derive(Debug, PartialEq)]
pub struct Claims {
    pub access_key: String,
    pub parent: String,
    pub name: String,
    pub expires_ms: u64,
    pub policy: Option<String>,
}

/// New temporary credentials.
pub struct Issued {
    pub access_key: String,
    pub secret: String,
    pub token: String,
    pub expires_ms: u64,
}

fn b64url(data: &[u8]) -> String {
    util::base64(data).trim_end_matches('=').replace('+', "-").replace('/', "_")
}

fn mac(key: &[u8; 32], payload: &str) -> [u8; 32] {
    hmac(key, format!("s3rs-sts-token\0{payload}").as_bytes())
}

/// The secret of a session access key.
pub fn secret_for(key: &[u8; 32], access_key: &str) -> String {
    b64url(&hmac(key, format!("s3rs-sts-secret\0{access_key}").as_bytes()))[..40].to_string()
}

/// Session access keys look like AWS's temporary ones.
pub fn is_session_key(access_key: &str) -> bool {
    access_key.starts_with("ASIA")
}

pub fn issue(key: &[u8; 32], parent: &str, name: &str, policy: Option<&str>, expires_ms: u64) -> Issued {
    let access_key = format!("ASIA{}", &crate::keys::generate_access_key()[4..]);
    let mut claims = vec![
        ("a".to_string(), Json::Str(access_key.clone())),
        ("p".to_string(), Json::Str(parent.to_string())),
        ("n".to_string(), Json::Str(name.to_string())),
        ("e".to_string(), Json::Num(expires_ms as f64)),
    ];
    if let Some(p) = policy {
        claims.push(("pol".to_string(), Json::Str(p.to_string())));
    }
    let payload = b64url(Json::Obj(claims).to_text().as_bytes());
    let token = format!("{TOKEN_PREFIX}{payload}.{}", b64url(&mac(key, &payload)));
    Issued { secret: secret_for(key, &access_key), access_key, token, expires_ms }
}

pub fn invalid_token() -> S3Error {
    S3Error::new("InvalidToken", StatusCode::BAD_REQUEST, "The provided token is malformed or otherwise invalid.")
}

pub fn expired_token() -> S3Error {
    S3Error::new("ExpiredToken", StatusCode::BAD_REQUEST, "The provided token has expired.")
}

/// Check a session token's signature and that it belongs to `access_key`.
pub fn open(key: &[u8; 32], access_key: &str, token: &str, now_ms: u64) -> S3Result<Claims> {
    let rest = token.strip_prefix(TOKEN_PREFIX).ok_or_else(invalid_token)?;
    let (payload, sig) = rest.split_once('.').ok_or_else(invalid_token)?;
    if !util::ct_eq(b64url(&mac(key, payload)).as_bytes(), sig.as_bytes()) {
        return Err(invalid_token());
    }
    let text = util::unbase64(payload).and_then(|b| String::from_utf8(b).ok()).ok_or_else(invalid_token)?;
    let j = parse_json(&text).ok_or_else(invalid_token)?;
    let s = |k: &str| match j.get(k) {
        Some(Json::Str(s)) => Some(s.clone()),
        _ => None,
    };
    let claims = Claims {
        access_key: s("a").ok_or_else(invalid_token)?,
        parent: s("p").ok_or_else(invalid_token)?,
        name: s("n").unwrap_or_default(),
        expires_ms: match j.get("e") {
            Some(Json::Num(n)) => *n as u64,
            _ => return Err(invalid_token()),
        },
        policy: s("pol"),
    };
    if claims.access_key != access_key {
        return Err(invalid_token());
    }
    if now_ms >= claims.expires_ms {
        return Err(expired_token());
    }
    Ok(claims)
}

#[derive(Debug)]
pub enum Action {
    AssumeRole(Request),
    GetCallerIdentity,
}

/// A parsed `AssumeRole` request.
#[derive(Debug)]
pub struct Request {
    pub duration_secs: u64,
    pub name: String,
    pub policy: Option<String>,
}

/// An STS error, in the query protocol's format.
pub fn error(code: &'static str, message: &str) -> S3Error {
    S3Error::new(code, StatusCode::BAD_REQUEST, message)
}

/// Parse the form body of an STS request (`Action=AssumeRole&...`).
pub fn parse_request(form: &[(String, String)]) -> S3Result<Action> {
    let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    match get("Action") {
        Some("AssumeRole") => {}
        Some("GetCallerIdentity") => return Ok(Action::GetCallerIdentity),
        Some(a) => return Err(error("InvalidAction", &format!("Could not find operation {a} for version 2011-06-15"))),
        None => return Err(error("MissingAction", "Missing Action")),
    }
    let duration_secs = match get("DurationSeconds") {
        None => DEFAULT_DURATION_SECS,
        Some(d) => match d.parse::<u64>() {
            Ok(n) if (MIN_DURATION_SECS..=MAX_DURATION_SECS).contains(&n) => n,
            _ => {
                return Err(error(
                    "ValidationError",
                    &format!("DurationSeconds must be between {MIN_DURATION_SECS} and {MAX_DURATION_SECS}"),
                ));
            }
        },
    };
    let name = get("RoleSessionName").unwrap_or("").to_string();
    if name.len() > 64 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"=,.@_-".contains(&b)) {
        return Err(error("ValidationError", "RoleSessionName must be 2 to 64 characters of [\\w+=,.@-]"));
    }
    let policy = match get("Policy") {
        None | Some("") => None,
        Some(p) if p.len() > MAX_POLICY_LEN => {
            return Err(error("PackedPolicyTooLarge", "The session policy is too large"));
        }
        Some(p) => {
            Policy::parse(p, Kind::Identity, None)
                .map_err(|e| error("MalformedPolicyDocument", &format!("The session policy is invalid: {}", e.message)))?;
            Some(p.to_string())
        }
    };
    Ok(Action::AssumeRole(Request { duration_secs, name, policy }))
}

/// Decode `application/x-www-form-urlencoded` pairs.
pub fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((util::uri_decode(k, true)?, util::uri_decode(v, true)?))
        })
        .collect()
}

const NS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";

fn doc(root: &str) -> Xml {
    Xml(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<{root} xmlns=\"{NS}\">"))
}

pub fn response_xml(i: &Issued, parent: &str, name: &str, request_id: &str) -> String {
    let session = if name.is_empty() { i.access_key.as_str() } else { name };
    let mut x = doc("AssumeRoleResponse");
    x.open("AssumeRoleResult")
        .open("AssumedRoleUser")
        .elem("Arn", session_arn(parent, session))
        .elem("AssumedRoleId", format!("{parent}:{session}"))
        .close("AssumedRoleUser")
        .open("Credentials")
        .elem("AccessKeyId", &i.access_key)
        .elem("SecretAccessKey", &i.secret)
        .elem("SessionToken", &i.token)
        .elem("Expiration", util::iso8601(i.expires_ms))
        .close("Credentials")
        .close("AssumeRoleResult")
        .open("ResponseMetadata")
        .elem("RequestId", request_id)
        .close("ResponseMetadata");
    x.finish("AssumeRoleResponse")
}

fn session_arn(parent: &str, session: &str) -> String {
    format!("arn:aws:sts::{}:assumed-role/{parent}/{session}", crate::OWNER_ID)
}

/// GetCallerIdentity: who the credentials belong to.
pub fn identity_xml(c: &crate::auth::Credential, request_id: &str) -> String {
    let (arn, id) = match &c.session {
        Some(s) => {
            let name = if s.name.is_empty() { c.access_key.as_str() } else { s.name.as_str() };
            (session_arn(&s.parent, name), format!("{}:{name}", s.parent))
        }
        None => (format!("arn:aws:iam::{}:user/{}", crate::OWNER_ID, c.access_key), c.access_key.clone()),
    };
    let mut x = doc("GetCallerIdentityResponse");
    x.open("GetCallerIdentityResult")
        .elem("Arn", arn)
        .elem("UserId", id)
        .elem("Account", crate::OWNER_ID)
        .close("GetCallerIdentityResult")
        .open("ResponseMetadata")
        .elem("RequestId", request_id)
        .close("ResponseMetadata");
    x.finish("GetCallerIdentityResponse")
}

/// STS errors have their own XML shape (`ErrorResponse/Error`), which SDKs need to read the code.
pub fn error_xml(e: &S3Error, request_id: &str) -> String {
    let mut x = doc("ErrorResponse");
    x.open("Error")
        .elem("Type", if e.status.is_server_error() { "Receiver" } else { "Sender" })
        .elem("Code", e.code)
        .elem("Message", &e.message)
        .close("Error")
        .elem("RequestId", request_id);
    x.finish("ErrorResponse")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_round_trip_and_are_tamper_proof() {
        let key = [7u8; 32];
        let i = issue(&key, "parent", "job", Some(r#"{"Statement":[]}"#), 5_000);
        assert!(is_session_key(&i.access_key) && i.access_key.len() == 20);
        assert_eq!(i.secret, secret_for(&key, &i.access_key));
        let c = open(&key, &i.access_key, &i.token, 1_000).unwrap();
        assert_eq!(
            c,
            Claims {
                access_key: i.access_key.clone(),
                parent: "parent".into(),
                name: "job".into(),
                expires_ms: 5_000,
                policy: Some(r#"{"Statement":[]}"#.into())
            }
        );
        assert_eq!(open(&key, &i.access_key, &i.token, 5_000).unwrap_err().code, "ExpiredToken");
        // Another key's token, another server's key, or a changed payload are refused.
        let other = issue(&key, "parent", "", None, 5_000);
        assert_eq!(open(&key, &i.access_key, &other.token, 1_000).unwrap_err().code, "InvalidToken");
        assert_eq!(open(&[8u8; 32], &i.access_key, &i.token, 1_000).unwrap_err().code, "InvalidToken");
        let (payload, sig) = i.token[TOKEN_PREFIX.len()..].split_once('.').unwrap();
        let forged =
            b64url(String::from_utf8(util::unbase64(payload).unwrap()).unwrap().replace("\"parent\"", "\"admin\"").as_bytes());
        assert_eq!(open(&key, &i.access_key, &format!("{TOKEN_PREFIX}{forged}.{sig}"), 1_000).unwrap_err().code, "InvalidToken");
        assert_eq!(open(&key, &i.access_key, "garbage", 1_000).unwrap_err().code, "InvalidToken");
    }

    #[test]
    fn requests() {
        let form = |s: &str| parse_form(s);
        let parse = |s: &str| match parse_request(&form(s))? {
            Action::AssumeRole(r) => Ok::<_, S3Error>(r),
            Action::GetCallerIdentity => panic!("not AssumeRole"),
        };
        let r = parse("Action=AssumeRole&Version=2011-06-15&RoleArn=arn%3Ax&RoleSessionName=ci-job").unwrap();
        assert_eq!((r.duration_secs, r.name.as_str(), r.policy), (3600, "ci-job", None));
        let r = parse(
            "Action=AssumeRole&DurationSeconds=900&Policy=%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3AGetObject%22%2C%22Resource%22%3A%22*%22%7D%5D%7D",
        )
        .unwrap();
        assert_eq!(r.duration_secs, 900);
        assert!(r.policy.unwrap().contains("s3:GetObject"));
        assert!(matches!(parse_request(&form("Action=GetCallerIdentity")), Ok(Action::GetCallerIdentity)));
        assert_eq!(parse_request(&form("Action=GetSessionToken")).unwrap_err().code, "InvalidAction");
        assert_eq!(parse("Action=AssumeRole&DurationSeconds=60").unwrap_err().code, "ValidationError");
        assert_eq!(parse("Action=AssumeRole&Policy=nope").unwrap_err().code, "MalformedPolicyDocument");
        assert_eq!(parse("Action=AssumeRole&RoleSessionName=a%20b").unwrap_err().code, "ValidationError");
    }
}
