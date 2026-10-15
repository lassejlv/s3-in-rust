//! Request classification. Every S3 request maps to exactly one operation, and that operation
//! decides both the IAM action that is authorized and the handler that runs, so the two can
//! never disagree. Requests that name more than one subresource are rejected.

use crate::error::{S3Result, err};
use hyper::Method;

/// A bucket subresource (`?acl`, `?policy`, ...) and the actions for reading / changing it.
pub struct Sub {
    pub name: &'static str,
    get: Option<&'static str>,
    put: Option<&'static str>,
    /// Deleting the configuration (`None`: DELETE is not allowed on this subresource).
    delete: Option<&'static str>,
}

const fn sub(name: &'static str, get: Option<&'static str>, put: Option<&'static str>, delete: Option<&'static str>) -> Sub {
    Sub { name, get, put, delete }
}

/// Bucket subresources. `location`, `uploads`, `versions` and `delete` are operations rather than
/// configurations; they are listed so that they count as subresources.
pub const BUCKET_SUBS: &[Sub] = &[
    sub("acl", Some("s3:GetBucketAcl"), Some("s3:PutBucketAcl"), None),
    sub("policy", Some("s3:GetBucketPolicy"), Some("s3:PutBucketPolicy"), Some("s3:DeleteBucketPolicy")),
    sub("policyStatus", Some("s3:GetBucketPolicyStatus"), None, None),
    sub("cors", Some("s3:GetBucketCORS"), Some("s3:PutBucketCORS"), Some("s3:PutBucketCORS")),
    sub("tagging", Some("s3:GetBucketTagging"), Some("s3:PutBucketTagging"), Some("s3:PutBucketTagging")),
    sub(
        "lifecycle",
        Some("s3:GetLifecycleConfiguration"),
        Some("s3:PutLifecycleConfiguration"),
        Some("s3:PutLifecycleConfiguration"),
    ),
    sub(
        "encryption",
        Some("s3:GetEncryptionConfiguration"),
        Some("s3:PutEncryptionConfiguration"),
        Some("s3:PutEncryptionConfiguration"),
    ),
    sub("versioning", Some("s3:GetBucketVersioning"), Some("s3:PutBucketVersioning"), None),
    sub("object-lock", Some("s3:GetBucketObjectLockConfiguration"), Some("s3:PutBucketObjectLockConfiguration"), None),
    sub("website", Some("s3:GetBucketWebsite"), Some("s3:PutBucketWebsite"), Some("s3:DeleteBucketWebsite")),
    sub("logging", Some("s3:GetBucketLogging"), Some("s3:PutBucketLogging"), None),
    sub("notification", Some("s3:GetBucketNotification"), Some("s3:PutBucketNotification"), None),
    sub(
        "replication",
        Some("s3:GetReplicationConfiguration"),
        Some("s3:PutReplicationConfiguration"),
        Some("s3:PutReplicationConfiguration"),
    ),
    sub("accelerate", Some("s3:GetAccelerateConfiguration"), Some("s3:PutAccelerateConfiguration"), None),
    sub("requestPayment", Some("s3:GetBucketRequestPayment"), Some("s3:PutBucketRequestPayment"), None),
    sub(
        "ownershipControls",
        Some("s3:GetBucketOwnershipControls"),
        Some("s3:PutBucketOwnershipControls"),
        Some("s3:PutBucketOwnershipControls"),
    ),
    sub(
        "publicAccessBlock",
        Some("s3:GetBucketPublicAccessBlock"),
        Some("s3:PutBucketPublicAccessBlock"),
        Some("s3:PutBucketPublicAccessBlock"),
    ),
    sub(
        "analytics",
        Some("s3:GetAnalyticsConfiguration"),
        Some("s3:PutAnalyticsConfiguration"),
        Some("s3:PutAnalyticsConfiguration"),
    ),
    sub("metrics", Some("s3:GetMetricsConfiguration"), Some("s3:PutMetricsConfiguration"), Some("s3:PutMetricsConfiguration")),
    sub(
        "inventory",
        Some("s3:GetInventoryConfiguration"),
        Some("s3:PutInventoryConfiguration"),
        Some("s3:PutInventoryConfiguration"),
    ),
    sub(
        "intelligent-tiering",
        Some("s3:GetIntelligentTieringConfiguration"),
        Some("s3:PutIntelligentTieringConfiguration"),
        Some("s3:PutIntelligentTieringConfiguration"),
    ),
    sub("location", Some("s3:GetBucketLocation"), None, None),
    sub("uploads", Some("s3:ListBucketMultipartUploads"), None, None),
    sub("versions", Some("s3:ListBucketVersions"), None, None),
    sub("delete", None, None, None),
    sub("events", Some("s3:ListenBucketNotification"), None, None),
    // s3rs extensions: storage used by a bucket, and its quota.
    sub("usage", Some("s3:GetBucketUsage"), None, None),
    sub("quota", Some("s3:GetBucketQuota"), Some("s3:PutBucketQuota"), Some("s3:PutBucketQuota")),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketOp {
    ListObjects,
    Head,
    Create,
    Delete,
    /// POST ?delete; each key is authorized separately.
    DeleteObjects,
    GetLocation,
    ListUploads,
    ListVersions,
    GetConfig(&'static str),
    PutConfig(&'static str),
    DeleteConfig(&'static str),
    /// MinIO-style ListenBucketNotification (a stream of events).
    Listen,
}

/// Whether the query parameter `name` selects a subresource, i.e. another operation on the same
/// bucket or object.
pub fn is_subresource(name: &str) -> bool {
    BUCKET_SUBS.iter().any(|s| s.name == name) || OBJECT_SUBS.contains(&name) || name == "partNumber"
}

fn has(query: &[(String, String)], name: &str) -> bool {
    query.iter().any(|(k, _)| k == name)
}

fn one_subresource<T>(found: Vec<T>) -> S3Result<Option<T>> {
    let mut it = found.into_iter();
    let first = it.next();
    if it.next().is_some() {
        return Err(err::InvalidRequest().with_message("A request may name only one subresource"));
    }
    Ok(first)
}

pub fn classify_bucket(m: &Method, query: &[(String, String)]) -> S3Result<BucketOp> {
    let sub = one_subresource(BUCKET_SUBS.iter().filter(|s| has(query, s.name)).collect())?;
    let not_allowed = || Err(err::MethodNotAllowed());
    Ok(match (m, sub) {
        (&Method::GET, None) => BucketOp::ListObjects,
        (&Method::HEAD, None) => BucketOp::Head,
        (&Method::PUT, None) => BucketOp::Create,
        (&Method::DELETE, None) => BucketOp::Delete,
        (&Method::POST, Some(s)) if s.name == "delete" => BucketOp::DeleteObjects,
        (&Method::GET, Some(s)) => match s.name {
            "location" => BucketOp::GetLocation,
            "uploads" => BucketOp::ListUploads,
            "versions" => BucketOp::ListVersions,
            "events" => BucketOp::Listen,
            "delete" => return not_allowed(),
            name => BucketOp::GetConfig(name),
        },
        (&Method::PUT, Some(s)) if s.put.is_some() => BucketOp::PutConfig(s.name),
        (&Method::DELETE, Some(s)) if s.delete.is_some() => BucketOp::DeleteConfig(s.name),
        _ => return not_allowed(),
    })
}

impl BucketOp {
    /// The IAM action (`None` for DeleteObjects, which is authorized per key).
    pub fn action(self) -> Option<&'static str> {
        let find = |name: &str| BUCKET_SUBS.iter().find(|s| s.name == name);
        match self {
            BucketOp::ListObjects | BucketOp::Head => Some("s3:ListBucket"),
            BucketOp::Create => Some("s3:CreateBucket"),
            BucketOp::Delete => Some("s3:DeleteBucket"),
            BucketOp::DeleteObjects => None,
            BucketOp::GetLocation => Some("s3:GetBucketLocation"),
            BucketOp::ListUploads => Some("s3:ListBucketMultipartUploads"),
            BucketOp::ListVersions => Some("s3:ListBucketVersions"),
            BucketOp::Listen => Some("s3:ListenBucketNotification"),
            BucketOp::GetConfig(n) => find(n).and_then(|s| s.get),
            BucketOp::PutConfig(n) => find(n).and_then(|s| s.put),
            BucketOp::DeleteConfig(n) => find(n).and_then(|s| s.delete),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectOp {
    Get,
    Head,
    ListParts,
    GetAcl,
    GetTagging,
    GetRetention,
    GetLegalHold,
    GetAttributes,
    Put,
    Copy,
    UploadPart,
    UploadPartCopy,
    PutAcl,
    PutTagging,
    PutRetention,
    PutLegalHold,
    CreateUpload,
    CompleteUpload,
    AbortUpload,
    DeleteTagging,
    Delete,
    /// Recognized but not implemented (select, restore, torrent, ...).
    Unsupported,
}

const OBJECT_SUBS: &[&str] = &[
    "uploadId",
    "uploads",
    "acl",
    "tagging",
    "retention",
    "legal-hold",
    "torrent",
    "restore",
    "select",
    "attributes",
    "renameObject",
];

pub fn classify_object(m: &Method, query: &[(String, String)], copy_source: bool) -> S3Result<ObjectOp> {
    let sub = one_subresource(OBJECT_SUBS.iter().copied().filter(|s| has(query, s)).collect())?;
    let part = has(query, "partNumber");
    if matches!(sub, Some("torrent" | "restore" | "select" | "renameObject")) {
        return Ok(ObjectOp::Unsupported);
    }
    let missing = |msg: &str| Err(err::InvalidRequest().with_message(msg.to_string()));
    Ok(match (m, sub) {
        (&Method::GET, None) => ObjectOp::Get,
        (&Method::HEAD, None) => ObjectOp::Head,
        (&Method::GET, Some("uploadId")) => ObjectOp::ListParts,
        (&Method::GET, Some("acl")) => ObjectOp::GetAcl,
        (&Method::GET, Some("tagging")) => ObjectOp::GetTagging,
        (&Method::GET, Some("retention")) => ObjectOp::GetRetention,
        (&Method::GET, Some("legal-hold")) => ObjectOp::GetLegalHold,
        (&Method::GET, Some("attributes")) => ObjectOp::GetAttributes,
        (&Method::PUT, None) if part => return missing("partNumber requires uploadId"),
        (&Method::PUT, None) if copy_source => ObjectOp::Copy,
        (&Method::PUT, None) => ObjectOp::Put,
        (&Method::PUT, Some("uploadId")) if !part => return missing("uploadId requires partNumber"),
        (&Method::PUT, Some("uploadId")) if copy_source => ObjectOp::UploadPartCopy,
        (&Method::PUT, Some("uploadId")) => ObjectOp::UploadPart,
        (&Method::PUT, Some("acl")) => ObjectOp::PutAcl,
        (&Method::PUT, Some("tagging")) => ObjectOp::PutTagging,
        (&Method::PUT, Some("retention")) => ObjectOp::PutRetention,
        (&Method::PUT, Some("legal-hold")) => ObjectOp::PutLegalHold,
        (&Method::POST, Some("uploads")) => ObjectOp::CreateUpload,
        (&Method::POST, Some("uploadId")) => ObjectOp::CompleteUpload,
        (&Method::DELETE, None) => ObjectOp::Delete,
        (&Method::DELETE, Some("uploadId")) => ObjectOp::AbortUpload,
        (&Method::DELETE, Some("tagging")) => ObjectOp::DeleteTagging,
        _ => return Err(err::MethodNotAllowed()),
    })
}

impl ObjectOp {
    /// The IAM action; `versioned` when the request names a version id.
    pub fn action(self, versioned: bool) -> Option<&'static str> {
        let v = |plain: &'static str, version: &'static str| Some(if versioned { version } else { plain });
        match self {
            ObjectOp::Get | ObjectOp::Head => v("s3:GetObject", "s3:GetObjectVersion"),
            ObjectOp::ListParts => Some("s3:ListMultipartUploadParts"),
            ObjectOp::GetAcl => v("s3:GetObjectAcl", "s3:GetObjectVersionAcl"),
            ObjectOp::GetTagging => v("s3:GetObjectTagging", "s3:GetObjectVersionTagging"),
            ObjectOp::GetRetention => Some("s3:GetObjectRetention"),
            ObjectOp::GetLegalHold => Some("s3:GetObjectLegalHold"),
            ObjectOp::GetAttributes => v("s3:GetObjectAttributes", "s3:GetObjectVersionAttributes"),
            ObjectOp::Put
            | ObjectOp::Copy
            | ObjectOp::UploadPart
            | ObjectOp::UploadPartCopy
            | ObjectOp::CreateUpload
            | ObjectOp::CompleteUpload => Some("s3:PutObject"),
            ObjectOp::PutAcl => v("s3:PutObjectAcl", "s3:PutObjectVersionAcl"),
            ObjectOp::PutTagging => v("s3:PutObjectTagging", "s3:PutObjectVersionTagging"),
            ObjectOp::PutRetention => Some("s3:PutObjectRetention"),
            ObjectOp::PutLegalHold => Some("s3:PutObjectLegalHold"),
            ObjectOp::AbortUpload => Some("s3:AbortMultipartUpload"),
            ObjectOp::DeleteTagging => v("s3:DeleteObjectTagging", "s3:DeleteObjectVersionTagging"),
            ObjectOp::Delete => v("s3:DeleteObject", "s3:DeleteObjectVersion"),
            ObjectOp::Unsupported => None,
        }
    }

    /// Operations that create an object and may carry tags, retention or a legal hold.
    pub fn creates_object(self) -> bool {
        matches!(self, ObjectOp::Put | ObjectOp::Copy | ObjectOp::CreateUpload)
    }
}

/// Bucket-level actions an anonymous caller may ever be granted (by ACL or bucket policy).
/// Managing the bucket itself (policies, ACLs, configuration, creation, deletion) is reserved
/// for keys, as on S3 where only the owning account can manage a bucket's policy.
pub fn anonymous_may(action: &str) -> bool {
    action.starts_with("s3:GetObject")
        || action.starts_with("s3:PutObject")
        || action.starts_with("s3:DeleteObject")
        || matches!(
            action,
            "s3:ListBucket"
                | "s3:ListBucketVersions"
                | "s3:ListBucketMultipartUploads"
                | "s3:ListMultipartUploadParts"
                | "s3:AbortMultipartUpload"
                | "s3:GetBucketLocation"
                | "s3:RestoreObject"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(keys: &[&str]) -> Vec<(String, String)> {
        keys.iter().map(|k| (k.to_string(), String::new())).collect()
    }

    #[test]
    fn bucket_requests() {
        let c = |m: Method, keys: &[&str]| classify_bucket(&m, &q(keys));
        assert_eq!(c(Method::GET, &[]).unwrap(), BucketOp::ListObjects);
        assert_eq!(c(Method::GET, &["list-type", "prefix"]).unwrap(), BucketOp::ListObjects);
        assert_eq!(c(Method::PUT, &[]).unwrap(), BucketOp::Create);
        // Read-only subresources never turn into creation or deletion.
        for sub in ["location", "uploads", "versions", "policyStatus", "delete"] {
            assert!(c(Method::PUT, &[sub]).is_err(), "PUT ?{sub}");
            assert!(c(Method::DELETE, &[sub]).is_err(), "DELETE ?{sub}");
        }
        for sub in ["versioning", "acl", "object-lock"] {
            assert!(c(Method::DELETE, &[sub]).is_err(), "DELETE ?{sub}");
        }
        assert!(c(Method::GET, &["versions", "acl"]).is_err());
        assert!(c(Method::HEAD, &["acl"]).is_err());
        assert_eq!(c(Method::GET, &["versions", "key-marker"]).unwrap(), BucketOp::ListVersions);
        assert_eq!(c(Method::POST, &["delete"]).unwrap(), BucketOp::DeleteObjects);
        assert_eq!(c(Method::DELETE, &["policy"]).unwrap().action(), Some("s3:DeleteBucketPolicy"));
        assert_eq!(c(Method::PUT, &["versioning"]).unwrap().action(), Some("s3:PutBucketVersioning"));
    }

    #[test]
    fn object_requests() {
        let c = |m: Method, keys: &[&str], copy: bool| classify_object(&m, &q(keys), copy);
        assert_eq!(c(Method::PUT, &["partNumber", "uploadId"], false).unwrap(), ObjectOp::UploadPart);
        assert_eq!(c(Method::PUT, &["partNumber", "uploadId"], true).unwrap(), ObjectOp::UploadPartCopy);
        assert!(c(Method::PUT, &["partNumber"], false).is_err());
        assert!(c(Method::PUT, &["uploadId"], false).is_err());
        assert!(c(Method::PUT, &["partNumber", "uploadId", "acl"], false).is_err());
        assert!(c(Method::HEAD, &["acl"], false).is_err());
        assert_eq!(c(Method::GET, &["partNumber"], false).unwrap(), ObjectOp::Get);
        assert_eq!(c(Method::GET, &["select"], false).unwrap(), ObjectOp::Unsupported);
        assert_eq!(c(Method::GET, &["attributes"], false).unwrap(), ObjectOp::GetAttributes);
        assert_eq!(c(Method::DELETE, &["versionId"], false).unwrap().action(true), Some("s3:DeleteObjectVersion"));
        assert!(c(Method::PUT, &[], true).unwrap().creates_object());
        assert!(!c(Method::PUT, &["tagging"], false).unwrap().creates_object());
    }
}
