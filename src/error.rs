//! S3 error codes and their HTTP mapping.

use hyper::StatusCode;
use std::fmt;

#[derive(Debug, Clone)]
pub struct S3Error {
    pub code: &'static str,
    pub status: StatusCode,
    pub message: String,
    /// Extra response headers (e.g. `x-amz-delete-marker` on a 404 for a deleted key).
    pub headers: Vec<(&'static str, String)>,
}

pub type S3Result<T> = Result<T, S3Error>;

impl S3Error {
    pub fn new(code: &'static str, status: StatusCode, message: impl Into<String>) -> Self {
        S3Error { code, status, message: message.into(), headers: Vec::new() }
    }

    pub fn internal(msg: impl fmt::Display) -> Self {
        Self::new("InternalError", StatusCode::INTERNAL_SERVER_ERROR, format!("We encountered an internal error: {msg}"))
    }
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl From<std::io::Error> for S3Error {
    fn from(e: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match e.kind() {
            ErrorKind::StorageFull | ErrorKind::QuotaExceeded => crate::store::space::storage_full(),
            // Out of file descriptors: temporary, and clients should back off and retry.
            _ if cfg!(unix) && matches!(e.raw_os_error(), Some(23 | 24)) => S3Error::new(
                "SlowDown",
                StatusCode::SERVICE_UNAVAILABLE,
                "Please reduce your request rate (the server is out of file descriptors).",
            ),
            _ => S3Error::internal(e),
        }
    }
}

macro_rules! errors {
    ($($name:ident => $status:ident, $msg:literal;)*) => {
        #[allow(non_snake_case, dead_code)]
        pub mod err {
            use super::*;
            $(
                pub fn $name() -> S3Error {
                    S3Error::new(stringify!($name), StatusCode::$status, $msg)
                }
            )*
        }
    };
}

errors! {
    AccessDenied => FORBIDDEN, "Access Denied";
    BadDigest => BAD_REQUEST, "The Content-MD5 or checksum you specified did not match what we received.";
    BucketAlreadyOwnedByYou => CONFLICT, "Your previous request to create the named bucket succeeded and you already own it.";
    BucketNotEmpty => CONFLICT, "The bucket you tried to delete is not empty";
    EntityTooLarge => BAD_REQUEST, "Your proposed upload exceeds the maximum allowed object size.";
    RequestTimeout => BAD_REQUEST, "Your socket connection to the server was not read from or written to within the timeout period.";
    EntityTooSmall => BAD_REQUEST, "Your proposed upload is smaller than the minimum allowed object size.";
    IncompleteBody => BAD_REQUEST, "You did not provide the number of bytes specified by the Content-Length HTTP header.";
    InvalidAccessKeyId => FORBIDDEN, "The AWS Access Key Id you provided does not exist in our records.";
    InvalidArgument => BAD_REQUEST, "Invalid Argument";
    InvalidBucketName => BAD_REQUEST, "The specified bucket is not valid.";
    InvalidDigest => BAD_REQUEST, "The Content-MD5 you specified is not valid.";
    InvalidPart => BAD_REQUEST, "One or more of the specified parts could not be found. The part might not have been uploaded, or the specified entity tag might not have matched the part's entity tag.";
    InvalidPartOrder => BAD_REQUEST, "The list of parts was not in ascending order. Parts must be ordered by part number.";
    InvalidRange => RANGE_NOT_SATISFIABLE, "The requested range is not satisfiable";
    InvalidRequest => BAD_REQUEST, "Invalid Request";
    KeyTooLongError => BAD_REQUEST, "Your key is too long";
    MalformedXML => BAD_REQUEST, "The XML you provided was not well-formed or did not validate against our published schema.";
    MethodNotAllowed => METHOD_NOT_ALLOWED, "The specified method is not allowed against this resource.";
    MissingContentLength => LENGTH_REQUIRED, "You must provide the Content-Length HTTP header.";
    NoSuchBucket => NOT_FOUND, "The specified bucket does not exist";
    NoSuchKey => NOT_FOUND, "The specified key does not exist.";
    NoSuchUpload => NOT_FOUND, "The specified multipart upload does not exist. The upload ID might be invalid, or the multipart upload might have been aborted or completed.";
    NotImplemented => NOT_IMPLEMENTED, "A header or query you provided requested a function that is not implemented.";
    PreconditionFailed => PRECONDITION_FAILED, "At least one of the pre-conditions you specified did not hold";
    RequestTimeTooSkewed => FORBIDDEN, "The difference between the request time and the server's time is too large.";
    SignatureDoesNotMatch => FORBIDDEN, "The request signature we calculated does not match the signature you provided. Check your key and signing method.";
    XAmzContentSHA256Mismatch => BAD_REQUEST, "The provided 'x-amz-content-sha256' header does not match what was computed.";
    NoSuchBucketPolicy => NOT_FOUND, "The bucket policy does not exist";
    NoSuchCORSConfiguration => NOT_FOUND, "The CORS configuration does not exist";
    NoSuchLifecycleConfiguration => NOT_FOUND, "The lifecycle configuration does not exist";
    NoSuchTagSet => NOT_FOUND, "The TagSet does not exist";
    ServerSideEncryptionConfigurationNotFoundError => NOT_FOUND, "The server side encryption configuration was not found";
    NoSuchVersion => NOT_FOUND, "The specified version does not exist.";
    NoSuchObjectLockConfiguration => NOT_FOUND, "The specified object does not have a ObjectLock configuration";
    ObjectLockConfigurationNotFoundError => NOT_FOUND, "Object Lock configuration does not exist for this bucket";
    NoSuchWebsiteConfiguration => NOT_FOUND, "The specified bucket does not have a website configuration";
    ReplicationConfigurationNotFoundError => NOT_FOUND, "The replication configuration was not found";
    NoSuchPublicAccessBlockConfiguration => NOT_FOUND, "The public access block configuration was not found";
    OwnershipControlsNotFoundError => NOT_FOUND, "The bucket ownership controls were not found";
    AccessControlListNotSupported => BAD_REQUEST, "The bucket does not allow ACLs";
    InvalidBucketAclWithObjectOwnership => BAD_REQUEST, "Bucket cannot have ACLs set with ObjectOwnership's BucketOwnerEnforced setting";
    ConditionalRequestConflict => CONFLICT, "A conflicting conditional operation is currently in progress against this resource.";
}

impl S3Error {
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = msg.into();
        self
    }

    pub fn with_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }
}
