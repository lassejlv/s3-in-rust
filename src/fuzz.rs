//! Mutation fuzzing of every parser that sees client input (or on-disk records), as unit tests:
//! valid seeds are mutated (bit flips, truncation, splicing, repetition, hostile bytes) and fed
//! to each parser, which must return a value or an error, never panic. Deterministic per seed;
//! `S3RS_FUZZ_ITERS` raises the iteration count for longer local runs.

use crate::{access, auth, chunked, events, iam, lifecycle, lock, post, s3, util, website, xml};
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const INTERESTING: &[&[u8]] = &[
    b"<",
    b">",
    b"</",
    b"/>",
    b"&",
    b"&amp;",
    b"&#0;",
    b"&#x110000;",
    b"&#99999999999;",
    b"<!--",
    b"<![CDATA[",
    b"<?xml",
    b"\"",
    b"'",
    b"\\",
    b"\\u0000",
    b"\\ud800",
    b"{",
    b"}",
    b"[",
    b"]",
    b":",
    b",",
    b"=",
    b";",
    b"\r\n",
    b"\0",
    b"\xff",
    b"\xc3",
    b"\xe2\x82",
    b"%",
    b"%zz",
    b"%00",
    b"%ff",
    b"*",
    b"?",
    b"${",
    b"${aws:username}",
    b"-",
    b"0",
    b"-1",
    b"18446744073709551616",
    b"99999999999999999999",
    b"1e309",
    b"NaN",
    b"bytes=",
    b"chunk-signature=",
];

fn mutate(rng: &mut Rng, seed: &[u8], seeds: &[&[u8]]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        let pos = rng.below(v.len() + 1);
        match rng.below(8) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => v.truncate(pos),
            2 => {
                let ins = INTERESTING[rng.below(INTERESTING.len())];
                v.splice(pos..pos, ins.iter().copied());
            }
            3 if !v.is_empty() => {
                // Repeat a slice (deep nesting, long runs).
                let a = rng.below(v.len());
                let b = (a + 1 + rng.below(32)).min(v.len());
                let piece = v[a..b].to_vec();
                for _ in 0..1 + rng.below(64) {
                    v.splice(pos.min(v.len())..pos.min(v.len()), piece.iter().copied());
                }
            }
            4 => {
                // Splice in part of another seed.
                let other = seeds[rng.below(seeds.len())];
                let a = rng.below(other.len());
                let b = (a + rng.below(64)).min(other.len());
                v.splice(pos..pos, other[a..b].iter().copied());
            }
            5 if !v.is_empty() => {
                let a = rng.below(v.len());
                let b = (a + rng.below(16)).min(v.len());
                v.drain(a..b);
            }
            6 => v.insert(pos, rng.next() as u8),
            _ => {}
        }
    }
    v
}

fn iterations() -> usize {
    std::env::var("S3RS_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(3000)
}

/// Feed mutations of `seeds` to `f`; report the first input that panics.
fn fuzz(name: &str, seeds: &[&[u8]], f: impl Fn(&[u8])) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64 ^ (name.as_bytes()[0] as u64) << 32);
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for s in seeds {
        if catch_unwind(AssertUnwindSafe(|| f(s))).is_err() {
            std::panic::set_hook(prev);
            panic!("{name}: seed panicked: {:?}", String::from_utf8_lossy(s));
        }
    }
    for _ in 0..iterations() {
        let seed = seeds[rng.below(seeds.len())];
        let input = mutate(&mut rng, seed, seeds);
        if catch_unwind(AssertUnwindSafe(|| f(&input))).is_err() {
            std::panic::set_hook(prev);
            panic!("{name}: panicked on input {:?}", String::from_utf8_lossy(&input));
        }
    }
    std::panic::set_hook(prev);
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

const XML_SEEDS: &[&[u8]] = &[
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Delete><Object><Key>a&amp;b</Key><VersionId>null</VersionId></Object><Quiet>true</Quiet></Delete>",
    b"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedHeader>*</AllowedHeader><MaxAgeSeconds>3000</MaxAgeSeconds><ExposeHeader>ETag</ExposeHeader></CORSRule></CORSConfiguration>",
    b"<LifecycleConfiguration><Rule><ID>r</ID><Filter><And><Prefix>logs/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>3</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>",
    b"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>",
    b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Days>1</Days></DefaultRetention></Rule></ObjectLockConfiguration>",
    b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument><ErrorDocument><Key>404.html</Key></ErrorDocument><RoutingRules><RoutingRule><Condition><KeyPrefixEquals>docs/</KeyPrefixEquals><HttpErrorCodeReturnedEquals>404</HttpErrorCodeReturnedEquals></Condition><Redirect><HostName>example.com</HostName><Protocol>https</Protocol><ReplaceKeyPrefixWith>d/</ReplaceKeyPrefixWith><HttpRedirectCode>301</HttpRedirectCode></Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>",
    b"<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.com</HostName></RedirectAllRequestsTo></WebsiteConfiguration>",
    b"<NotificationConfiguration><QueueConfiguration><Id>q</Id><Queue>arn:s3rs:webhook::hook</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>a/</Value></FilterRule></S3Key></Filter></QueueConfiguration></NotificationConfiguration>",
    b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"abc\"</ETag></Part></CompleteMultipartUpload>",
    b"<BucketQuota><MaxBytes>1000</MaxBytes><MaxObjects>3</MaxObjects></BucketQuota>",
    b"<a><!-- c --><b x=\"1\" y='2'/><![CDATA[<raw>]]>&#65;&#x42;&lt;&gt;&quot;&apos;</a>",
];

#[test]
fn xml_configs() {
    let targets = vec!["hook".to_string()];
    fuzz("xml", XML_SEEDS, |b| {
        let Some(doc) = xml::parse(&text(b)) else { return };
        let _ = access::parse_cors(&doc);
        let _ = access::parse_tagging_xml(&doc, 50);
        let _ = lifecycle::parse(&doc);
        let _ = lock::BucketLock::parse_xml(&doc);
        let _ = website::Config::parse(&doc);
        let _ = events::parse_config(&doc, &targets);
        let _ = events::load_config("b", &doc, &targets);
    });
}

const POLICY_SEEDS: &[&[u8]] = &[
    br#"{"Version":"2012-10-17","Statement":[{"Sid":"a","Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject","s3:List*"],"Resource":["arn:aws:s3:::b/${aws:username}/*","arn:aws:s3:::b"],"Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","::1/128"]},"StringLike":{"s3:prefix":["home/*"]},"NumericLessThan":{"s3:max-keys":"10"},"Bool":{"aws:SecureTransport":"true"},"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}"#,
    br#"{"Statement":{"Effect":"Deny","NotPrincipal":"*","NotAction":"s3:*","NotResource":"*","Condition":{"Null":{"s3:x-amz-acl":"true"},"ForAnyValue:StringEquals":{"s3:ExistingObjectTag/env":["a","b"]}}}}"#,
    br#"{"a":[1,2.5e10,-3,true,false,null,"\u00e9\ud83d\ude00\n\t\"\\"],"b":{}}"#,
];

#[test]
fn policies_and_json() {
    fuzz("policy", POLICY_SEEDS, |b| {
        let s = text(b);
        let _ = access::parse_json(&s);
        let _ = iam::Policy::parse(&s, iam::Kind::Bucket, Some("b"));
        let _ = iam::Policy::parse(&s, iam::Kind::Identity, None);
    });
}

const POST_POLICY_SEEDS: &[&[u8]] = &[
    br#"{"expiration":"2030-01-01T00:00:00.000Z","conditions":[{"bucket":"b"},["starts-with","$key","up/"],["content-length-range",1,1048576],{"acl":"public-read"},["eq","$Content-Type","image/png"]]}"#,
];

#[test]
fn post_policies_and_forms() {
    fuzz("post-policy", POST_POLICY_SEEDS, |b| {
        let _ = post::PostPolicy::parse(&util::base64(b));
        let _ = post::PostPolicy::parse(&text(b));
    });
    fuzz("form-boundary", &[b"multipart/form-data; boundary=----abc", b"multipart/form-data; boundary=\"q\"; x=y"], |b| {
        let _ = post::boundary(&text(b));
    });
}

#[test]
fn small_grammars() {
    let seeds: &[&[u8]] = &[
        b"bytes=0-99",
        b"bytes=-500",
        b"bytes=100-",
        b"env=prod&team=a%20b&x=",
        b"list-type=2&prefix=a%2Fb&delimiter=/&continuation-token=abc&max-keys=1000&encoding-type=url",
        b"Wed, 21 Oct 2015 07:28:00 GMT",
        b"20150830T123600Z",
        b"2030-01-01T00:00:00.000Z",
        b"0123456789abcdef0123456789abcdef",
        b"https://[::1]:8443/hook?x=1",
        b"http://hooks.internal:8080/s3",
        b"private",
        b"GOVERNANCE",
        b"ON",
    ];
    fuzz("grammars", seeds, |b| {
        let s = text(b);
        for size in [0, 1, 100, u64::MAX] {
            let _ = s3::parse_range(&s, size);
        }
        let _ = s3::parse_query(&s);
        let _ = access::parse_tagging_header(&s);
        let _ = util::parse_http_date(&s);
        let _ = util::parse_amz_date(&s);
        let _ = util::parse_iso8601(&s);
        let _ = util::uri_decode(&s, true);
        let _ = util::uri_decode(&s, false);
        let _ = util::parse_id_hex(&s);
        let _ = events::Url::parse(&s);
        let _ = access::CannedAcl::parse(&s);
        let _ = lock::Mode::parse(&s);
        let _ = lock::parse_legal_hold(&s);
        let _ = lock::parse_retention(&s, &s, 0);
        let _ = crate::crypt::parse_customer_key(&s, Some(&s));
    });
}

#[test]
fn aws_chunked_bodies() {
    let seeds: &[&[u8]] = &[
        b"5;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\nhello\r\n0;chunk-signature=0000000000000000000000000000000000000000000000000000000000000000\r\n\r\n",
        b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n",
        b"a\r\n0123456789\r\n3\r\nabc\r\n0\r\n\r\n",
    ];
    fuzz("aws-chunked", seeds, |b| {
        for trailer in [false, true] {
            let mut d = chunked::ChunkDecoder::new(None, trailer);
            // Split the input at a random-ish point to exercise state across feeds.
            let cut = b.len() / 3;
            let mut sink = |_b: bytes::Bytes| {};
            if d.feed(bytes::Bytes::copy_from_slice(&b[..cut]), &mut sink).is_ok()
                && d.feed(bytes::Bytes::copy_from_slice(&b[cut..]), &mut sink).is_ok()
            {
                let _ = d.finish();
            }
        }
    });
}

#[test]
fn auth_headers() {
    let auth = auth::Auth::new(vec![auth::Credential {
        access_key: "AKID".into(),
        secret: "secret".into(),
        read_only: false,
        buckets: None,
        policy: None,
        expires_ms: None,
    }]);
    let seeds: &[&[u8]] = &[
        b"AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        b"AWS AKID:c2lnbmF0dXJl",
        b"X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
        b"AWSAccessKeyId=AKID&Expires=99999999999&Signature=abc%3D",
    ];
    fuzz("auth", seeds, |b| {
        let s = text(b);
        let header_ok = hyper::header::HeaderValue::from_str(&s).is_ok();
        let mut req = hyper::Request::builder()
            .method("GET")
            .uri("/bucket/key")
            .header("host", "localhost")
            .header("x-amz-date", "20240101T000000Z")
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD");
        if header_ok {
            req = req.header("authorization", s.as_str());
        }
        let (parts, ()) = req.body(()).expect("request").into_parts();
        let _ = auth::payload_mode(&parts);
        let _ = auth.verify(&parts, "", None);
        let _ = auth.verify(&parts, &s, Some("bucket"));
        let _ = auth::has_credentials(&parts, &s);
    });
}

#[test]
fn stored_records() {
    // Metadata decoders read what is on disk; corruption must be an error, not a crash.
    use crate::store::meta::{ObjectMeta, PartMeta, Storage, UploadMeta};
    let obj = ObjectMeta {
        size: 5,
        mtime_ms: 1,
        etag: "\"e\"".into(),
        headers: vec![("content-type".into(), "text/plain".into())],
        checksum: None,
        storage: Storage::Segments(vec![(7, 5)]),
        tags: vec![("k".into(), "v".into())],
        version: Some("v".into()),
        seq: 3,
        delete_marker: false,
    }
    .encode();
    let upload = UploadMeta { bucket: "b".into(), key: "k".into(), initiated_ms: 1, headers: vec![], tags: vec![] }.encode();
    let part = PartMeta { size: 5, md5: [1; 16], mtime_ms: 1, file: 9, checksum: None }.encode();
    let seeds: Vec<&[u8]> = vec![&obj, &upload, &part];
    fuzz("records", &seeds, |b| {
        let _ = ObjectMeta::decode(b);
        let _ = ObjectMeta::decode_summary(b);
        let _ = UploadMeta::decode(b);
        let _ = PartMeta::decode(b);
        let _ = crate::store::Quota::decode(b);
    });
}
