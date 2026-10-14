//! Bucket lifecycle rules: object expiration and cleanup of abandoned multipart uploads.
//!
//! Rules are stored as the raw XML document per bucket. A background task sweeps every bucket
//! that has a configuration on a fixed interval. Expiration uses a compare-and-delete so an
//! object rewritten after the sweeper inspected it is never removed by mistake.

use crate::error::{S3Result, err};
use crate::store::meta::ObjectMeta;
use crate::store::{Op, OpOut, PurgeRule, Store};
use crate::util;
use crate::xml;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub enabled: bool,
    pub prefix: String,
    pub tags: Vec<(String, String)>,
    pub size_gt: Option<u64>,
    pub size_lt: Option<u64>,
    pub expire_days: Option<u64>,
    /// Unix seconds.
    pub expire_date: Option<u64>,
    pub abort_mpu_days: Option<u64>,
    /// Remove versions this many days after they became noncurrent.
    pub noncurrent_days: Option<u64>,
    /// Remove delete markers that are the only remaining version of their key.
    pub expired_delete_marker: bool,
}

fn bad(msg: &str) -> crate::error::S3Error {
    err::MalformedXML().with_message(msg.to_string())
}

fn parse_filter(f: &xml::Node, rule: &mut Rule) -> S3Result<()> {
    let mut apply = |n: &xml::Node| -> S3Result<()> {
        if let Some(p) = n.child_text("Prefix") {
            rule.prefix = p.to_string();
        }
        for t in n.children_named("Tag") {
            let k = t.child_text("Key").ok_or_else(|| bad("Tag requires a Key"))?;
            rule.tags.push((k.to_string(), t.child_text("Value").unwrap_or("").to_string()));
        }
        if let Some(v) = n.child_text("ObjectSizeGreaterThan") {
            rule.size_gt = Some(v.trim().parse().map_err(|_| bad("Invalid ObjectSizeGreaterThan"))?);
        }
        if let Some(v) = n.child_text("ObjectSizeLessThan") {
            rule.size_lt = Some(v.trim().parse().map_err(|_| bad("Invalid ObjectSizeLessThan"))?);
        }
        Ok(())
    };
    apply(f)?;
    if let Some(and) = f.child("And") {
        apply(and)?;
    }
    Ok(())
}

pub fn parse(doc: &xml::Node) -> S3Result<Vec<Rule>> {
    if doc.name != "LifecycleConfiguration" {
        return Err(err::MalformedXML());
    }
    let mut rules = Vec::new();
    for r in doc.children_named("Rule") {
        let mut rule = Rule {
            enabled: match r.child_text("Status").map(str::trim) {
                Some("Enabled") => true,
                Some("Disabled") => false,
                _ => return Err(bad("Rule Status must be Enabled or Disabled")),
            },
            ..Default::default()
        };
        // Legacy top-level <Prefix> or the newer <Filter>.
        if let Some(p) = r.child_text("Prefix") {
            rule.prefix = p.to_string();
        }
        if let Some(f) = r.child("Filter") {
            parse_filter(f, &mut rule)?;
        }
        if let Some(e) = r.child("Expiration") {
            if let Some(d) = e.child_text("Days") {
                let d: u64 = d.trim().parse().map_err(|_| bad("Invalid Days"))?;
                if d == 0 {
                    return Err(err::InvalidArgument().with_message("'Days' for Expiration action must be a positive integer"));
                }
                rule.expire_days = Some(d);
            }
            if let Some(d) = e.child_text("Date") {
                let t = util::parse_iso8601(d.trim()).ok_or_else(|| bad("Invalid Date"))?;
                if t % 86_400 != 0 {
                    return Err(err::InvalidArgument().with_message("'Date' must be at midnight GMT"));
                }
                rule.expire_date = Some(t);
            }
            if let Some(v) = e.child_text("ExpiredObjectDeleteMarker") {
                rule.expired_delete_marker = v.trim().eq_ignore_ascii_case("true");
            }
        }
        if let Some(n) = r.child("NoncurrentVersionExpiration") {
            let d: u64 = n
                .child_text("NoncurrentDays")
                .and_then(|d| d.trim().parse().ok())
                .filter(|d| *d > 0)
                .ok_or_else(|| bad("Invalid NoncurrentDays"))?;
            rule.noncurrent_days = Some(d);
        }
        if let Some(a) = r.child("AbortIncompleteMultipartUpload") {
            let d: u64 = a
                .child_text("DaysAfterInitiation")
                .and_then(|d| d.trim().parse().ok())
                .filter(|d| *d > 0)
                .ok_or_else(|| bad("Invalid DaysAfterInitiation"))?;
            rule.abort_mpu_days = Some(d);
        }
        // Transitions are accepted but have no effect: there is a single storage class.
        let has_other = ["Transition", "NoncurrentVersionTransition"].iter().any(|n| r.child(n).is_some());
        if rule.expire_days.is_none()
            && rule.expire_date.is_none()
            && rule.abort_mpu_days.is_none()
            && rule.noncurrent_days.is_none()
            && !rule.expired_delete_marker
            && !has_other
        {
            return Err(err::InvalidRequest().with_message("At least one action needs to be specified in a rule"));
        }
        rules.push(rule);
    }
    if rules.is_empty() || rules.len() > 1000 {
        return Err(bad("A lifecycle configuration must have between 1 and 1000 rules"));
    }
    Ok(rules)
}

impl Rule {
    fn matches(&self, key: &str, meta: &ObjectMeta) -> bool {
        key.starts_with(&self.prefix)
            && self.size_gt.is_none_or(|s| meta.size > s)
            && self.size_lt.is_none_or(|s| meta.size < s)
            && self.tags.iter().all(|t| meta.tags.contains(t))
    }

    /// Whether an object is due for expiration at `now` (unix seconds). Like S3, a Days rule
    /// expires the object at the first "midnight" after mtime + days.
    fn expired(&self, meta: &ObjectMeta, now: u64, day_secs: u64) -> bool {
        if let Some(date) = self.expire_date
            && now >= date
        {
            return true;
        }
        if let Some(days) = self.expire_days {
            let due = (meta.mtime_ms / 1000 + days * day_secs).div_ceil(day_secs) * day_secs;
            return now >= due;
        }
        false
    }
}

#[derive(Default)]
pub struct Stats {
    pub expired: AtomicU64,
    pub aborted_uploads: AtomicU64,
}

/// Run one sweep over all buckets. Returns (objects expired, uploads aborted).
pub async fn sweep(store: &Arc<Store>, day_secs: u64, events: Option<&crate::events::Bus>) -> S3Result<(u64, u64)> {
    let notify = |bucket: &str, removed: &[crate::store::Removed]| {
        let Some(bus) = events else { return };
        for r in removed {
            bus.emit(crate::events::Event {
                name: if r.marker_created { "LifecycleExpiration:DeleteMarkerCreated" } else { "LifecycleExpiration:Delete" },
                bucket: bucket.to_string(),
                key: r.key.clone(),
                size: r.size,
                etag: r.etag.clone(),
                version: r.version.clone(),
                principal: String::new(),
                source_ip: String::new(),
                request_id: String::new(),
                time_ms: util::now_ms(),
                sequencer: 0,
            });
        }
    };
    let (mut expired, mut aborted) = (0u64, 0u64);
    let st = store.clone();
    let buckets = tokio::task::spawn_blocking(move || st.list_buckets()).await.map_err(crate::error::S3Error::internal)??;
    for (bucket, _) in buckets {
        let Ok(Some(doc)) = store.bucket_config(&bucket, "lifecycle") else { continue };
        let Some(rules) = xml::parse(&String::from_utf8_lossy(&doc)).and_then(|d| parse(&d).ok()) else { continue };
        let now = util::now_ms() / 1000;
        for rule in rules.iter().filter(|r| r.enabled) {
            if rule.expire_days.is_some() || rule.expire_date.is_some() {
                let mut after: Option<String> = None;
                loop {
                    let (st, b, p, a) = (store.clone(), bucket.clone(), rule.prefix.clone(), after.clone());
                    let page = tokio::task::spawn_blocking(move || st.scan_objects(&b, &p, a.as_deref(), 1000))
                        .await
                        .map_err(crate::error::S3Error::internal)??;
                    let Some((last, _)) = page.last() else { break };
                    after = Some(last.clone());
                    let due: Vec<(String, u64)> = page
                        .iter()
                        .filter(|(k, m)| rule.matches(k, m) && rule.expired(m, now, day_secs))
                        .map(|(k, m)| (k.clone(), m.mtime_ms))
                        .collect();
                    if !due.is_empty()
                        && let Ok(OpOut::Removed(removed)) = store.submit(Op::Expire { bucket: bucket.clone(), items: due }).await
                    {
                        expired += removed.len() as u64;
                        notify(&bucket, &removed);
                    }
                    if page.len() < 1000 {
                        break;
                    }
                }
            }
            if rule.noncurrent_days.is_some() || rule.expired_delete_marker {
                let mut after: Option<Vec<u8>> = None;
                loop {
                    let (st, b, p, a) = (store.clone(), bucket.clone(), rule.prefix.clone(), after.clone());
                    let page = tokio::task::spawn_blocking(move || st.scan_noncurrent(&b, &p, a.as_deref(), 1000))
                        .await
                        .map_err(crate::error::S3Error::internal)??;
                    let n = page.items.len();
                    // Due when since + days, rounded up to midnight, has passed; equivalently when
                    // the version became noncurrent at or before this cutoff.
                    let cutoff = rule.noncurrent_days.map(|d| (now / day_secs * day_secs).saturating_sub(d * day_secs));
                    let due: Vec<(String, u64, PurgeRule)> = page
                        .items
                        .iter()
                        // Delete markers carry no tags or size, so only the prefix applies to them.
                        .filter(|it| {
                            if it.meta.delete_marker { it.key.starts_with(&rule.prefix) } else { rule.matches(&it.key, &it.meta) }
                        })
                        .filter_map(|it| {
                            let why = match it.noncurrent_since_ms {
                                Some(since) => {
                                    let cut = cutoff?;
                                    (since / 1000 <= cut).then_some(PurgeRule::NoncurrentBefore(cut))?
                                }
                                None if rule.expired_delete_marker && it.meta.delete_marker && it.only_version => {
                                    PurgeRule::LoneDeleteMarker
                                }
                                None => return None,
                            };
                            Some((it.key.clone(), it.meta.seq, why))
                        })
                        .collect();
                    if !due.is_empty()
                        && let Ok(OpOut::Removed(removed)) =
                            store.submit(Op::PurgeVersions { bucket: bucket.clone(), items: due }).await
                    {
                        expired += removed.len() as u64;
                        notify(&bucket, &removed);
                    }
                    match page.last {
                        Some(l) if n >= 1000 => after = Some(l),
                        _ => break,
                    }
                }
            }
            if let Some(days) = rule.abort_mpu_days {
                let cutoff_ms = now.saturating_sub(days * day_secs) * 1000;
                for u in store.list_uploads(&bucket, &rule.prefix)? {
                    if u.meta.initiated_ms <= cutoff_ms
                        && store.submit(Op::Abort { bucket: bucket.clone(), key: u.meta.key.clone(), upload: u.id }).await.is_ok()
                    {
                        aborted += 1;
                    }
                }
            }
        }
    }
    Ok((expired, aborted))
}

/// Background loop: sweep every `interval`.
pub async fn run(store: Arc<Store>, interval: Duration, day_secs: u64, stats: Arc<Stats>, events: Arc<crate::events::Bus>) {
    loop {
        tokio::time::sleep(interval).await;
        match sweep(&store, day_secs, Some(&events)).await {
            Ok((e, a)) => {
                stats.expired.fetch_add(e, Ordering::Relaxed);
                stats.aborted_uploads.fetch_add(a, Ordering::Relaxed);
                if e > 0 || a > 0 {
                    eprintln!("lifecycle: expired {e} object(s), aborted {a} multipart upload(s)");
                }
            }
            Err(e) => eprintln!("lifecycle sweep failed: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::meta::Storage;

    fn meta(size: u64, mtime_s: u64, tags: &[(&str, &str)]) -> ObjectMeta {
        ObjectMeta {
            size,
            mtime_ms: mtime_s * 1000,
            etag: String::new(),
            headers: vec![],
            checksum: None,
            storage: Storage::Inline(0),
            tags: tags.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            version: None,
            seq: 0,
            delete_marker: false,
        }
    }

    #[test]
    fn parses_and_matches() {
        let doc = xml::parse(
            "<LifecycleConfiguration><Rule><ID>logs</ID><Status>Enabled</Status>\
             <Filter><And><Prefix>logs/</Prefix><Tag><Key>tier</Key><Value>tmp</Value></Tag></And></Filter>\
             <Expiration><Days>2</Days></Expiration>\
             <AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload>\
             </Rule><Rule><Status>Disabled</Status><Prefix>old/</Prefix><Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule>\
             </LifecycleConfiguration>",
        )
        .unwrap();
        let rules = parse(&doc).unwrap();
        assert_eq!(rules.len(), 2);
        let r = &rules[0];
        assert_eq!((r.prefix.as_str(), r.expire_days, r.abort_mpu_days), ("logs/", Some(2), Some(1)));
        assert!(r.matches("logs/a", &meta(1, 0, &[("tier", "tmp")])));
        assert!(!r.matches("logs/a", &meta(1, 0, &[])));
        assert!(!r.matches("data/a", &meta(1, 0, &[("tier", "tmp")])));
        assert!(!rules[1].enabled);
        assert_eq!(rules[1].expire_date, Some(1_577_836_800));
    }

    #[test]
    fn expiry_rounds_to_midnight() {
        let r = Rule { expire_days: Some(1), ..Default::default() };
        let day = 86_400;
        // Written at 10:00 on day 0: due at midnight starting day 2 (mtime + 1 day, rounded up).
        let m = meta(1, 10 * 3600, &[]);
        assert!(!r.expired(&m, day + 10 * 3600, day));
        assert!(!r.expired(&m, 2 * day - 1, day));
        assert!(r.expired(&m, 2 * day, day));
    }

    #[test]
    fn parses_noncurrent_actions() {
        let doc = xml::parse(
            "<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>\
             <NoncurrentVersionExpiration><NoncurrentDays>3</NoncurrentDays></NoncurrentVersionExpiration>\
             <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>",
        )
        .unwrap();
        let r = &parse(&doc).unwrap()[0];
        assert_eq!((r.noncurrent_days, r.expired_delete_marker, r.expire_days), (Some(3), true, None));
    }

    #[test]
    fn rejects_invalid() {
        let p = |s: &str| parse(&xml::parse(s).unwrap());
        assert!(p("<LifecycleConfiguration><Rule><Status>Enabled</Status></Rule></LifecycleConfiguration>").is_err());
        assert!(p("<LifecycleConfiguration><Rule><Status>On</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>").is_err());
        assert!(p("<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Days>0</Days></Expiration></Rule></LifecycleConfiguration>").is_err());
        assert!(p("<LifecycleConfiguration><Rule><Status>Enabled</Status><Expiration><Date>2020-01-01T05:00:00Z</Date></Expiration></Rule></LifecycleConfiguration>").is_err());
    }
}
