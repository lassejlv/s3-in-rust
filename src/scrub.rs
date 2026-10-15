//! Online scrubbing: re-read every stored object version in the background, at a limited rate,
//! and check it against its ETag (the MD5 of the data, or of the parts' MD5s for multipart
//! objects). Encrypted data is decrypted on the way, which also checks its authentication tags.
//! This finds data damaged on disk (bit rot, bad sectors, files changed behind the server's
//! back) before a client reads it, and while backups or replicas still have a good copy.
//!
//! Damaged objects are logged and counted (`s3rs_scrub_corrupt_total`); nothing is changed.
//! SSE-C objects can't be checked without their key, and neither can SSE-S3 objects without
//! `--encryption-key`; they are counted as skipped.

use crate::crypt::{self, WrapKey};
use crate::store::Store;
use crate::store::meta::{ObjectMeta, Storage};
use crate::util;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// Versions listed per page.
const PAGE: usize = 500;

#[derive(Default)]
pub struct Stats {
    /// Versions whose data matched their ETag.
    pub verified: AtomicU64,
    pub bytes: AtomicU64,
    pub corrupt: AtomicU64,
    /// Versions that can't be checked (no key for their encryption).
    pub skipped: AtomicU64,
    /// Completed passes over all data.
    pub passes: AtomicU64,
}

pub struct Config {
    /// Time between the starts of two passes.
    pub interval: Duration,
    /// Bytes read per second, at most.
    pub rate: u64,
}

/// Keeps a pass's reads under the configured rate (sleeping on the blocking thread that
/// reads), and stops them when the server shuts down.
struct Pacer {
    started: Instant,
    rate: u64,
    read: AtomicU64,
    stopping: watch::Receiver<bool>,
}

impl Pacer {
    /// Count `n` bytes read and wait until that is within the rate. False once stopping.
    fn pace(&self, n: u64) -> bool {
        let read = self.read.fetch_add(n, Relaxed) + n;
        let due = Duration::from_secs_f64(read as f64 / self.rate.max(1) as f64);
        loop {
            if *self.stopping.borrow() {
                return false;
            }
            let Some(wait) = due.checked_sub(self.started.elapsed()) else { return true };
            std::thread::sleep(wait.min(Duration::from_millis(200)));
        }
    }
}

enum Outcome {
    Verified,
    Skipped,
    /// The server is shutting down.
    Stopped,
    /// A data file is gone (maybe the object was replaced meanwhile: checked by the caller).
    Missing(String),
    Corrupt(String),
}

fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    md5::Md5::digest(data).into()
}

/// Check one version's data against its ETag.
fn verify(store: &Store, meta: &ObjectMeta, inline: Option<&Bytes>, master: Option<&WrapKey>, pacer: &Pacer) -> Outcome {
    let header = |n: &str| meta.headers.iter().any(|(k, _)| k == n);
    let key = if header("x-amz-server-side-encryption-customer-algorithm") {
        return Outcome::Skipped;
    } else if header("x-amz-server-side-encryption") {
        match master {
            Some(k) => Some(k),
            None => return Outcome::Skipped,
        }
    } else {
        None
    };
    let mut digests: Vec<[u8; 16]> = Vec::new();
    match &meta.storage {
        Storage::Inline(_) => {
            let Some(data) = inline else { return Outcome::Missing("inline data is missing".into()) };
            match key {
                Some(k) => match crypt::decrypt_range(k, data, 0, meta.size, meta.size) {
                    Ok(p) => digests.push(md5(&p)),
                    Err(e) => return Outcome::Corrupt(format!("cannot decrypt: {}", e.message)),
                },
                None => digests.push(md5(data)),
            }
            if !pacer.pace(data.len() as u64) {
                return Outcome::Stopped;
            }
        }
        Storage::Segments(segs) => {
            for (id, len) in segs {
                let path = store.data_path(*id);
                match crate::io::segment_md5_paced(&path, *len, key, &mut |n| pacer.pace(n)) {
                    Ok(d) => digests.push(d),
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => return Outcome::Stopped,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Outcome::Missing(format!("data file {} is missing", path.display()));
                    }
                    Err(e) => return Outcome::Corrupt(format!("cannot read {}: {e}", path.display())),
                }
            }
        }
    }
    let want = meta.etag.trim_matches('"').to_ascii_lowercase();
    let got = if want.contains('-') {
        let joined: Vec<u8> = digests.concat();
        format!("{}-{}", util::hex(&md5(&joined)), digests.len())
    } else if digests.len() == 1 {
        util::hex(&digests[0])
    } else {
        util::hex(&md5(&digests.concat()))
    };
    if got == want || (meta.size == 0 && digests.is_empty()) {
        Outcome::Verified
    } else {
        Outcome::Corrupt(format!("content does not match its ETag ({got} != {want})"))
    }
}

/// Run passes until the server stops: the first right away, then one every `interval`.
pub async fn run(
    store: Arc<Store>,
    master: Option<WrapKey>,
    cfg: Config,
    stats: Arc<Stats>,
    mut stopping: watch::Receiver<bool>,
) {
    loop {
        let started = Instant::now();
        let (versions, corrupt) = match pass(&store, master.as_ref(), &cfg, &stats, &stopping).await {
            Some(r) => r,
            None => return,
        };
        stats.passes.fetch_add(1, Relaxed);
        elog!(
            "scrub: pass finished in {:.0}s: {versions} version(s) checked, {corrupt} damaged",
            started.elapsed().as_secs_f64()
        );
        let wait = cfg.interval.saturating_sub(started.elapsed());
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = stopping.changed() => return,
        }
    }
}

/// One pass over all buckets. Returns (versions checked, damaged ones), or `None` when the
/// server is stopping.
async fn pass(
    store: &Arc<Store>,
    master: Option<&WrapKey>,
    cfg: &Config,
    stats: &Stats,
    stopping: &watch::Receiver<bool>,
) -> Option<(u64, u64)> {
    let pacer = Arc::new(Pacer { started: Instant::now(), rate: cfg.rate, read: AtomicU64::new(0), stopping: stopping.clone() });
    let (mut checked, mut damaged) = (0u64, 0u64);
    let st = store.clone();
    let buckets = tokio::task::spawn_blocking(move || st.list_buckets()).await.ok()?.unwrap_or_default();
    for (bucket, _) in buckets {
        let mut marker: Option<(String, Option<String>)> = None;
        loop {
            if *stopping.borrow() {
                return None;
            }
            let (st, b, m) = (store.clone(), bucket.clone(), marker.clone());
            let page = tokio::task::spawn_blocking(move || {
                let (km, vm) = match &m {
                    Some((k, v)) => (Some(k.as_str()), v.as_deref()),
                    None => (None, None),
                };
                st.list_object_versions(&b, "", "", km, vm, PAGE)
            })
            .await
            .ok()?;
            // The bucket was deleted meanwhile.
            let Ok(page) = page else { break };
            for e in page.entries.iter().filter(|e| !e.meta.delete_marker) {
                if *stopping.borrow() {
                    return None;
                }
                let vid = e.meta.version.clone().unwrap_or_else(|| "null".into());
                let (st, b, k, key, pacer) = (store.clone(), bucket.clone(), e.key.clone(), master.cloned(), pacer.clone());
                let outcome = tokio::task::spawn_blocking(move || {
                    // Read the version again: it may have changed since it was listed.
                    let Ok((meta, inline)) = st.get_object_version(&b, &k, &vid) else { return None };
                    let first = verify(&st, &meta, inline.as_ref(), key.as_ref(), &pacer);
                    // Damage is reported only if the version still exists unchanged (a
                    // concurrent overwrite or delete removes data files under the check).
                    let outcome = match first {
                        Outcome::Missing(_) | Outcome::Corrupt(_) => match st.get_object_version(&b, &k, &vid) {
                            Ok((again, _)) if again.storage == meta.storage => first,
                            _ => return None,
                        },
                        o => o,
                    };
                    Some((outcome, meta.size))
                })
                .await
                .ok()?;
                let Some((outcome, size)) = outcome else { continue };
                let label = match &e.meta.version {
                    Some(v) => format!("{bucket}/{} (version {v})", e.key),
                    None => format!("{bucket}/{}", e.key),
                };
                match outcome {
                    Outcome::Verified => {
                        checked += 1;
                        stats.verified.fetch_add(1, Relaxed);
                        stats.bytes.fetch_add(size, Relaxed);
                    }
                    Outcome::Stopped => return None,
                    Outcome::Skipped => {
                        stats.skipped.fetch_add(1, Relaxed);
                    }
                    Outcome::Missing(why) | Outcome::Corrupt(why) => {
                        checked += 1;
                        damaged += 1;
                        stats.corrupt.fetch_add(1, Relaxed);
                        elog!("scrub: DAMAGED {label}: {why}");
                    }
                }
            }
            if !page.truncated {
                break;
            }
            marker = page.next;
            if marker.is_none() {
                break;
            }
        }
    }
    Some((checked, damaged))
}
