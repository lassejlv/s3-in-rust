//! Lock-free request metrics, exposed in Prometheus text format at `/_metrics`.

use crate::store::Store;
use hyper::Method;
use std::fmt::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

const METHODS: [&str; 7] = ["GET", "HEAD", "PUT", "POST", "DELETE", "OPTIONS", "OTHER"];
/// Latency histogram bucket upper bounds, in seconds.
const BOUNDS: [f64; 12] = [0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

#[derive(Default)]
pub struct Metrics {
    started: OnceLock<Instant>,
    inflight: AtomicI64,
    /// Open client connections.
    pub connections: std::sync::Arc<AtomicI64>,
    /// The connection limit.
    pub max_connections: AtomicU64,
    /// [method][status class 1xx..5xx]
    requests: [[AtomicU64; 5]; 7],
    latency: [AtomicU64; 13],
    latency_sum_us: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// Requests refused by the rate limits.
    pub throttled: AtomicU64,
    pub lifecycle: std::sync::Arc<crate::lifecycle::Stats>,
    pub events: std::sync::Arc<crate::events::Stats>,
    pub replication: std::sync::Arc<crate::replication::Stats>,
}

impl Metrics {
    pub fn new(events: std::sync::Arc<crate::events::Stats>, replication: std::sync::Arc<crate::replication::Stats>) -> Self {
        Metrics { events, replication, ..Default::default() }
    }
}

pub struct Inflight<'a>(&'a Metrics);

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Relaxed);
    }
}

fn method_idx(m: &Method) -> usize {
    METHODS.iter().position(|x| *x == m.as_str()).unwrap_or(METHODS.len() - 1)
}

impl Metrics {
    /// Count a request as in flight until the returned guard drops (which also happens when a
    /// client disconnects and the request future is cancelled).
    pub fn start(&self) -> Inflight<'_> {
        self.started.get_or_init(Instant::now);
        self.inflight.fetch_add(1, Relaxed);
        Inflight(self)
    }

    pub fn finish(&self, m: &Method, status: u16, elapsed: Duration) {
        let class = (status / 100).clamp(1, 5) as usize - 1;
        self.requests[method_idx(m)][class].fetch_add(1, Relaxed);
        let secs = elapsed.as_secs_f64();
        let b = BOUNDS.iter().position(|ub| secs <= *ub).unwrap_or(BOUNDS.len());
        self.latency[b].fetch_add(1, Relaxed);
        self.latency_sum_us.fetch_add(elapsed.as_micros() as u64, Relaxed);
    }

    pub fn add_bytes_in(&self, n: u64) {
        self.bytes_in.fetch_add(n, Relaxed);
    }

    pub fn add_bytes_out(&self, n: u64) {
        self.bytes_out.fetch_add(n, Relaxed);
    }

    /// `per_bucket` adds series labelled with bucket names and sizes; they are only served when
    /// the endpoint is protected by a token, since anonymous callers cannot list buckets.
    pub fn render(&self, store: &Store, per_bucket: bool) -> String {
        let mut o = String::with_capacity(4096);
        let uptime = self.started.get().map_or(0.0, |s| s.elapsed().as_secs_f64());
        let _ = writeln!(o, "# TYPE s3rs_uptime_seconds gauge\ns3rs_uptime_seconds {uptime:.3}");
        let _ = writeln!(o, "# TYPE s3rs_requests_in_flight gauge\ns3rs_requests_in_flight {}", self.inflight.load(Relaxed));
        let _ = writeln!(o, "# TYPE s3rs_connections gauge\ns3rs_connections {}", self.connections.load(Relaxed));
        let _ = writeln!(o, "# TYPE s3rs_connections_max gauge\ns3rs_connections_max {}", self.max_connections.load(Relaxed));
        let _ = writeln!(o, "# TYPE s3rs_requests_total counter");
        for (mi, m) in METHODS.iter().enumerate() {
            for (ci, c) in self.requests[mi].iter().enumerate() {
                let n = c.load(Relaxed);
                if n > 0 {
                    let _ = writeln!(o, "s3rs_requests_total{{method=\"{m}\",code=\"{}xx\"}} {n}", ci + 1);
                }
            }
        }
        let _ = writeln!(o, "# TYPE s3rs_request_duration_seconds histogram");
        let mut cum = 0;
        for (i, ub) in BOUNDS.iter().enumerate() {
            cum += self.latency[i].load(Relaxed);
            let _ = writeln!(o, "s3rs_request_duration_seconds_bucket{{le=\"{ub}\"}} {cum}");
        }
        cum += self.latency[BOUNDS.len()].load(Relaxed);
        let _ = writeln!(o, "s3rs_request_duration_seconds_bucket{{le=\"+Inf\"}} {cum}");
        let _ = writeln!(o, "s3rs_request_duration_seconds_sum {:.6}", self.latency_sum_us.load(Relaxed) as f64 / 1e6);
        let _ = writeln!(o, "s3rs_request_duration_seconds_count {cum}");
        let _ =
            writeln!(o, "# TYPE s3rs_received_bytes_total counter\ns3rs_received_bytes_total {}", self.bytes_in.load(Relaxed));
        let _ = writeln!(o, "# TYPE s3rs_sent_bytes_total counter\ns3rs_sent_bytes_total {}", self.bytes_out.load(Relaxed));
        let _ = writeln!(
            o,
            "# TYPE s3rs_lifecycle_expired_objects_total counter\ns3rs_lifecycle_expired_objects_total {}",
            self.lifecycle.expired.load(Relaxed)
        );
        let _ = writeln!(
            o,
            "# TYPE s3rs_lifecycle_aborted_uploads_total counter\ns3rs_lifecycle_aborted_uploads_total {}",
            self.lifecycle.aborted_uploads.load(Relaxed)
        );
        for (name, v) in
            [("delivered", &self.events.delivered), ("failed", &self.events.failed), ("dropped", &self.events.dropped)]
        {
            let _ = writeln!(o, "s3rs_notifications_total{{result=\"{name}\"}} {}", v.load(Relaxed));
        }
        let _ = writeln!(
            o,
            "# TYPE s3rs_throttled_requests_total counter\ns3rs_throttled_requests_total {}",
            self.throttled.load(Relaxed)
        );
        let r = &self.replication;
        let _ = writeln!(o, "# TYPE s3rs_replication_total counter");
        for (name, v) in
            [("replicated", &r.replicated), ("unchanged", &r.unchanged), ("skipped", &r.skipped), ("failed", &r.failed)]
        {
            let _ = writeln!(o, "s3rs_replication_total{{result=\"{name}\"}} {}", v.load(Relaxed));
        }
        let _ =
            writeln!(o, "# TYPE s3rs_replication_bytes_total counter\ns3rs_replication_bytes_total {}", r.bytes.load(Relaxed));
        if let Ok(n) = store.repl_pending() {
            let _ = writeln!(o, "# TYPE s3rs_replication_pending gauge\ns3rs_replication_pending {n}");
        }
        let oldest = r.oldest_ms.load(Relaxed);
        let lag = if oldest == 0 { 0.0 } else { crate::util::now_ms().saturating_sub(oldest) as f64 / 1000.0 };
        let _ = writeln!(o, "# TYPE s3rs_replication_lag_seconds gauge\ns3rs_replication_lag_seconds {lag:.3}");
        if per_bucket && let Ok(usage) = store.all_usage() {
            let _ = writeln!(o, "# TYPE s3rs_bucket_objects gauge");
            for (b, n, _) in &usage {
                let _ = writeln!(o, "s3rs_bucket_objects{{bucket=\"{b}\"}} {n}");
            }
            let _ = writeln!(o, "# TYPE s3rs_bucket_bytes gauge");
            for (b, _, bytes) in &usage {
                let _ = writeln!(o, "s3rs_bucket_bytes{{bucket=\"{b}\"}} {bytes}");
            }
        }
        let _ = writeln!(
            o,
            "# TYPE s3rs_build_info gauge\ns3rs_build_info{{version=\"{}\",tls=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION"),
            cfg!(feature = "tls")
        );
        let free = store.space.free();
        if free != u64::MAX {
            let _ = writeln!(o, "# TYPE s3rs_disk_free_bytes gauge\ns3rs_disk_free_bytes {free}");
        }
        let _ = writeln!(o, "# TYPE s3rs_disk_reserve_bytes gauge\ns3rs_disk_reserve_bytes {}", store.space.reserve());
        if let Ok(b) = store.list_buckets() {
            let _ = writeln!(o, "# TYPE s3rs_buckets gauge\ns3rs_buckets {}", b.len());
        }
        o
    }
}
