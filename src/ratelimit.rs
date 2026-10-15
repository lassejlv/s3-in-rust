//! Request rate limits per access key (and per client address for unsigned requests): token
//! buckets that refill at `rate` requests per second and hold up to two seconds' worth, so short
//! bursts pass. A request over the limit gets S3's retryable `503 SlowDown`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SHARDS: usize = 16;
/// Entries per shard before idle ones are dropped.
const MAX_ENTRIES: usize = 4096;

pub struct Limiter {
    rate: f64,
    burst: f64,
    shards: Vec<Mutex<HashMap<String, (f64, Instant)>>>,
}

impl Limiter {
    pub fn new(rate: u32) -> Self {
        let rate = rate.max(1) as f64;
        Limiter { rate, burst: rate * 2.0, shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect() }
    }

    /// Take a token for `key`, or say how long until one is available.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
        let shard = key.bytes().fold(0usize, |h, b| h.wrapping_mul(31).wrapping_add(b as usize)) % SHARDS;
        let mut map = self.shards[shard].lock().unwrap();
        if map.len() >= MAX_ENTRIES && !map.contains_key(key) {
            // Forget clients whose bucket has refilled: they are back to a full burst anyway.
            let full = Duration::from_secs_f64(self.burst / self.rate);
            map.retain(|_, (_, last)| now.saturating_duration_since(*last) < full);
        }
        let (tokens, last) = map.entry(key.to_string()).or_insert((self.burst, now));
        *tokens = (*tokens + now.saturating_duration_since(*last).as_secs_f64() * self.rate).min(self.burst);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - *tokens) / self.rate))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_each_key_separately() {
        let l = Limiter::new(10);
        let t0 = Instant::now();
        // A burst of two seconds' worth passes, then requests are refused...
        for _ in 0..20 {
            l.check_at("a", t0).unwrap();
        }
        let wait = l.check_at("a", t0).unwrap_err();
        assert!(wait > Duration::ZERO && wait <= Duration::from_millis(100), "{wait:?}");
        // ...while other keys are unaffected...
        l.check_at("b", t0).unwrap();
        // ...and tokens come back at the configured rate.
        let t1 = t0 + Duration::from_millis(500);
        for _ in 0..5 {
            l.check_at("a", t1).unwrap();
        }
        assert!(l.check_at("a", t1).is_err());
    }

    #[test]
    fn forgets_idle_clients() {
        let l = Limiter::new(1);
        let t0 = Instant::now();
        for i in 0..MAX_ENTRIES * SHARDS * 2 {
            let _ = l.check_at(&format!("ip{i}"), t0 + Duration::from_secs(i as u64));
        }
        let total: usize = l.shards.iter().map(|s| s.lock().unwrap().len()).sum();
        assert!(total <= MAX_ENTRIES * SHARDS, "{total}");
    }
}
