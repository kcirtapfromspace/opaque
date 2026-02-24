//! Operation rate limiting with sliding window counters.
//!
//! Provides per-client, per-operation, and global rate limiting for operation
//! requests. Rate limits are checked BEFORE policy evaluation in the enclave
//! pipeline (fail fast).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Rate limit rule configuration
// ---------------------------------------------------------------------------

/// A single rate limit rule. Rules are matched against operation names using
/// glob patterns.
///
/// Example TOML:
/// ```toml
/// [[rate_limits]]
/// pattern = "*"
/// max_requests = 60
/// window_secs = 60
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Glob pattern to match against operation names.
    /// `"*"` matches all operations (global limit).
    pub pattern: String,

    /// Maximum number of requests allowed within the sliding window.
    pub max_requests: u32,

    /// Duration of the sliding window in seconds.
    pub window_secs: u64,
}

// ---------------------------------------------------------------------------
// Rate limit error
// ---------------------------------------------------------------------------

/// Returned when a request exceeds a rate limit.
#[derive(Debug, thiserror::Error)]
#[error("rate limited: try again in {retry_after_secs}s")]
pub struct RateLimitError {
    /// Suggested time (in seconds) until the client can retry.
    pub retry_after_secs: u64,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Key for the sliding window counter: (client identity hash, rule index).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    client_id: String,
    rule_index: usize,
}

/// Sliding window of request timestamps for a single bucket.
#[derive(Debug)]
struct WindowBucket {
    timestamps: Vec<Instant>,
}

impl WindowBucket {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    /// Remove timestamps outside the window and return the count of remaining
    /// (in-window) entries.
    fn prune_and_count(&mut self, window: Duration, now: Instant) -> usize {
        self.timestamps
            .retain(|t| now.duration_since(*t) < window);
        self.timestamps.len()
    }

    /// Record a new request timestamp.
    fn record(&mut self, now: Instant) {
        self.timestamps.push(now);
    }
}

// ---------------------------------------------------------------------------
// RateLimiter
// ---------------------------------------------------------------------------

/// Thread-safe sliding window rate limiter.
///
/// Tracks request counts per (client, rule) pair. Each rule defines a glob
/// pattern, a max request count, and a window duration.
pub struct RateLimiter {
    rules: Vec<RateLimitRule>,
    buckets: Mutex<HashMap<BucketKey, WindowBucket>>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl RateLimiter {
    /// Create a new rate limiter with the given rules.
    pub fn new(rules: Vec<RateLimitRule>) -> Self {
        Self {
            rules,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Create a rate limiter with no rules (everything passes).
    pub fn disabled() -> Self {
        Self::new(Vec::new())
    }

    /// Check whether the request from `client_id` for `operation` is within
    /// rate limits. Returns `Ok(())` if allowed, or a `RateLimitError` with
    /// a suggested retry-after duration.
    ///
    /// If no rules match the operation, the request is allowed (default no
    /// limit).
    pub fn check(&self, client_id: &str, operation: &str) -> Result<(), RateLimitError> {
        if self.rules.is_empty() {
            return Ok(());
        }

        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            if !glob_match::glob_match(&rule.pattern, operation) {
                continue;
            }

            let window = Duration::from_secs(rule.window_secs);
            let key = BucketKey {
                client_id: client_id.to_owned(),
                rule_index: rule_idx,
            };

            let bucket = buckets.entry(key).or_insert_with(WindowBucket::new);
            let count = bucket.prune_and_count(window, now);

            if count >= rule.max_requests as usize {
                // Compute retry_after: time until the oldest in-window entry
                // will expire.
                let retry_after = bucket
                    .timestamps
                    .first()
                    .map(|oldest| {
                        let elapsed = now.duration_since(*oldest);
                        if elapsed < window {
                            (window - elapsed).as_secs().max(1)
                        } else {
                            1
                        }
                    })
                    .unwrap_or(1);

                return Err(RateLimitError {
                    retry_after_secs: retry_after,
                });
            }

            bucket.record(now);
        }

        Ok(())
    }

    /// Remove expired entries from all buckets. Call periodically to prevent
    /// unbounded memory growth.
    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        // Collect keys to remove after pruning.
        let mut empty_keys = Vec::new();

        for (key, bucket) in buckets.iter_mut() {
            let rule = match self.rules.get(key.rule_index) {
                Some(r) => r,
                None => continue,
            };
            let window = Duration::from_secs(rule.window_secs);
            bucket.prune_and_count(window, now);
            if bucket.timestamps.is_empty() {
                empty_keys.push(key.clone());
            }
        }

        for key in empty_keys {
            buckets.remove(&key);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_allows_under_limit() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 10,
            window_secs: 60,
        }]);

        // 5 requests should all pass.
        for _ in 0..5 {
            limiter.check("client-a", "github.set_secret").unwrap();
        }
    }

    #[test]
    fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 10,
            window_secs: 60,
        }]);

        // 10 requests should pass.
        for i in 0..10 {
            limiter
                .check("client-a", "github.set_secret")
                .unwrap_or_else(|_| panic!("request {i} should pass"));
        }

        // 11th should be blocked.
        let err = limiter
            .check("client-a", "github.set_secret")
            .unwrap_err();
        assert!(err.retry_after_secs >= 1);
    }

    #[test]
    fn test_window_slides() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 2,
            window_secs: 1,
        }]);

        // Fill the window.
        limiter.check("client-a", "op").unwrap();
        limiter.check("client-a", "op").unwrap();
        assert!(limiter.check("client-a", "op").is_err());

        // Wait for the window to slide.
        sleep(Duration::from_millis(1100));

        // Should pass again.
        limiter.check("client-a", "op").unwrap();
    }

    #[test]
    fn test_per_client_isolation() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 2,
            window_secs: 60,
        }]);

        // Client A exhausts its limit.
        limiter.check("client-a", "op").unwrap();
        limiter.check("client-a", "op").unwrap();
        assert!(limiter.check("client-a", "op").is_err());

        // Client B should still be allowed.
        limiter.check("client-b", "op").unwrap();
        limiter.check("client-b", "op").unwrap();
    }

    #[test]
    fn test_per_operation_isolation() {
        let limiter = RateLimiter::new(vec![
            RateLimitRule {
                pattern: "github.*".into(),
                max_requests: 2,
                window_secs: 60,
            },
            RateLimitRule {
                pattern: "vault.*".into(),
                max_requests: 5,
                window_secs: 60,
            },
        ]);

        // Exhaust the github.* limit.
        limiter.check("client-a", "github.set_secret").unwrap();
        limiter.check("client-a", "github.set_secret").unwrap();
        assert!(limiter.check("client-a", "github.set_secret").is_err());

        // vault.* should still be allowed.
        limiter.check("client-a", "vault.read").unwrap();
        limiter.check("client-a", "vault.read").unwrap();
        limiter.check("client-a", "vault.read").unwrap();
    }

    #[test]
    fn test_global_limit() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 3,
            window_secs: 60,
        }]);

        // Any operation should count toward the same global limit.
        limiter.check("client-a", "github.set_secret").unwrap();
        limiter.check("client-a", "vault.read").unwrap();
        limiter.check("client-a", "random.op").unwrap();

        // All three counted; next should be blocked regardless of operation.
        assert!(limiter.check("client-a", "yet.another").is_err());
    }

    #[test]
    fn test_default_no_limit() {
        let limiter = RateLimiter::disabled();

        // No rules means everything passes.
        for _ in 0..100 {
            limiter.check("client-a", "any.operation").unwrap();
        }
    }

    #[test]
    fn test_cleanup_expired() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 100,
            window_secs: 1,
        }]);

        limiter.check("client-a", "op").unwrap();
        limiter.check("client-b", "op").unwrap();

        // Wait for window to expire.
        sleep(Duration::from_millis(1100));

        limiter.cleanup_expired();

        let buckets = limiter.buckets.lock().unwrap();
        assert!(
            buckets.is_empty(),
            "expired buckets should be removed after cleanup"
        );
    }

    #[test]
    fn test_retry_after_is_positive() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "*".into(),
            max_requests: 1,
            window_secs: 30,
        }]);

        limiter.check("client-a", "op").unwrap();
        let err = limiter.check("client-a", "op").unwrap_err();
        assert!(
            err.retry_after_secs > 0 && err.retry_after_secs <= 30,
            "retry_after_secs should be between 1 and 30, got {}",
            err.retry_after_secs
        );
    }

    #[test]
    fn test_non_matching_pattern_allows() {
        let limiter = RateLimiter::new(vec![RateLimitRule {
            pattern: "github.*".into(),
            max_requests: 1,
            window_secs: 60,
        }]);

        // vault.read does not match "github.*", so no limit applies.
        for _ in 0..50 {
            limiter.check("client-a", "vault.read").unwrap();
        }
    }
}
