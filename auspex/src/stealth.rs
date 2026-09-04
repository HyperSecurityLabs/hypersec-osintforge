/// Auspex — Stealth & OPSEC Utilities
///
/// Provides randomized User-Agent selection and jitter delays
/// to reduce fingerprinting and detection risk during recon.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use rand::Rng;
use std::time::Duration;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
];

/// Returns a random User-Agent string from a predefined list.
pub fn random_ua() -> &'static str {
    let idx = rand::thread_rng().gen_range(0..USER_AGENTS.len());
    USER_AGENTS[idx]
}

/// Sleeps for a random duration between 50ms and max_ms to add request jitter.
pub async fn jitter(max_ms: u64) {
    if max_ms == 0 {
        return;
    }
    let delay = rand::thread_rng().gen_range(50..=max_ms);
    tokio::time::sleep(Duration::from_millis(delay)).await;
}
