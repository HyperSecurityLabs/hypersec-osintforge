/// Stealth utilities — random User-Agent selection and request jitter.
use rand::Rng;
use std::time::Duration;

/// Pool of realistic browser User-Agent strings for evading basic
/// bot-detection heuristics.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
];

/// Return a random User-Agent string from the built-in pool.
pub fn random_ua() -> &'static str {
    // Step: Pick a random index within the agent list
    let idx = rand::thread_rng().gen_range(0..USER_AGENTS.len());
    USER_AGENTS[idx]
}

/// Sleep for a random duration up to `max_ms` milliseconds.
///
/// If `max_ms` is zero the function returns immediately.
pub async fn jitter(max_ms: u64) {
    // Check: No-op when jitter is disabled
    if max_ms == 0 {
        return;
    }
    // Step: Random delay between 50 and max_ms
    let delay = rand::thread_rng().gen_range(50..=max_ms);
    tokio::time::sleep(Duration::from_millis(delay)).await;
}
