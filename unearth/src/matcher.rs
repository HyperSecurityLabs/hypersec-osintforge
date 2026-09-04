/// Toolkit 4: Matcher — fingerprint comparison to identify origin servers.
use std::sync::Arc;
use std::time::Duration;
use sha2::{Sha256, Digest};
use tokio::sync::Semaphore;
use crate::models::OriginCandidate;
use crate::stealth::random_ua;

/// Matcher toolkit that probes candidate IPs and compares body hashes
/// and server headers against the target's reference fingerprint.
pub struct MatcherToolkit {
    pub domain: String,
    pub candidates: Vec<OriginCandidate>,
}

impl MatcherToolkit {
    /// Create a new `MatcherToolkit` with candidates from prior toolkits.
    pub fn new(domain: &str, candidates: Vec<OriginCandidate>, _concurrency: usize) -> Self {
        Self {
            domain: domain.to_string(),
            candidates,
        }
    }

    /// Probe all candidates concurrently, scoring each by origin likelihood.
    pub async fn probe_all(candidates: &[OriginCandidate], domain: &str) -> Vec<OriginCandidate> {
        let mut results = Vec::new();
        let semaphore = Arc::new(Semaphore::new(10));

        // Loop: Spawn a probe task for each candidate
        for candidate in candidates {
            let permit = semaphore.clone().acquire_owned().await;
            let domain = domain.to_string();
            let ip = candidate.ip;
            let port = candidate.port;

            let handle = tokio::spawn(async move {
                drop(permit);
                // Step: Determine URL scheme from port
                let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
                let url = format!("{}://{}:{}/", scheme, ip, port);

                // Step: Build client and send GET with Host header
                let client = match reqwest::Client::builder()
                    .timeout(Duration::from_secs(8))
                    .user_agent(random_ua())
                    .danger_accept_invalid_certs(true)
                    .redirect(reqwest::redirect::Policy::none())
                    .build()
                {
                    Ok(c) => c,
                    Err(_) => return None,
                };

                let start = std::time::Instant::now();
                let response = match client
                    .get(&url)
                    .header("Host", &domain)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(_) => return None,
                };

                // Step: Record response metadata
                let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;
                let status_code = response.status().as_u16();
                let server = response
                    .headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                // Step: Hash the response body
                let body = match response.bytes().await {
                    Ok(b) => b,
                    Err(_) => return None,
                };

                let mut hasher = Sha256::new();
                hasher.update(&body);
                let hash = hex::encode(hasher.finalize());

                Some(OriginCandidate {
                    ip,
                    port,
                    confidence: 30,
                    source: "Matcher".to_string(),
                    hostname: Some(domain),
                    server_header: server,
                    status_code: Some(status_code),
                    body_hash: Some(hash),
                    response_time_ms: Some(response_time_ms),
                })
            });

            if let Ok(Some(result)) = handle.await {
                results.push(result);
            }
        }

        results
    }

    /// Score and filter candidates by comparing against reference fingerprint.
    pub fn match_candidates(
        candidates: Vec<OriginCandidate>,
        ref_hash: &Option<String>,
        ref_server: &Option<String>,
        _target_domain: &str,
    ) -> Vec<OriginCandidate> {
        let mut matched = Vec::new();

        // Loop: Score each candidate against the reference
        for mut candidate in candidates {
            let mut score = 0u8;

            // Check: Body hash matches reference
            if let Some(ref ref_hash) = ref_hash {
                if let Some(ref body_hash) = candidate.body_hash {
                    if body_hash == ref_hash {
                        score += 50;
                    }
                }
            }

            // Check: Server header matches reference
            if let Some(ref ref_server) = ref_server {
                if let Some(ref server) = candidate.server_header {
                    let s_lower = server.to_lowercase();
                    let ref_lower = ref_server.to_lowercase();
                    if s_lower == ref_lower {
                        score += 20;
                    } else if s_lower.contains(&ref_lower) || ref_lower.contains(&s_lower) {
                        score += 10;
                    }
                }
            }

            // Check: Successful or redirect status codes
            if candidate.status_code == Some(200) || candidate.status_code == Some(301) || candidate.status_code == Some(302) {
                score += 10;
            }

            // Check: Presence of a Server header
            if candidate.server_header.is_some() {
                score += 5;
            }

            candidate.confidence = score.min(100);
            // Check: Confidence threshold of 15
            if score >= 15 {
                matched.push(candidate);
            }
        }

        matched.sort_by_key(|b| std::cmp::Reverse(b.confidence));
        matched
    }

    /// Run the full matcher toolkit: probe candidates then score them.
    pub async fn run(&self, ref_hash: &Option<String>, ref_server: &Option<String>) -> Vec<OriginCandidate> {
        let probed = Self::probe_all(&self.candidates, &self.domain).await;
        Self::match_candidates(probed, ref_hash, ref_server, &self.domain)
    }
}
