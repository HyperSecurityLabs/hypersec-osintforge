/// Shroud — HTTP Probing & Certificate Intelligence
///
/// Probes target servers for HTTP response analysis, WAF/CDN
/// fingerprinting, and certificate transparency log harvesting.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use std::time::Duration;
use reqwest::header::HeaderMap;
use crate::stealth::random_ua;

/// Result of an HTTP probe against a target.
pub struct HttpProbe {
    pub status: u16,
    pub server: Option<String>,
    pub waf: Option<String>,
    pub latency_ms: f64,
    pub cert_issuer: Option<String>,
}

/// Detects CDN and WAF infrastructure from HTTP response headers.
pub fn detect_infra(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let mut cdn: Option<String> = None;
    let mut waf: Option<String> = None;

    // Cloudflare detection
    if headers.get("cf-ray").is_some() {
        cdn = Some("Cloudflare".to_string());
        if headers.get("cf-challenge").is_some() || headers.get("cf-waf-error").is_some() {
            waf = Some("Cloudflare WAF".to_string());
        }
    }
    if let Some(server) = headers.get("server") {
        let val = server.to_str().unwrap_or("").to_lowercase();
        if val.contains("cloudflare") && cdn.is_none() {
            cdn = Some("Cloudflare".to_string());
        }
        if val.contains("cloudfront") {
            cdn = Some("AWS CloudFront".to_string());
        }
        if val.contains("akamai") {
            cdn = Some("Akamai".to_string());
        }
    }
    if let Some(x_powered) = headers.get("x-powered-by") {
        let val = x_powered.to_str().unwrap_or("");
        if val.contains("Vercel") || val.contains("Next.js") {
            cdn = Some("Vercel (Edge Network)".to_string());
        }
    }
    if headers.get("x-sucuri-id").is_some() || headers.get("x-sucuri-cache").is_some() {
        waf = Some("Sucuri WAF".to_string());
    }
    if headers.get("x-akamai-transformed").is_some() {
        cdn = Some("Akamai".to_string());
    }
    if headers.get("x-amz-cf-id").is_some() || headers.get("x-amz-cf-pop").is_some() {
        cdn = Some("AWS CloudFront".to_string());
    }

    (cdn, waf)
}

/// Sends an HTTP GET probe to the target URL and returns response analysis.
pub async fn probe_target(target: &str, proxy: Option<&str>) -> Option<HttpProbe> {
    let ua = random_ua();
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(ua)
        .danger_accept_invalid_certs(false);

    if let Some(proxy_url) = proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }

    let client = builder.build().ok()?;
    let start = std::time::Instant::now();
    let response = client.get(target).send().await.ok()?;
    let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
    let status = response.status().as_u16();
    let server = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let waf = detect_infra(response.headers()).1;
    let cert_issuer = None;

    Some(HttpProbe { status, server, waf, latency_ms, cert_issuer })
}

/// Fetches subdomain data from crt.sh certificate transparency logs.
pub async fn fetch_crt_sh(domain: &str, jitter_ms: u64) -> Vec<String> {
    crate::stealth::jitter(jitter_ms).await;
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(random_ua())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let data: Vec<serde_json::Value> = response.json().await.unwrap_or_default();

    let mut subdomains: Vec<String> = data
        .iter()
        .filter_map(|entry| {
            entry.get("name_value")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    subdomains.sort();
    subdomains.dedup();
    subdomains
}
