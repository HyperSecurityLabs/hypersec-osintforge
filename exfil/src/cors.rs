/// CORS misconfiguration scanner.
/// Tests a target URL against a battery of malicious origins to detect
/// permissive CORS policies, wildcard + credential combos,
/// origin reflection, and echo-server false positives.
use crate::models::CorsResult;
use crate::stealth;
use reqwest::header::HeaderMap;
use std::collections::HashSet;

/// Origins used to probe the target's CORS policy.
/// Covers basic attack domains, reflection variants, null/wildcard,
/// protocol manipulation, subdomain takeover, and cloud endpoints.
const TEST_ORIGINS: &[&str] = &[
    "https://evil.com",
    "https://attacker.com",
    "https://malicious.io",
    "null",
    "https://www.example.com.evil.com",
    "https://evil.com/www.example.com",
    "https://evil.com/../example.com",
    "https://sub.example.com.attacker-controlled.com",
    "https://nonexistent.example.com",
    "http://evil.com",
    "http://example.com",
    "https://example.com.evil.com",
    "https://example.com%40evil.com",
    "https://example.com@evil.com",
    "https://bucket.s3.amazonaws.com",
    "https://bucket.s3.amazonaws.com.evil.com",
    "http://127.0.0.1:8080",
    "http://localhost:3000",
    "http://169.254.169.254",
    "https://cdn.example.com",
    "https://cdn.example.com.attacker.io",
    "null",
    "null.evil.com",
    "*",
];

/// Scan a single base URL for CORS misconfigurations across all test origins.
/// Returns only origins that produced an allowed or wildcard response.
pub async fn check_cors(base_url: &str, proxy: Option<&str>) -> Vec<CorsResult> {
    // Step: build HTTP client with optional proxy
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(stealth::random_ua());

    // Check: proxy configured?
    if let Some(proxy_url) = proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }
    let client = match builder.build() {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();
    let mut seen_origins = HashSet::new();

    // Loop: probe each origin
    for origin in TEST_ORIGINS {
        if !seen_origins.insert(origin.to_string()) {
            continue;
        }
        let result = scan_origin(&client, base_url, origin).await;
        // Check: origin allowed?
        if result.allowed || result.wildcard {
            results.push(result);
        }
    }

    // Step: filter out echo-server false positives
    let mut filtered = Vec::new();
    for r in results {
        if !is_echo_server(&client, base_url, &r.origin).await {
            filtered.push(r);
        }
    }

    filtered
}

/// Detect echo-server behaviour by sending a random, unique origin.
/// If the server reflects it back verbatim, it is an echo-server and
/// the CORS result is a false positive.
async fn is_echo_server(client: &reqwest::Client, url: &str, _matched_origin: &str) -> bool {
    let random_origin = format!("https://nonexistent-echo-test-{}.local", rand::random::<u64>());
    let resp = match client.get(url).header("Origin", &random_origin).send().await {
        Ok(r) => r,
        Err(_) => return false,
    };
    let acao = match resp.headers().get("access-control-allow-origin") {
        Some(v) => v.to_str().unwrap_or(""),
        None => return false,
    };
    acao == random_origin
}

/// Send a request with a test `Origin` header and classify the response.
async fn scan_origin(client: &reqwest::Client, url: &str, origin: &str) -> CorsResult {
    let mut result = CorsResult {
        endpoint: url.to_string(),
        origin: origin.to_string(),
        allowed: false,
        credentials: false,
        wildcard: false,
        level: "INFO".to_string(),
    };

    let resp = match client.get(url).header("Origin", origin).send().await {
        Ok(r) => r,
        Err(_) => return result,
    };

    let headers = resp.headers();
    // Step: check response headers
    result.allowed = is_origin_allowed(headers, origin);
    result.wildcard = has_wildcard_origin(headers);
    result.credentials = has_credentials_allowed(headers);

    // Step: classify severity
    result.level = classify_level(&result);

    result
}

/// Check if the `Access-Control-Allow-Origin` header matches the given origin or is wildcard.
fn is_origin_allowed(headers: &HeaderMap, origin: &str) -> bool {
    let acao = match headers.get("access-control-allow-origin") {
        Some(v) => v.to_str().unwrap_or(""),
        None => return false,
    };
    acao == "*" || acao == origin
}

/// Check if the server sets `Access-Control-Allow-Origin: *`.
fn has_wildcard_origin(headers: &HeaderMap) -> bool {
    match headers.get("access-control-allow-origin") {
        Some(v) => v.to_str().unwrap_or("") == "*",
        None => false,
    }
}

/// Check if `Access-Control-Allow-Credentials` is set to `true`.
fn has_credentials_allowed(headers: &HeaderMap) -> bool {
    match headers.get("access-control-allow-credentials") {
        Some(v) => v.to_str().unwrap_or("").eq_ignore_ascii_case("true"),
        None => false,
    }
}

/// Determine severity level based on wildcard and credential flags.
fn classify_level(result: &CorsResult) -> String {
    if result.wildcard && result.credentials {
        "CRITICAL".to_string()
    } else if result.wildcard {
        "HIGH".to_string()
    } else if result.credentials {
        "HIGH".to_string()
    } else if result.allowed {
        "MEDIUM".to_string()
    } else {
        "INFO".to_string()
    }
}
