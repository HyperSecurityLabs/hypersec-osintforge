/// Subdomain takeover detection via CNAME fingerprinting and body-signature matching.
use crate::models::TakeoverInfo;
use rand::Rng;
use reqwest::header::HeaderMap;
use std::process::Command;

/// Known-takeover signatures: (service_name, body_snippets, cname_patterns).
///
/// Each entry pairs one or more body-signature substrings that, when
/// found in an HTTP response, indicate an unclaimed cloud service,
/// together with the CNAME patterns that lead to that service.
const TAKEOVER_SIGS: &[(&str, &[&str], &[&str])] = &[
    ("aws_s3", &[
        "<Code>NoSuchBucket</Code>",
    ], &["s3.amazonaws.com", "s3-website"]),
    ("github_pages", &[
        "There isn't a GitHub Pages site here.",
    ], &["github.io"]),
    ("heroku", &[
        "heroku logo",
        "no such app",
    ], &["herokuapp.com", "herokudns.com"]),
    ("shopify", &[
        "Sorry, this shop is currently unavailable.",
    ], &["myshopify.com", "shopify.com"]),
    ("azure_cloudapp", &[
        "Could not get any response",
    ], &["cloudapp.net", "azurewebsites.net"]),
    ("squarespace", &[
        "No Such Site",
        "page not found",
    ], &["squarespace.com"]),
    ("bitbucket", &[
        "This page is either unavailable",
    ], &["bitbucket.io"]),
    ("wordpress", &[
        "Do you want to register",
        "wordpress.com/domains",
    ], &["wordpress.com"]),
    ("unbounce", &[
        "The page you requested was not found",
    ], &["unbouncepages.com"]),
    ("strikingly", &[
        "page not found",
    ], &["strikingly.com", "strikinglydns.com"]),
];

/// Check HTTP response headers for known provider server strings.
fn matches_headers(headers: &HeaderMap, service: &str) -> bool {
    match service {
        "aws_s3" => headers.get("server").and_then(|v| v.to_str().ok())
            .map(|s| s.contains("AmazonS3")).unwrap_or(false),
        "github_pages" => headers.get("server").and_then(|v| v.to_str().ok())
            .map(|s| s.contains("GitHub.com")).unwrap_or(false),
        "heroku" => headers.contains_key("x-powered-by")
            && headers.get("server").and_then(|v| v.to_str().ok())
                .map(|s| s.contains("Cowboy")).unwrap_or(false),
        _ => false,
    }
}

/// Check whether a CNAME hostname is unclaimed via DNS resolution.
async fn is_unclaimed(cname: &str) -> bool {
    // Step: Attempt to resolve the CNAME — no addresses means unclaimed
    tokio::net::lookup_host((cname, 0)).await
        .map(|addrs| addrs.count() == 0)
        .unwrap_or(true)
}

/// Generate a random probe path for testing subdomain responses.
fn generate_probe_path() -> String {
    let mut rng = rand::thread_rng();
    // Step: Build random alphanumeric path segment
    let path: String = (0..12).map(|_| {
        char::from_digit(rng.gen_range(0..36), 36).unwrap()
    }).collect();
    format!("/nonexistent-{}", &path[..8])
}

/// Probe a subdomain with a random path over HTTPS and HTTP.
async fn probe_service(subdomain: &str, probe_path: &str) -> Option<(u16, HeaderMap, String)> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) sniff/0.1.0")
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;

    // Loop: Try HTTPS first, then HTTP
    for scheme in &["https", "http"] {
        let url = format!("{}://{}{}", scheme, subdomain, probe_path);
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            // Check: Only analyse meaningful status codes
            if [200, 404, 403].contains(&status) {
                let body = resp.text().await.unwrap_or_default();
                return Some((status, headers, body));
            }
        }
    }

    None
}

/// Check a single subdomain for a takeover vulnerability.
///
/// Resolves the CNAME, probes the subdomain with a random path,
/// matches body signatures, header fingerprints, and CNAME patterns
/// against all known services, and returns `Some(TakeoverInfo)` when
/// confidence exceeds the threshold of 5.
pub async fn check(subdomain: &str) -> Option<TakeoverInfo> {
    // Step: Resolve CNAME record for the subdomain
    let cname = resolve_cname(subdomain).await?;
    // Check: Empty CNAME means no takeover possible
    if cname.is_empty() {
        return None;
    }

    let cname_lower = cname.to_lowercase();
    let probe_path = generate_probe_path();

    // Loop: Check against every known takeover signature
    for &(service, body_sigs, cname_patterns) in TAKEOVER_SIGS {
        // Check: CNAME matches this service's pattern
        let cname_match = cname_patterns.iter().any(|pat| cname_lower.contains(pat));
        if !cname_match {
            continue;
        }

        // Handle: Probe the subdomain for body and headers
        if let Some((_status, headers, body)) = probe_service(subdomain, &probe_path).await {
            let body_lower = body.to_lowercase();
            let mut confidence = 0i32;

            // Check: CNAME pattern match contributes 1
            if cname_match {
                confidence += 1;
            }

            // Check: Body signature match contributes 3
            if body_sigs.iter().any(|sig| body_lower.contains(&sig.to_lowercase())) {
                confidence += 3;
            }

            // Check: Header fingerprint match contributes 2
            if matches_headers(&headers, service) {
                confidence += 2;
            }

            // Check: Unclaimed CNAME contributes 2
            if is_unclaimed(&cname).await {
                confidence += 2;
            }

            // Check: Confidence threshold met
            if confidence >= 5 {
                return Some(TakeoverInfo {
                    service: service.to_string(),
                    cname: cname.clone(),
                    vulnerable: true,
                });
            }
        }
    }

    None
}

/// Resolve the CNAME record for a subdomain via `dig`.
async fn resolve_cname(subdomain: &str) -> Option<String> {
    // Step: Spawn blocking task to run `dig cname +short`
    let output = tokio::task::spawn_blocking({
        let s = subdomain.to_string();
        move || {
            Command::new("dig")
                .arg("cname")
                .arg(&s)
                .arg("+short")
                .output()
                .ok()
        }
    })
    .await
    .ok()
    .flatten()?;

    // Step: Parse and normalise the CNAME output
    let cname = String::from_utf8_lossy(&output.stdout).trim().to_lowercase();
    // Check: Return None on empty CNAME
    if cname.is_empty() { None } else { Some(cname) }
}
