/// Security headers audit for HTTP responses.
///
/// Checks for the presence and quality of well-known security headers
/// such as HSTS, CSP, X-Frame-Options, and CORS headers.
use crate::models::SecurityHeader;
use reqwest::header::HeaderMap;

/// Security header check definitions: (name, missing message, present message, analyzer function).
const CHECKS: &[(&str, &str, &str, fn(&str) -> String)] = &[
    (
        "Strict-Transport-Security",
        "Missing HSTS header — risk of SSL stripping",
        "",
        |_| String::new(),
    ),
    (
        "Content-Security-Policy",
        "No CSP — vulnerable to XSS and data injection",
        "",
        |_| String::new(),
    ),
    (
        "X-Frame-Options",
        "Missing — clickjacking possible",
        "",
        |_| String::new(),
    ),
    (
        "X-Content-Type-Options",
        "Missing — MIME sniffing risk",
        "",
        |_| String::new(),
    ),
    (
        "Referrer-Policy",
        "Missing — referrer leakage possible",
        "",
        |_| String::new(),
    ),
    (
        "Permissions-Policy",
        "Missing — feature permissions unrestricted",
        "",
        |_| String::new(),
    ),
    (
        "X-XSS-Protection",
        "Missing — consider using CSP instead",
        "Deprecated header — use Content-Security-Policy",
        |_| String::new(),
    ),
    (
        "Access-Control-Allow-Origin",
        "Missing CORS header — API/mobile access unrestricted",
        "",
        |v: &str| {
            if v == "*" {
                "wildcard origin — dangerous".to_string()
            } else {
                String::new()
            }
        },
    ),
    (
        "Access-Control-Allow-Credentials",
        "Missing",
        "Credentials allowed with CORS",
        |_| String::new(),
    ),
    (
        "Access-Control-Allow-Methods",
        "Missing",
        "CORS methods exposed",
        |_| String::new(),
    ),
];

/// Audit response headers for security best practices.
///
/// Returns a vector of `SecurityHeader` entries with presence flags and notes.
pub fn audit(headers: &HeaderMap) -> Vec<SecurityHeader> {
    let mut results = Vec::new();

    // Loop: check each defined security header
    for (hdr, missing_msg, present_msg, analyze) in CHECKS {
        let raw = headers.get(*hdr).and_then(|v| v.to_str().ok());
        let val = raw.map(|s| s.to_string());
        // Dispatch: generate note based on presence and value analysis
        let note = match &val {
            Some(v) => {
                let extra = analyze(v);
                if !extra.is_empty() {
                    extra
                } else if !present_msg.is_empty() {
                    present_msg.to_string()
                } else {
                    String::new()
                }
            }
            None => missing_msg.to_string(),
        };
        results.push(SecurityHeader {
            header: hdr.to_string(),
            present: raw.is_some(),
            value: val,
            note,
        });
    }

    results
}
