/// Hidden parameter fuzzer.
/// Sends a battery of common GET/POST parameters to a URL and flags responses
/// that deviate significantly from baseline, indicating potentially interesting
/// or reflected parameters.
use crate::models::FuzzResult;
use crate::stealth;

/// Keywords that indicate a generic error/not-found response body.
const ERROR_KEYWORDS: &[&str] = &[
    "error", "exception", "not found", "invalid", "malformed",
    "warning", "fatal", "syntax error", "unexpected", "cannot",
    "unable to", "missing", "illegal", "bad request",
    "parameter not allowed", "unknown parameter", "undefined",
];

/// Check whether the response body contains error-like keywords.
fn is_error_body(body: &str) -> bool {
    let lower = body.to_lowercase();
    ERROR_KEYWORDS.iter().any(|k| lower.contains(k))
}

/// Check whether the content-type string suggests a renderable page (HTML/JSON).
fn is_error_content_type_str(ct: &str) -> bool {
    ct.contains("text/html") || ct.contains("application/json")
}

/// Common GET parameters likely to be handled by web frameworks.
const GET_PARAMS: &[&str] = &[
    "id", "user_id", "uid", "uuid", "token", "secret",
    "key", "api_key", "apikey", "auth", "session",
    "pass", "password", "pwd", "email", "mail",
    "file", "file_id", "document", "doc", "download",
    "redirect", "url", "next", "return", "callback",
    "debug", "test", "admin", "role", "action",
    "page", "view", "template", "include", "path",
    "sig", "signature", "hash", "checksum",
    "access", "access_token", "refresh_token",
    "code", "state", "scope", "response_type",
    "grant_type", "client_id", "client_secret",
    "username", "login", "account", "acct",
    "msg", "message", "content", "text",
    "type", "format", "mode", "lang", "locale",
    "limit", "offset", "page", "per_page", "count",
    "order", "sort", "filter", "search", "q",
    "callback", "jsonp", "format", "method",
    "debug", "verbose", "dry_run", "preview",
];

/// POST parameter payloads that may trigger logic changes.
const POST_PARAMS: &[(&str, &str)] = &[
    ("id", "1337"),
    ("user_id", "1337"),
    ("token", "test_token_1337"),
    ("email", "test@example.com"),
    ("pass", "password123"),
    ("password", "password123"),
    ("api_key", "test_api_key_1337"),
    ("username", "admin"),
    ("admin", "true"),
    ("role", "admin"),
    ("debug", "1"),
    ("test", "1"),
    ("action", "delete"),
    ("method", "edit"),
    ("file", "/etc/passwd"),
    ("path", "../../etc/passwd"),
    ("url", "http://evil.com"),
    ("callback", "http://evil.com"),
];

/// Fuzz the given URL with GET and POST parameters, returning interesting results.
pub async fn fuzz_params(base_url: &str, proxy: Option<&str>) -> Vec<FuzzResult> {
    // Step: build HTTP client with optional proxy
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(8))
        .user_agent(stealth::random_ua());

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
    let mut seen = std::collections::HashSet::new();

    // Step: collect baseline samples for statistical comparison
    let mut baseline_lens: Vec<usize> = Vec::new();
    for _ in 0..5 {
        if let Ok(r) = client.get(base_url).send().await {
            if let Ok(body) = r.text().await {
                baseline_lens.push(body.len());
            }
        }
    }

    // Check: enough baseline samples?
    if baseline_lens.len() < 3 {
        return results;
    }

    // Step: compute baseline statistics
    let avg_baseline = baseline_lens.iter().sum::<usize>() / baseline_lens.len();
    let variance: usize = baseline_lens.iter()
        .map(|l| l.abs_diff(avg_baseline).pow(2))
        .sum::<usize>() / baseline_lens.len();
    let std_dev = (variance as f64).sqrt() as usize;

    let threshold = (std_dev * 3) + 200;

    // Step: GET parameter fuzzing
    for param in GET_PARAMS {
        let test_value = "exfil_fuzz_1337_test";
        let test_url = if base_url.contains('?') {
            format!("{}&{}={}", base_url, param, test_value)
        } else {
            format!("{}?{}={}", base_url, param, test_value)
        };

        if !seen.insert(test_url.clone()) {
            continue;
        }

        if let Ok(resp) = client.get(&test_url).send().await {
            let status = resp.status().as_u16();
            let content_type = resp.headers().get("content-type").cloned();
            let body = resp.text().await.unwrap_or_default();
            let body_len = body.len();
            let reflected = body.contains(test_value);

            let diff = body_len.abs_diff(avg_baseline);

            // Check: interesting response?
            let interesting = status == 200
                && (diff > threshold || reflected)
                && !is_error_body(&body)
                && content_type.as_ref().map_or(true, |ct| {
                    ct.to_str().map_or(true, |s| is_error_content_type_str(s))
                });

            if interesting {
                let level = if reflected {
                    "HIGH"
                } else if diff > 1000 {
                    "MEDIUM"
                } else {
                    "LOW"
                };

                results.push(FuzzResult {
                    endpoint: base_url.to_string(),
                    parameter: param.to_string(),
                    status,
                    body_length: body_len,
                    reflection: reflected,
                    level: level.to_string(),
                });
            }
        }
    }

    // Step: POST parameter fuzzing
    for &(param, value) in POST_PARAMS {
        let key = format!("POST:{}={}", param, value);
        if !seen.insert(key) {
            continue;
        }

        let form_data = [(param, value)];
        if let Ok(resp) = client.post(base_url).form(&form_data).send().await {
            let status = resp.status().as_u16();
            let content_type = resp.headers().get("content-type").cloned();
            let body = resp.text().await.unwrap_or_default();
            let body_len = body.len();
            let reflected = body.contains(value);

            let diff = body_len.abs_diff(avg_baseline);

            // Check: interesting response?
            if status == 200 && (diff > threshold || reflected) && !is_error_body(&body) && content_type.as_ref().map_or(true, |ct| ct.to_str().map_or(true, |s| is_error_content_type_str(s))) {
                let level = if reflected {
                    "HIGH"
                } else {
                    "MEDIUM"
                };

                results.push(FuzzResult {
                    endpoint: base_url.to_string(),
                    parameter: format!("POST:{}", param),
                    status,
                    body_length: body_len,
                    reflection: reflected,
                    level: level.to_string(),
                });
            }
        }
    }

    results
}
