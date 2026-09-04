/// Insecure Direct Object Reference (IDOR) scanner.
/// Tests path-based and query-parameter-based IDs by replacing them with
/// common alternates and analysing response variance against a statistical baseline.
use crate::models::IdorResult;
use crate::stealth;
use regex::Regex;
use std::collections::HashSet;
use url::Url;

/// Test IDs used to replace the original identifier during IDOR probing.
const TEST_IDS: &[&str] = &[
    "1", "2", "100", "1000", "999999",
    "admin", "test", "00000001", "00000000",
    "ffffffff", "11111111", "0", "-1",
    "null", "undefined", "true", "false",
];

/// Regex patterns for detecting numeric, UUID, MongoDB ObjectId,
/// and long alphanumeric path segments.
const PATH_PATTERNS: &[&str] = &[
    r"/(\d+)",
    r"/([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})",
    r"/([a-fA-F0-9]{24})",
    r"/([a-zA-Z0-9_-]{20,})",
];

/// A deliberately invalid ID used as a negative control.
/// Responses matching this indicate access-control enforcement.
const NEGATIVE_CONTROL_ID: &str = "NEGATIVE_CONTROL_999999999999";

/// Keywords found in access-denied/error responses.
const ERROR_KEYWORDS: &[&str] = &[
    "access denied",
    "forbidden",
    "unauthorized",
    "not found",
    "permission denied",
    "insufficient privileges",
    "you do not have permission",
    "authentication required",
    "token required",
    "invalid request",
    "bad request",
    "page not found",
    "404 not found",
    "403 forbidden",
    "401 unauthorized",
];

/// Subset of error keywords indicating explicit forbiddance.
const FORBIDDEN_KEYWORDS: &[&str] = &[
    "access denied",
    "forbidden",
    "unauthorized",
    "permission denied",
    "insufficient privileges",
    "you do not have permission",
];

const BASELINE_SAMPLES: usize = 5;
const STD_DEV_THRESHOLD: f64 = 3.0;

/// Internal struct holding a raw HTTP fetch result.
struct FetchResult {
    status: u16,
    body: String,
    content_type: String,
}

/// Statistical summary of baseline responses (length mean, std dev, content-type).
struct BaselineStats {
    lengths: Vec<usize>,
    mean: f64,
    std_dev: f64,
    content_type: String,
}

/// Scan a URL for IDOR vulnerabilities via path and query-parameter mutation.
pub async fn check_idor(base_url: &str, proxy: Option<&str>) -> Vec<IdorResult> {
    // Step: build HTTP client with optional proxy
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
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
    let mut seen = HashSet::new();

    // Step: scan path-based IDs
    for pattern_str in PATH_PATTERNS {
        let re = match Regex::new(pattern_str) {
            Ok(r) => r,
            Err(_) => continue,
        };
        // Check: URL matches this pattern?
        if let Some(caps) = re.captures(base_url) {
            let original_id = caps[1].to_string();
            let param_name = if pattern_str.contains("uuid") || pattern_str.contains("24}") {
                "path_uuid"
            } else if pattern_str.contains("20}") {
                "path_hash"
            } else {
                "path_id"
            };

            // Step: collect baseline
            let baseline = collect_baseline(&client, base_url).await;
            let baseline = match baseline {
                Some(b) => b,
                None => continue,
            };

            // Step: fetch negative control
            let neg_ctrl_url = replace_path_id(base_url, &re, NEGATIVE_CONTROL_ID);
            let negative_control = match fetch_url_full(&client, &neg_ctrl_url).await {
                Ok(r) => r,
                Err(_) => continue,
            };

            // Loop: test each candidate ID
            for test_id in TEST_IDS {
                if test_id == &original_id {
                    continue;
                }
                let key = format!("path:{}->{}", original_id, test_id);
                if !seen.insert(key) {
                    continue;
                }

                let test_url = replace_path_id(base_url, &re, test_id);
                let result = compare_id(
                    &client, base_url, &test_url, &param_name,
                    &original_id, test_id, &baseline, &negative_control,
                ).await;
                if let Some(r) = result {
                    results.push(r);
                }
            }
        }
    }

    // Step: scan query param-based IDs
    let param_pattern = match Regex::new(r"(?:id|uid|user_id|account|profile|document|file|order|invoice|ticket|user|customer|member|pid|eid)=(\d+)") {
        Ok(r) => r,
        Err(_) => return results,
    };
    // Check: URL contains a numeric query param?
    if let Some(caps) = param_pattern.captures(base_url) {
        let original_id = caps[1].to_string();
        let param_name = base_url
            .split('&')
            .find(|p| p.contains(&format!("={}", original_id)))
            .and_then(|p| p.split('=').next())
            .unwrap_or("id")
            .to_string();

        let baseline = collect_baseline(&client, base_url).await;
        let baseline = match baseline {
            Some(b) => b,
            None => return results,
        };

        let neg_ctrl_url = replace_query_param(base_url, &param_name, NEGATIVE_CONTROL_ID);
        let negative_control = match fetch_url_full(&client, &neg_ctrl_url).await {
            Ok(r) => r,
            Err(_) => return results,
        };

        // Loop: test each candidate ID
        for test_id in TEST_IDS {
            if test_id == &original_id {
                continue;
            }
            let key = format!("param:{}->{}", original_id, test_id);
            if !seen.insert(key) {
                continue;
            }

            let test_url = replace_query_param(base_url, &param_name, test_id);
            let result = compare_id(
                &client, base_url, &test_url, &param_name,
                &original_id, test_id, &baseline, &negative_control,
            ).await;
            if let Some(r) = result {
                results.push(r);
            }
        }
    }

    results
}

/// Replace the matched path segment in `url_str` with `new_id` using regex.
fn replace_path_id(url_str: &str, re: &Regex, new_id: &str) -> String {
    re.replace(url_str, |_: &regex::Captures| format!("/{}", new_id)).to_string()
}

/// Replace the value of a specific query parameter with `new_val`.
fn replace_query_param(url_str: &str, param: &str, new_val: &str) -> String {
    let mut url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return url_str.to_string(),
    };
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let mut new_pairs = url.query_pairs_mut();
    new_pairs.clear();
    for (k, v) in &pairs {
        if k == param {
            new_pairs.append_pair(k, new_val);
        } else {
            new_pairs.append_pair(k, v);
        }
    }
    drop(new_pairs);
    url.to_string()
}

/// Collect multiple baseline requests and compute statistics.
async fn collect_baseline(client: &reqwest::Client, url: &str) -> Option<BaselineStats> {
    let mut results = Vec::new();
    for _ in 0..BASELINE_SAMPLES {
        if let Ok(fr) = fetch_url_full(client, url).await {
            results.push(fr);
        }
    }
    // Check: enough samples?
    if results.len() < 2 {
        return None;
    }

    let lengths: Vec<usize> = results.iter().map(|r| r.body.len()).collect();
    let n = lengths.len() as f64;
    let sum: usize = lengths.iter().sum();
    let mean = sum as f64 / n;
    let variance = lengths.iter().map(|l| {
        let d = *l as f64 - mean;
        d * d
    }).sum::<f64>() / n;
    let std_dev = variance.sqrt();

    // Step: determine majority content-type
    let content_type = results
        .iter()
        .map(|r| r.content_type.split(';').next().unwrap_or("").trim().to_string())
        .fold(std::collections::HashMap::new(), |mut acc, ct| {
            *acc.entry(ct).or_insert(0) += 1;
            acc
        })
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .map(|(ct, _)| ct)
        .unwrap_or_default();

    Some(BaselineStats {
        lengths,
        mean,
        std_dev,
        content_type,
    })
}

/// Fetch a URL and return status, body, and content-type as a `FetchResult`.
async fn fetch_url_full(client: &reqwest::Client, url: &str) -> Result<FetchResult, ()> {
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = resp.text().await.unwrap_or_default();
            Ok(FetchResult { status, body, content_type })
        }
        Err(_) => Err(()),
    }
}

/// Check if the body contains access-control error keywords.
fn is_error_body(body: &str) -> bool {
    let lower = body.to_lowercase();
    ERROR_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Check if the status code or body indicates a forbidden response.
fn is_forbidden(status: u16, body: &str) -> bool {
    if matches!(status, 401 | 403 | 407) {
        return true;
    }
    let lower = body.to_lowercase();
    FORBIDDEN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Check whether the body length differs significantly from the baseline
/// using either z-score or percentage-based heuristics.
fn is_significant_difference(length: usize, stats: &BaselineStats) -> bool {
    if stats.std_dev < 0.001 || stats.lengths.is_empty() {
        let baseline_avg = stats.lengths.iter().sum::<usize>() as f64 / stats.lengths.len() as f64;
        (length as f64 - baseline_avg).abs() > baseline_avg * 0.05
    } else {
        let z = (length as f64 - stats.mean).abs() / stats.std_dev;
        z > STD_DEV_THRESHOLD
    }
}

/// Determine if the test response resembles the negative control response
/// (same error/forbidden pattern).
fn body_resembles_negative_control(test: &FetchResult, neg_ctrl: &FetchResult) -> bool {
    if test.status == neg_ctrl.status && neg_ctrl.status != 200 {
        return true;
    }
    let test_len = test.body.len();
    let neg_len = neg_ctrl.body.len();
    if neg_len > 0 {
        let ratio = test_len as f64 / neg_len as f64;
        if (ratio - 1.0).abs() < 0.15 {
            return true;
        }
    }
    if is_error_body(&neg_ctrl.body) && is_error_body(&test.body) {
        return true;
    }
    false
}

/// Check that the test response content-type matches the baseline content-type.
fn content_type_matches(test_ct: &str, baseline_ct: &str) -> bool {
    if baseline_ct.is_empty() {
        return true;
    }
    let test_mime = test_ct.split(';').next().unwrap_or("").trim();
    let base_mime = baseline_ct.split(';').next().unwrap_or("").trim();
    test_mime == base_mime
}

/// Compare an original resource with a mutated ID to detect potential IDOR.
async fn compare_id(
    client: &reqwest::Client,
    orig_url: &str,
    test_url: &str,
    param_name: &str,
    original_id: &str,
    test_id: &str,
    baseline: &BaselineStats,
    negative_control: &FetchResult,
) -> Option<IdorResult> {
    let orig = fetch_url_full(client, orig_url).await.ok()?;
    let test = fetch_url_full(client, test_url).await.ok()?;

    // Check: request failed?
    if orig.status == 0 || test.status == 0 {
        return None;
    }

    // Check: test response is forbidden?
    if is_forbidden(test.status, &test.body) {
        return None;
    }

    // Check: test body is error page?
    if is_error_body(&test.body) {
        return None;
    }

    // Check: test resembles negative control?
    if body_resembles_negative_control(&test, negative_control) {
        return None;
    }

    // Check: content-type consistent?
    if !content_type_matches(&test.content_type, &baseline.content_type) {
        return None;
    }

    // Step: check body length significance
    let body_changed = is_significant_difference(test.body.len(), baseline);

    if !body_changed {
        return None;
    }

    // Step: final IDOR determination
    let potential_idor = orig.status == 200
        && test.status == 200
        && body_changed
        && !test.body.contains(original_id)
        && !is_error_body(&test.body)
        && !is_forbidden(test.status, &test.body)
        && !body_resembles_negative_control(&test, negative_control)
        && content_type_matches(&test.content_type, &baseline.content_type);

    let level = if potential_idor {
        "HIGH"
    } else if orig.status != test.status {
        "MEDIUM"
    } else {
        "LOW"
    };

    Some(IdorResult {
        endpoint: orig_url.to_string(),
        parameter: param_name.to_string(),
        original_id: original_id.to_string(),
        test_id: test_id.to_string(),
        original_status: orig.status,
        test_status: test.status,
        original_length: orig.body.len(),
        test_length: test.body.len(),
        potential_idor,
        level: level.to_string(),
    })
}
