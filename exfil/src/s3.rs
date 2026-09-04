/// S3 bucket access auditor — authorized security audit tool.
///
/// Checks multiple regional S3 endpoints for a given bucket name, testing
/// for public readability, listability, and write access.
///
/// WARNING: This module is for authorized penetration testing and security
/// auditing only. Unauthorized access to cloud storage is illegal.
use crate::models::S3Result;
use crate::stealth;
use reqwest::header::HeaderMap;

/// Regional S3 endpoints to probe for each bucket.
const S3_ENDPOINTS: &[&str] = &[
    "s3.amazonaws.com",
    "s3-us-east-1.amazonaws.com",
    "s3-eu-west-1.amazonaws.com",
    "s3-eu-central-1.amazonaws.com",
    "s3-us-west-1.amazonaws.com",
    "s3-us-west-2.amazonaws.com",
    "s3-ap-southeast-1.amazonaws.com",
    "s3-ap-northeast-1.amazonaws.com",
    "s3-ap-southeast-2.amazonaws.com",
    "s3-ap-northeast-2.amazonaws.com",
    "s3-sa-east-1.amazonaws.com",
    "s3-ca-central-1.amazonaws.com",
    "s3-eu-west-2.amazonaws.com",
    "s3-eu-west-3.amazonaws.com",
    "s3-eu-north-1.amazonaws.com",
    "s3-ap-east-1.amazonaws.com",
    "s3-me-south-1.amazonaws.com",
    "s3-af-south-1.amazonaws.com",
    "s3-us-gov-east-1.amazonaws.com",
    "s3-us-gov-west-1.amazonaws.com",
];

/// Check whether the response headers indicate an S3 endpoint.
fn is_s3_response(headers: &HeaderMap) -> bool {
    headers.get("x-amz-request-id").is_some()
        || headers.get("x-amz-id-2").is_some()
        || headers.get("x-amz-version-id").is_some()
}

/// Check whether the XML body contains an S3 `Error` response.
fn body_is_s3_error(body: &str) -> bool {
    body.contains("<Error>") && (body.contains("<Code>") || body.contains("<Message>"))
}

/// Test a bucket name against all known S3 endpoints and return non-INFO results.
pub async fn check_s3_bucket(bucket: &str, proxy: Option<&str>) -> Vec<S3Result> {
    // Step: build HTTP client
    // NOTE: danger_accept_invalid_certs(true) is intentional for security auditing.
    // Some S3-compatible endpoints use self-signed certs or custom CAs.
    // This tool only probes public endpoints for misconfigurations.
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
    let mut seen = std::collections::HashSet::new();

    // Loop: probe each regional endpoint
    for endpoint in S3_ENDPOINTS {
        let url = format!("https://{}.{}", bucket, endpoint);
        if !seen.insert(url.clone()) {
            continue;
        }
        let result = test_bucket(&client, &url).await;
        // Check: accessible or writable?
        if result.accessible || result.writable {
            results.push(result);
        }
    }

    results
}

/// Probe a single bucket URL for public access, listability, and writeability.
async fn test_bucket(client: &reqwest::Client, url: &str) -> S3Result {
    let mut result = S3Result {
        bucket_url: url.to_string(),
        accessible: false,
        listable: false,
        writable: false,
        level: "INFO".to_string(),
    };

    // Step: GET to check listability/readability
    match client.get(url).send().await {
        Ok(resp) => {
            let headers = resp.headers();
            // Check: S3 response?
            if !is_s3_response(headers) {
                return result;
            }
            let status = resp.status().as_u16();
            if status == 200 || status == 301 || status == 302 {
                result.accessible = true;
                if let Ok(body) = resp.text().await {
                    result.listable = body.contains("<ListBucketResult")
                        || body.contains("<Contents>")
                        || body.contains("<Key>")
                        || body.contains("<CommonPrefixes>");
                }
            } else if status == 403 {
                if let Ok(body) = resp.text().await {
                    if body_is_s3_error(&body) {
                        result.accessible = true;
                    }
                }
            }
        }
        Err(_) => {}
    }

    // Step: PUT to check write access
    if let Ok(resp) = client
        .put(format!("{}/.exfil_write_test", url))
        .header("Content-Length", "0")
        .send()
        .await
    {
        // Check: write succeeded?
        if resp.status().as_u16() == 200 && is_s3_response(resp.headers()) {
            result.writable = true;
            result.accessible = true;
        }
    }

    // Step: determine severity level
    result.level = if result.writable {
        "CRITICAL".to_string()
    } else if result.listable {
        "HIGH".to_string()
    } else if result.accessible {
        "MEDIUM".to_string()
    } else {
        "INFO".to_string()
    };

    result
}
