/// AlienVault OTX (Open Threat Exchange) passive subdomain enumeration.
use crate::models::Subdomain;
use crate::stealth;

/// Query AlienVault OTX for subdomains of the given domain.
///
/// Fetches up to 500 URL results from the OTX API, extracts the
/// host portion of each URL, filters to subdomains ending with the
/// target domain, deduplicates, and returns tagged [`Subdomain`]s
/// with source `"otx"`.
pub async fn query(domain: &str) -> Vec<Subdomain> {
    // Step: Build OTX API URL
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list?limit=500",
        domain
    );

    // Step: Build stealth HTTP client
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(stealth::random_ua())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Step: Send GET request to OTX
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // Step: Parse JSON response body
    let body: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    // Step: Extract and deduplicate subdomains from url_list
    let mut seen = std::collections::HashSet::new();
    let mut subs = Vec::new();

    // Check: url_list array present in response
    if let Some(urls) = body["url_list"].as_array() {
        // Loop: Iterate through each URL entry
        for entry in urls {
            if let Some(url_str) = entry["url"].as_str() {
                // Step: Extract hostname from full URL
                let host = url_str
                    .split("://")
                    .nth(1)
                    .and_then(|s| s.split('/').next())
                    .map(|s| s.trim_start_matches("*.").to_lowercase())
                    .unwrap_or_default();
                // Check: Host is valid subdomain and not already seen
                if host.contains('.') && host.ends_with(domain) && !seen.contains(&host) {
                    seen.insert(host.clone());
                    subs.push(Subdomain {
                        name: host,
                        ip: None,
                        source: "otx".to_string(),
                        status_code: None,
                        title: None,
                        takeover: None,
                    });
                }
            }
        }
    }

    subs
}
