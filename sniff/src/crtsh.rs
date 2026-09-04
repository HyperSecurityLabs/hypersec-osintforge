/// crt.sh passive subdomain enumeration.
///
/// Queries the crt.sh certificate transparency log for subdomains
/// belonging to the target domain.
use crate::models::Subdomain;
use crate::stealth;

/// Query crt.sh for certificate-sanctioned subdomains.
///
/// Sends an HTTP GET to crt.sh with the target domain, parses the
/// JSON response, deduplicates entries, and returns a vector of
/// [`Subdomain`] structs tagged with source `"crt.sh"`.
pub async fn query(domain: &str) -> Vec<Subdomain> {
    // Step: Build crt.sh search URL with wildcard prefix
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);

    // Step: Construct an HTTP client with stealth User-Agent
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(stealth::random_ua())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Step: Send request and await response
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // Step: Deserialize response body as JSON array
    let entries: Vec<serde_json::Value> = match resp.json().await {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    // Step: Deduplicate and extract subdomain names
    let mut seen = std::collections::HashSet::new();
    let mut subs = Vec::new();

    // Loop: Iterate over every CT log entry
    for entry in &entries {
        // Check: Entry carries a name_value field
        if let Some(name) = entry["name_value"].as_str() {
            // Loop: Split on newline — one certificate may cover multiple domains
            for n in name.split('\n') {
                let n = n.trim().trim_start_matches("*.").to_lowercase();
                // Check: Valid subdomain candidate AND not already collected
                if n.contains('.') && !seen.contains(&n) {
                    seen.insert(n.clone());
                    subs.push(Subdomain {
                        name: n,
                        ip: None,
                        source: "crt.sh".to_string(),
                        status_code: None,
                        title: None,
                        takeover: None,
                    });
                }
            }
        }
    }

    // Return: Collected unique subdomains
    subs
}
