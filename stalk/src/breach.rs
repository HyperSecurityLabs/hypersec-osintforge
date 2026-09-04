/// Breach-data lookup via HIBP (Have I Been Pwned) API v3
/// and k-anonymity password-pwned check.
use crate::models::BreachResult;
use crate::stealth;
use sha1::{Digest, Sha1};

/// Read the HIBP API key from environment variables.
///
/// Checks `HIBP_API_KEY` first, then `STALK_HIBP_KEY`, and rejects
/// empty or `"unused"` sentinel values.
fn hibp_api_key() -> Option<String> {
    std::env::var("HIBP_API_KEY").ok()
        .or_else(|| std::env::var("STALK_HIBP_KEY").ok())
        .filter(|k| !k.is_empty() && k != "unused")
}

/// Check an email address against known data breaches via HIBP.
///
/// Returns all verified, non-spam, non-retired, non-malware breaches
/// associated with the given email.
pub async fn check_email(email: &str) -> Vec<BreachResult> {
    // Step: Obtain API key — skip if not configured
    let api_key = match hibp_api_key() {
        Some(k) => k,
        None => return Vec::new(),
    };

    // Step: Build stealth HTTP client
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(stealth::random_ua())
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Step: Build HIBP API URL
    let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}", email);
    let resp = match client
        .get(&url)
        .header("hibp-api-key", &api_key)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => r,
        // Handle: 404 means no breaches found
        Ok(r) if r.status().as_u16() == 404 => return Vec::new(),
        _ => return Vec::new(),
    };

    // Step: Deserialize JSON array of breach entries
    let entries: Vec<serde_json::Value> = match resp.json().await {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    // Step: Filter and map breach entries
    entries.iter()
        .filter(|e| {
            let verified = e["IsVerified"].as_bool().unwrap_or(false);
            let spam_list = e["IsSpamList"].as_bool().unwrap_or(true);
            let retired = e["IsRetired"].as_bool().unwrap_or(true);
            let malware = e["IsMalware"].as_bool().unwrap_or(true);
            // Check: Only keep verified, non-spam, non-retired, non-malware
            verified && !spam_list && !retired && !malware
        })
        .map(|e| BreachResult {
        name: e["Name"].as_str().unwrap_or("?").to_string(),
        domain: e["Domain"].as_str().unwrap_or("?").to_string(),
        breach_date: e["BreachDate"].as_str().unwrap_or("?").to_string(),
        pwn_count: e["PwnCount"].as_u64().unwrap_or(0) as u32,
        data_classes: e["DataClasses"].as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default(),
    }).collect()
}

/// Compute the SHA-1 hex digest of a password (upper-case).
fn sha1_hex(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    hex::encode(result).to_uppercase()
}

/// Check how many times a password has been exposed via HIBP's
/// k-anonymity API (only the first 5 hash characters are sent).
pub async fn check_password(password: &str) -> u32 {
    // Step: Build stealth HTTP client
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(stealth::random_ua())
        .build()
    {
        Ok(c) => c,
        Err(_) => return 0,
    };

    // Step: Compute SHA-1 hash and split into prefix/suffix
    let hash = sha1_hex(password);
    let prefix = &hash[..5];
    let suffix = &hash[5..];
    let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

    // Step: Send k-anonymity range query
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return 0,
    };

    // Step: Read response body
    let body = match resp.text().await {
        Ok(t) => t,
        Err(_) => return 0,
    };

    // Loop: Search for matching hash suffix in response
    for line in body.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        // Check: Suffix match found
        if parts.len() == 2 && parts[0] == suffix {
            return parts[1].trim().parse::<u32>().unwrap_or(0);
        }
    }
    0
}
