/// HTTP utilities for public IP address discovery.
///
/// Fetches the caller's public IP from several external services
/// (checkip.amazonaws.com, api.ipify.org, icanhazip.com).
use std::net::IpAddr;

/// Determine the public IP address of the current machine.
///
/// Tries multiple providers in order, with an optional SOCKS/HTTP proxy.
pub async fn public_ip(proxy: Option<&str>) -> Option<IpAddr> {
    // Step: list of public IP discovery endpoints
    let urls = [
        "https://checkip.amazonaws.com",
        "https://api.ipify.org",
        "https://icanhazip.com",
    ];

    // Loop: try each URL until one succeeds
    for url in &urls {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5));

        // Branch: apply proxy if provided
        if let Some(proxy_url) = proxy {
            if let Ok(p) = reqwest::Proxy::all(proxy_url) {
                builder = builder.proxy(p);
            }
        }

        let client = builder.build().ok()?;

        // Handle: send the GET request and parse the response
        match client.get(*url).send().await {
            Ok(resp) => {
                let text = resp.text().await.ok()?;
                let ip_str = text.trim();
                // Check: string must be a valid IP address
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
            // Handle: try next URL on failure
            Err(_) => continue,
        }
    }
    // Handle: all providers failed
    None
}
