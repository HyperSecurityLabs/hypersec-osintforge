/// DNS resolution, brute-force enumeration, wildcard detection,
/// zone-transfer checks, and DNS-over-HTTPS fallback.
use crate::models::{Subdomain, ZoneTransferResult};
use std::collections::HashSet;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Resolve all subdomains via the system resolver with DoH fallback.
///
/// Iterates through the mutable slice, populating the `ip` field of
/// each [`Subdomain`]. On lookup failure it falls back to
/// Cloudflare's DNS-over-HTTPS JSON API.
pub async fn resolve(subdomains: &mut [Subdomain]) {
    // Loop: Iterate through each subdomain and attempt resolution
    for sd in subdomains.iter_mut() {
        let found = tokio::net::lookup_host((sd.name.as_str(), 0)).await;
        match found {
            Ok(addrs) => {
                // Handle: Take the first resolved address
                if let Some(addr) = addrs.into_iter().next() {
                    sd.ip = Some(addr.ip().to_string());
                }
            }
            Err(_) => {
                // Handle: Fallback to DNS-over-HTTPS
                if let Some(ip) = resolve_via_doh(&sd.name).await {
                    sd.ip = Some(ip);
                }
            }
        }
    }
}

/// Brute-force subdomains using a wordlist with concurrent lookups.
///
/// Each word is prefixed to the domain and resolved via the system
/// DNS. Only successful lookups are returned, deduplicated, and tagged
/// with source `"bruteforce"`.
pub async fn brute_force(domain: &str, wordlist: &[String], threads: usize) -> Vec<Subdomain> {
    // Step: Create a semaphore to limit concurrent DNS queries
    let sem = Arc::new(Semaphore::new(threads));
    let mut handles = Vec::new();

    // Loop: Spawn one task per word in the wordlist
    for word in wordlist {
        let sub = format!("{}.{}", word.trim(), domain).to_lowercase();
        let sem = sem.clone();
        let sub_for_lookup = sub.clone();

        handles.push(tokio::spawn(async move {
            // Step: Acquire semaphore permit before querying
            let _permit = sem.acquire().await.expect("semaphore");
            let found = tokio::net::lookup_host((sub_for_lookup.as_str(), 0)).await;
            // Check: DNS resolution succeeded
            if found.is_ok() {
                return Some(Subdomain {
                    name: sub,
                    ip: None,
                    source: "bruteforce".to_string(),
                    status_code: None,
                    title: None,
                    takeover: None,
                });
            }
            None
        }));
    }

    // Step: Collect and deduplicate results
    let mut subs = Vec::new();
    let mut seen = HashSet::new();
    for h in handles {
        if let Ok(Some(sd)) = h.await {
            // Check: Name not already collected
            if seen.insert(sd.name.clone()) {
                subs.push(sd);
            }
        }
    }

    subs
}

/// Retrieve the list of authoritative nameservers for a domain.
///
/// Shells out to `dig ns <domain> +short` and returns the parsed
/// hostnames, stripping the trailing dot.
pub async fn ns_list(domain: &str) -> Vec<String> {
    // Step: Spawn blocking task to run `dig` command
    let output = tokio::task::spawn_blocking({
        let d = domain.to_string();
        move || {
            Command::new("dig")
                .arg("ns")
                .arg(&d)
                .arg("+short")
                .output()
                .ok()
        }
    })
    .await
    .ok()
    .flatten()
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default();

    // Step: Parse each line, trim trailing dot, filter empties
    output.lines().map(|l| l.trim().trim_end_matches('.').to_string()).filter(|l| !l.is_empty()).collect()
}

/// Attempt a DNS AXFR (zone transfer) against a given nameserver.
///
/// Returns [`ZoneTransferResult`] with `records` populated when the
/// server leaks its zone. Returns `None` on failure or empty output.
pub async fn check_zone_transfer(domain: &str, ns: &str) -> Option<ZoneTransferResult> {
    // Step: Spawn blocking task for `dig axfr` command
    let output = tokio::task::spawn_blocking({
        let ns = ns.to_string();
        let domain = domain.to_string();
        move || {
            Command::new("dig")
                .arg("axfr")
                .arg(&domain)
                .arg(&format!("@{}", ns))
                .arg("+short")
                .output()
                .ok()
        }
    })
    .await
    .ok()
    .flatten()?;

    // Step: Parse stdout lines into a non-empty record vector
    let raw = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<String> = raw.lines().map(|l| l.to_string()).filter(|l| !l.is_empty()).collect();

    // Check: Any records returned indicates a successful (leaky) transfer
    if lines.is_empty() {
        None
    } else {
        Some(ZoneTransferResult {
            success: true,
            records: lines,
        })
    }
}

/// Detect whether the target domain uses wildcard DNS.
///
/// Resolves several random, non-existent subdomain prefixes.
/// If all resolve successfully the domain is considered wildcard.
pub async fn detect_wildcard(domain: &str) -> bool {
    let prefixes = [
        "sdkjfhsdkljfhklsdjhfklsdjhf",
        "xyznonexistenttest98765",
        "qwertyuiop1234567890asdf",
    ];
    let mut resolved = 0usize;
    // Loop: Check each random prefix for resolution
    for prefix in &prefixes {
        let sub = format!("{}.{}", prefix, domain);
        // Check: Prefix resolves — wildcard likely
        if tokio::net::lookup_host((sub.as_str(), 0)).await.is_ok() {
            resolved += 1;
        }
    }
    // Return: True if ALL bogus prefixes resolved
    resolved == prefixes.len()
}

/// Resolve a hostname via Cloudflare's DNS-over-HTTPS (JSON) API.
///
/// Sends an `application/dns-json` GET request and extracts the first
/// A-record `data` field, returning it as a string IP.
pub async fn resolve_via_doh(domain: &str) -> Option<String> {
    // Step: Build DoH URL for A-record lookup
    let url = format!("https://cloudflare-dns.com/dns-query?name={}&type=A", domain);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent("Mozilla/5.0")
        .build()
        .ok()?;
    // Step: Send request with DNS-JSON accept header
    let resp = client.get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await
        .ok()?;
    // Step: Parse JSON and extract first A record
    let data: serde_json::Value = resp.json().await.ok()?;
    data["Answer"]
        .as_array()?
        .first()?
        .get("data")?
        .as_str()
        .map(|s| s.to_string())
}
