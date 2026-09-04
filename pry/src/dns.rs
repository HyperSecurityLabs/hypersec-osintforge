/// DNS resolution module for PRY.
///
/// Performs A and AAAA record lookups via the system resolver.
use crate::models::LookupResult;
use std::net::IpAddr;

/// Perform DNS lookups for the given target string.
///
/// If the target is already an IP address, returns an empty result.
/// Otherwise, resolves the domain and populates A/AAAA records.
pub async fn lookup(target: &str) -> LookupResult {
    let target = target.trim().to_lowercase();

    // Branch: if target is an IP, no DNS resolution is needed
    if target.parse::<IpAddr>().is_ok() {
        let mut r = LookupResult::new(&target);
        r.source = "dns".to_string();
        return r;
    }

    let mut r = LookupResult::new(&target);
    r.source = "dns".to_string();

    // Step: resolve domain to IP addresses
    let ips: Vec<_> = match tokio::net::lookup_host((target.as_str(), 0)).await {
        Ok(addrs) => addrs.collect(),
        Err(_) => return r,
    };

    // Loop: classify each resolved address as A or AAAA
    for addr in ips {
        match addr.ip() {
            IpAddr::V4(v4) => {
                if !r.a_records.contains(&v4.to_string()) {
                    r.a_records.push(v4.to_string());
                }
            }
            IpAddr::V6(v6) => {
                if !r.aaaa_records.contains(&v6.to_string()) {
                    r.aaaa_records.push(v6.to_string());
                }
            }
        }
    }

    r
}
