/// DNS resolution and record lookup utilities.
///
/// Provides PTR reverse lookups and MX, NS, TXT record queries
/// via the system `dig` command.
use std::net::IpAddr;
use std::process::Command;

/// Perform a reverse DNS (PTR) lookup for the given IP address.
pub async fn ptr_lookup(ip: IpAddr) -> Option<String> {
    let ip_str = ip.to_string();
    // Step: spawn blocking dig command for PTR record
    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .arg("-x")
            .arg(&ip_str)
            .arg("+short")
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten()?;

    // Handle: parse and clean the result string
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // Check: empty result or NXDOMAIN indicates no PTR record
    if name.is_empty() || name.contains("NXDOMAIN") {
        return None;
    }
    Some(name.trim_end_matches('.').to_string())
}

/// Look up MX (mail exchange) records for a domain.
pub async fn mx_lookup(domain: &str) -> Vec<String> {
    let d = domain.to_string();
    // Step: spawn blocking dig command for MX records
    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .arg("mx")
            .arg(&d)
            .arg("+short")
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten()
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default();

    // Step: parse each line into a deduplicated vector
    let mut mx = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        // Check: skip empty lines
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Check: expect at least two fields (priority + hostname)
        if parts.len() >= 2 {
            let name = parts[1].trim_end_matches('.').to_string();
            if !name.is_empty() && !mx.contains(&name) {
                mx.push(name);
            }
        }
    }
    mx
}

/// Look up NS (nameserver) records for a domain.
pub async fn ns_lookup(domain: &str) -> Vec<String> {
    let d = domain.to_string();
    // Step: spawn blocking dig command for NS records
    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .arg("ns")
            .arg(&d)
            .arg("+short")
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten()
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default();

    // Step: parse each line into a deduplicated vector
    let mut ns = Vec::new();
    for line in output.lines() {
        let name = line.trim().trim_end_matches('.').to_string();
        if !name.is_empty() && !ns.contains(&name) {
            ns.push(name);
        }
    }
    ns
}

/// Look up TXT records for a domain.
pub async fn txt_lookup(domain: &str) -> Vec<String> {
    let d = domain.to_string();
    // Step: spawn blocking dig command for TXT records
    let output = tokio::task::spawn_blocking(move || {
        Command::new("dig")
            .arg("txt")
            .arg(&d)
            .arg("+short")
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten()
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default();

    // Step: parse each quoted TXT line into a deduplicated vector
    let mut txt = Vec::new();
    for line in output.lines() {
        let line = line.trim().trim_matches('"');
        if !line.is_empty() && !txt.contains(&line.to_string()) {
            txt.push(line.to_string());
        }
    }
    txt
}
