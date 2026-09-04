/// DNS resolution and record lookup for target domains.
///
/// Resolves A/AAAA records via the system resolver and fetches
/// MX, NS, and TXT records using the `dig` command.
use crate::models::{DnsInfo, DnsRecord};
use std::net::ToSocketAddrs;

/// Resolve all available DNS records for a target domain.
///
/// Strips protocol prefixes and paths, then queries A, AAAA, MX, NS, and TXT records.
pub async fn resolve(target: &str) -> DnsInfo {
    let mut info = DnsInfo { records: Vec::new() };
    // Step: extract hostname from URL if present
    let host = target
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(target)
        .split(':')
        .next()
        .unwrap_or(target);

    // Step: resolve A and AAAA records via system DNS
    let addr_str = format!("{}:0", host);
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        let mut seen = std::collections::HashSet::new();
        // Loop: iterate over resolved addresses
        while let Some(addr) = addrs.next() {
            let ip = addr.ip().to_string();
            if seen.insert(ip.clone()) {
                let rtype = if addr.is_ipv4() { "A" } else { "AAAA" };
                info.records.push(DnsRecord {
                    rtype: rtype.to_string(),
                    value: ip,
                });
            }
        }
    }

    // Step: query MX records via dig
    if let Ok(output) = run_dig(host, "MX") {
        for line in output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(last) = parts.last() {
                let val = last.trim_end_matches('.');
                if !val.is_empty() && val.contains('.') {
                    info.records.push(DnsRecord {
                        rtype: "MX".to_string(),
                        value: val.to_string(),
                    });
                }
            }
        }
    }

    // Step: query NS records via dig
    if let Ok(output) = run_dig(host, "NS") {
        for line in output.lines() {
            let ns = line.trim().trim_end_matches('.');
            if !ns.is_empty() && ns.contains('.') {
                if !info.records.iter().any(|r| r.rtype == "NS" && r.value == ns) {
                    info.records.push(DnsRecord {
                        rtype: "NS".to_string(),
                        value: ns.to_string(),
                    });
                }
            }
        }
    }

    // Step: query TXT records via dig
    if let Ok(output) = run_dig(host, "TXT") {
        for line in output.lines() {
            if let Some(val) = extract_txt_value(line) {
                if !val.is_empty() && !info.records.iter().any(|r| r.rtype == "TXT" && r.value == val) {
                    info.records.push(DnsRecord {
                        rtype: "TXT".to_string(),
                        value: val,
                    });
                }
            }
        }
    }

    info
}

/// Execute a `dig +short` command for a given record type.
fn run_dig(host: &str, rtype: &str) -> Result<String, std::io::Error> {
    let output = std::process::Command::new("dig")
        .arg("+short")
        .arg(host)
        .arg(rtype)
        .output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Extract a quoted TXT record value from a dig output line.
fn extract_txt_value(line: &str) -> Option<String> {
    let line = line.trim();
    if line.starts_with(';') || line.is_empty() {
        return None;
    }
    if let Some(start) = line.find('"') {
        let after = &line[start + 1..];
        if let Some(end) = after.find('"') {
            let val = &after[..end];
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}
