/// SPOOF — DNS Record Lookup
///
/// Performs MX, SPF, DMARC, and DKIM DNS record lookups via the
/// system `dig` command for email spoofability assessment.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::{DkimResult, DmarcResult, MxRecord, SpfResult};
use std::process::Command;

/// Executes a dig query for the given record type and domain.
fn dig(t: &str, domain: &str) -> String {
    Command::new("dig")
        .arg(t)
        .arg(domain)
        .arg("+short")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

/// Executes a dig TXT query and strips surrounding quotes from results.
fn dig_txt(domain: &str) -> String {
    Command::new("dig")
        .arg("txt")
        .arg(domain)
        .arg("+short")
        .output()
        .ok()
        .map(|o| {
            let raw = String::from_utf8_lossy(&o.stdout).to_string();
            raw.lines().map(|l| l.trim_matches('"')).collect::<Vec<_>>().join("\n")
        })
        .unwrap_or_default()
}

/// Looks up MX records for a domain.
pub async fn mx_lookup(domain: &str) -> Vec<MxRecord> {
    let output = tokio::task::spawn_blocking({
        let d = domain.to_string();
        move || dig("mx", &d)
    })
    .await
    .unwrap_or_default();

    let mut records = Vec::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let priority = parts[0].parse::<u16>().unwrap_or(10);
            let host = parts[1].trim_end_matches('.').to_string();
            records.push(MxRecord { host, ip: None, priority });
        }
    }
    records
}

/// Checks SPF records for a domain and extracts policy and includes.
pub async fn spf_check(domain: &str) -> Option<SpfResult> {
    let output = tokio::task::spawn_blocking({
        let d = domain.to_string();
        move || dig_txt(&d)
    })
    .await
    .unwrap_or_default();

    for line in output.lines() {
        if line.to_lowercase().contains("v=spf1") {
            let lower = line.to_lowercase();
            let all = if lower.contains("-all") { "-all" }
                      else if lower.contains("~all") { "~all" }
                      else if lower.contains("?all") { "?all" }
                      else if lower.contains("+all") { "+all" }
                      else { "none" }.to_string();

            let includes: Vec<String> = lower.split_whitespace()
                .filter(|w| w.starts_with("include:"))
                .map(|w| w.trim_start_matches("include:").to_string())
                .collect();

            return Some(SpfResult {
                raw: line.to_string(),
                all,
                includes,
                valid: true,
            });
        }
    }
    None
}

/// Checks DMARC records for a domain.
pub async fn dmarc_check(domain: &str) -> Option<DmarcResult> {
    let dmarc_domain = format!("_dmarc.{}", domain);
    let output = tokio::task::spawn_blocking({
        let d = dmarc_domain.clone();
        move || dig_txt(&d)
    })
    .await
    .unwrap_or_default();

    for line in output.lines() {
        if line.to_lowercase().contains("v=dmarc1") {
            let lower = line.to_lowercase();
            let policy = lower.split_whitespace()
                .find(|w| w.starts_with("p="))
                .map(|w| w[2..].to_string())
                .unwrap_or_else(|| "none".to_string());

            let pct = lower.split_whitespace()
                .find(|w| w.starts_with("pct="))
                .and_then(|w| w[4..].parse::<u32>().ok())
                .unwrap_or(100);

            let rua: Vec<String> = lower.split_whitespace()
                .filter(|w| w.starts_with("rua="))
                .flat_map(|w| w[4..].split(','))
                .map(|s| s.to_string())
                .collect();

            return Some(DmarcResult {
                raw: line.to_string(),
                policy,
                pct,
                rua,
                valid: true,
            });
        }
    }
    None
}

/// Checks DKIM records for a domain across multiple selectors.
pub async fn dkim_check(domain: &str, selectors: &[&str]) -> Vec<DkimResult> {
    let mut results = Vec::new();
    for sel in selectors {
        let dkim_domain = format!("{}._domainkey.{}", sel, domain);
        let output = tokio::task::spawn_blocking({
            let d = dkim_domain.clone();
            move || dig_txt(&d)
        })
        .await
        .unwrap_or_default();

        let found = output.lines().any(|l| l.contains("v=dkim1") || l.contains("k=rsa") || l.contains("p="));
        if found || !output.is_empty() {
            results.push(DkimResult {
                selector: sel.to_string(),
                raw: output,
                valid: found,
            });
        }
    }
    results
}
