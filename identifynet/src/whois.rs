/// WHOIS lookup for IP addresses via the system `whois` command.
use crate::models::WhoisInfo;
use std::net::IpAddr;
use std::process::Command;

/// Perform a WHOIS lookup against the given IP address.
///
/// Parses the raw WHOIS response and extracts key fields:
/// NetRange, OrgName, Tech Email, and Abuse Email.
pub async fn lookup(ip: IpAddr) -> Option<WhoisInfo> {
    let ip_str = ip.to_string();
    // Step: spawn blocking whois command
    let output = tokio::task::spawn_blocking(move || {
        Command::new("whois")
            .arg(&ip_str)
            .output()
            .ok()
    })
    .await
    .ok()
    .flatten()?;

    // Step: convert raw stdout to string
    let raw = String::from_utf8_lossy(&output.stdout).to_string();
    // Check: empty response means no data
    if raw.is_empty() {
        return None;
    }

    let mut info = WhoisInfo {
        raw: raw.clone(),
        ..Default::default()
    };

    // Loop: parse each line of the WHOIS response
    for line in raw.lines() {
        let l = line.trim();
        if let Some((key, val)) = l.split_once(':') {
            let k = key.trim().to_lowercase();
            let v = val.trim().to_string();
            // Check: skip empty values
            if v.is_empty() {
                continue;
            }
            // Dispatch: match key to the appropriate field
            match k.as_str() {
                "netrange" | "net range" => info.netrange = Some(v),
                "orgname" | "org-name" | "organisation" | "organization" => info.orgname = Some(v),
                "tech email" | "tech_email" => info.tech_email = Some(v),
                "abuse email" | "abuse-mailbox" | "abuse_email" => info.abuse_email = Some(v),
                _ => {}
            }
        }
    }

    Some(info)
}
