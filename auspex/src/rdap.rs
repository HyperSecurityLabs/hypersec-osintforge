/// Auspex — RDAP Lookup
///
/// Queries the RDAP (Registration Data Access Protocol) API at rdap.org
/// for structured domain registration data as a secondary intelligence source.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::{RdapEntity, RdapEvent, RdapInfo};
use crate::parser;
use std::time::Duration;

/// Performs an RDAP lookup for the given domain.
pub async fn lookup(domain: &str) -> Option<RdapInfo> {
    let clean = domain.trim().trim_end_matches('.').to_lowercase();
    let url = format!("https://rdap.org/domain/{}", clean);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(crate::stealth::random_ua())
        .build()
        .ok()?;

    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let json: serde_json::Value = resp.json().await.ok()?;
    let mut events = Vec::new();
    let mut entities = Vec::new();
    let mut status_codes = Vec::new();
    let mut name_servers = Vec::new();
    let mut dnssec = None;

    // Parse lifecycle events
    if let Some(evts) = json["events"].as_array() {
        for ev in evts {
            let action = ev["eventAction"].as_str().unwrap_or("?").to_string();
            let date_str = ev["eventDate"].as_str().unwrap_or("");
            let date = parser::parse_date_string(date_str);
            events.push(RdapEvent { action, date });
        }
    }

    // Parse status codes
    if let Some(status) = json["status"].as_array() {
        for s in status {
            if let Some(val) = s.as_str() {
                status_codes.push(val.to_string());
            }
        }
    }

    // Parse name servers
    if let Some(ns) = json["nameservers"].as_array() {
        for n in ns {
            if let Some(lfh) = n["ldhName"].as_str() {
                name_servers.push(lfh.trim_end_matches('.').to_string());
            }
        }
    }

    // Parse DNSSEC status
    if let Some(secure) = json["secureDNS"].as_object() {
        if secure.get("delegationSigned").and_then(|v| v.as_bool()).unwrap_or(false) {
            dnssec = Some("signedDelegation".to_string());
        }
    }

    // Parse entity records
    if let Some(ents) = json["entities"].as_array() {
        for ent in ents {
            let roles: Vec<&str> = ent["roles"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let role = roles.first().copied().unwrap_or("unknown").to_string();

            let name = extract_from_vcard(&ent, "fn");
            let org = extract_from_vcard(&ent, "org");
            let email = extract_from_vcard(&ent, "email");
            let country = extract_adr_country(&ent);

            entities.push(RdapEntity {
                role,
                name,
                org,
                email,
                country,
            });
        }
    }

    Some(RdapInfo {
        domain: clean,
        events,
        entities,
        status_codes,
        name_servers,
        dnssec,
        source: "rdap.org".to_string(),
    })
}

/// Extracts a vCard field value from an RDAP entity JSON object.
fn extract_from_vcard(ent: &serde_json::Value, field: &str) -> Option<String> {
    ent["vcardArray"][1]
        .as_array()?
        .iter()
        .find_map(|item| {
            let arr = item.as_array()?;
            if arr.first()?.as_str()? == field {
                arr.get(3)?.as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
}

/// Extracts the country from a vCard ADR field in an RDAP entity.
fn extract_adr_country(ent: &serde_json::Value) -> Option<String> {
    let adr = ent["vcardArray"][1]
        .as_array()?
        .iter()
        .find_map(|item| {
            let arr = item.as_array()?;
            if arr.first()?.as_str()? == "adr" {
                arr.get(3)?.as_array().cloned()
            } else {
                None
            }
        })?;
    adr.get(6)?.as_str().map(|s| s.to_string())
}
