/// Auspex — WHOIS Response Parser
///
/// Parses raw WHOIS text responses into structured WhoisInfo,
/// extracting registrar, registrant, dates, name servers,
/// status codes, and contact details using regex and prefix matching.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::WhoisInfo;
use chrono::NaiveDateTime;
use regex::Regex;

/// Parses raw WHOIS text into a structured WhoisInfo for the given domain.
pub fn parse_whois(domain: &str, raw: &str, server: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        domain: domain.to_string(),
        source_server: Some(server.to_string()),
        raw: Some(raw.to_string()),
        ..Default::default()
    };

    let lower = raw.to_lowercase();

    // Registrar
    info.registrar = extract_value(raw, &[
        "Registrar:",
        "registrar:",
        "Sponsoring Registrar:",
        "registrar name:",
    ]);
    if info.registrar.is_none() {
        info.registrar = extract_value_line(raw, &[
            "Registrar",
            "registrar",
        ]);
    }

    // Registrar IANA ID
    info.registrar_iana_id = extract_value(raw, &[
        "Registrar IANA ID:",
        "Registrar ID:",
        "sponsoring registrar iana id:",
        "iana_id:",
    ]);

    // Registrant
    info.registrant_name = extract_value(raw, &[
        "Registrant Name:",
        "registrant name:",
        "Registrant:",
        "registrant:",
    ]);
    info.registrant_org = extract_value(raw, &[
        "Registrant Organization:",
        "registrant organization:",
        "Registrant Org:",
        "org:",
        "organisation:",
        "Registrant Organisation:",
    ]);
    info.registrant_email = extract_value(raw, &[
        "Registrant Email:",
        "registrant email:",
        "Registrant E-mail:",
        "registrant e-mail:",
    ]);
    info.registrant_phone = extract_value(raw, &[
        "Registrant Phone:",
        "registrant phone:",
        "Registrant Telephone:",
        "registrant telephone:",
    ]);
    info.registrant_country = extract_value(raw, &[
        "Registrant Country:",
        "registrant country:",
        "country:",
        "Country:",
    ]);

    // Admin
    info.admin_name = extract_value(raw, &[
        "Admin Name:",
        "admin name:",
        "Administrative Contact:",
        "admin-c:",
    ]);
    info.admin_email = extract_value(raw, &[
        "Admin Email:",
        "admin email:",
        "Admin E-mail:",
        "admin e-mail:",
    ]);
    info.admin_org = extract_value(raw, &[
        "Admin Organization:",
        "admin organization:",
        "Admin Org:",
        "admin org:",
    ]);

    // Tech
    info.tech_name = extract_value(raw, &[
        "Tech Name:",
        "tech name:",
        "Technical Contact:",
        "tech-c:",
    ]);
    info.tech_email = extract_value(raw, &[
        "Tech Email:",
        "tech email:",
        "Tech E-mail:",
        "tech e-mail:",
    ]);

    // Abuse
    info.abuse_email = extract_value(raw, &[
        "Abuse Contact Email:",
        "abuse contact email:",
        "Abuse Email:",
        "abuse email:",
        "Abuse E-mail:",
        "abuse e-mail:",
        "Reseller Abuse Contact:",
    ]);

    // Name Servers
    info.name_servers = extract_multiline(raw, &[
        "Name Server:",
        "nserver:",
        "Nameserver:",
        "name server:",
    ]);
    if info.name_servers.is_empty() {
        info.name_servers = extract_multiline(raw, &["Name Server"]);
    }

    // Dates
    info.creation_date = extract_date(raw, &[
        "Creation Date:",
        "creation date:",
        "created:",
        "Created:",
        "Created On:",
        "Domain Registration Date:",
        "registered:",
        "Registered on:",
    ]);
    info.expiration_date = extract_date(raw, &[
        "Registry Expiry Date:",
        "registry expiry date:",
        "Expiration Date:",
        "expiration date:",
        "Expiry Date:",
        "expiry date:",
        "Expires:",
        "expires:",
        "Expire Date:",
        "paid-till:",
        "renewal date:",
        "Registry Expiry Date:",
    ]);
    info.updated_date = extract_date(raw, &[
        "Updated Date:",
        "updated date:",
        "Last Updated:",
        "last updated:",
        "Modified:",
        "modified:",
        "changed:",
        "last-modified:",
        "Last Update:",
        "last update:",
    ]);

    // DNSSEC
    info.dnssec = extract_value(raw, &[
        "DNSSEC:",
        "dnssec:",
        "DS Record:",
    ]);

    // Status codes
    info.status_codes = extract_multiline(raw, &[
        "Status:",
        "status:",
        "Domain Status:",
        "domain status:",
    ]);
    if info.status_codes.is_empty() && lower.contains("status:") {
        let re = Regex::new(r"(?m)^\s*[Ss]tatus:\s*(.+)$").ok();
        if let Some(re) = re {
            for cap in re.captures_iter(raw) {
                let val = cap[1].trim().to_string();
                if !val.is_empty() && !info.status_codes.contains(&val) {
                    info.status_codes.push(val);
                }
            }
        }
    }

    // Clean name servers - remove trailing dots and dedup
    info.name_servers = info.name_servers.iter()
        .map(|s| s.trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    info.name_servers.sort();
    info.name_servers.dedup();

    // Dedup status codes
    info.status_codes.sort();
    info.status_codes.dedup();

    // Clean emails
    info.registrant_email = info.registrant_email.map(clean_email);
    info.admin_email = info.admin_email.map(clean_email);
    info.tech_email = info.tech_email.map(clean_email);
    info.abuse_email = info.abuse_email.map(clean_email);

    // Redact personal emails (show only domain)
    if let Some(email) = &info.registrant_email {
        if is_redacted(email) || looks_like_privacy(email) {
            info.registrant_name = None;
        }
    }

    info
}

/// Parses RDAP JSON into a WhoisInfo structure, using vcardArray for entity details.
pub fn parse_rdap_to_whois(domain: &str, json: &serde_json::Value) -> WhoisInfo {
    let mut info = WhoisInfo {
        domain: domain.to_string(),
        source_server: Some("rdap.org".to_string()),
        ..Default::default()
    };

    // Events (creation, expiration, last changed)
    if let Some(events) = json["events"].as_array() {
        for ev in events {
            let action = ev["eventAction"].as_str().unwrap_or("");
            let date_str = ev["eventDate"].as_str().unwrap_or("");
            let dt = parse_rdap_date(date_str);
            match action {
                "registration" => info.creation_date = dt,
                "expiration" => info.expiration_date = dt,
                "last changed" => info.updated_date = dt,
                "last update of RDAP database" => {
                    if info.updated_date.is_none() {
                        info.updated_date = dt;
                    }
                }
                _ => {}
            }
        }
    }

    // Status
    if let Some(status) = json["status"].as_array() {
        for s in status {
            if let Some(val) = s.as_str() {
                info.status_codes.push(val.to_string());
            }
        }
    }

    // Name servers
    if let Some(ns) = json["nameservers"].as_array() {
        for n in ns {
            if let Some(lfh) = n["ldhName"].as_str() {
                info.name_servers.push(lfh.trim_end_matches('.').to_string());
            }
        }
    }

    // DNSSEC
    if let Some(dnssec) = json["secureDNS"].as_object() {
        if dnssec.get("delegationSigned").and_then(|v| v.as_bool()).unwrap_or(false) {
            info.dnssec = Some("signedDelegation".to_string());
        }
    }

    // Entities (registrar, registrant, admin, tech, abuse)
    if let Some(entities) = json["entities"].as_array() {
        for ent in entities {
            let roles: Vec<&str> = ent["roles"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let role = roles.first().copied().unwrap_or("");

            let name = ent["vcardArray"][1]
                .as_array()
                .and_then(|arr| {
                    arr.iter().find_map(|item| {
                        let item_arr = item.as_array()?;
                        if item_arr.first().and_then(|v| v.as_str()) == Some("fn") {
                            item_arr.get(3).and_then(|v| v.as_str())
                        } else {
                            None
                        }
                    })
                })
                .map(|s| s.to_string());

            let email = ent["vcardArray"][1]
                .as_array()
                .and_then(|arr| {
                    arr.iter().find_map(|item| {
                        let item_arr = item.as_array()?;
                        if item_arr.first().and_then(|v| v.as_str()) == Some("email") {
                            item_arr.get(3).and_then(|v| v.as_str())
                        } else {
                            None
                        }
                    })
                })
                .map(|s| s.to_string());

            match role {
                "registrar" => {
                    info.registrar = ent["name"].as_str().map(|s| s.to_string()).or(name);
                    if let Some(id) = ent["entities"]
                        .as_array()
                        .and_then(|arr| arr.first())
                        .and_then(|e| e["publicIds"].as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|pid| pid["identifier"].as_str())
                    {
                        info.registrar_iana_id = Some(id.to_string());
                    }
                }
                "registrant" => {
                    info.registrant_name = name;
                    info.registrant_email = email;
                    if let Some(org) = ent["vcardArray"][1].as_array().and_then(|arr| {
                        arr.iter().find_map(|item| {
                            let item_arr = item.as_array()?;
                            if item_arr.first().and_then(|v| v.as_str()) == Some("org") {
                                item_arr.get(3).and_then(|v| v.as_str())
                            } else {
                                None
                            }
                        })
                    }) {
                        info.registrant_org = Some(org.to_string());
                    }
                    if let Some(adr) = ent["vcardArray"][1].as_array().and_then(|arr| {
                        arr.iter().find_map(|item| {
                            let item_arr = item.as_array()?;
                            if item_arr.first().and_then(|v| v.as_str()) == Some("adr") {
                                item_arr.get(3).and_then(|v| v.as_array())
                            } else {
                                None
                            }
                        })
                    }) {
                        if adr.len() > 6 {
                            info.registrant_country = adr[6].as_str().map(|s| s.to_string());
                        }
                    }
                }
                "administrative" | "admin" => {
                    info.admin_name = name;
                    info.admin_email = email;
                }
                "technical" | "tech" => {
                    info.tech_name = name;
                    info.tech_email = email;
                }
                "abuse" => {
                    info.abuse_email = email;
                }
                _ => {}
            }
        }
    }

    info
}

/// Extracts a value from raw WHOIS text by searching for one of the given prefixes.
fn extract_value(raw: &str, prefixes: &[&str]) -> Option<String> {
    let lower = raw.to_lowercase();
    for prefix in prefixes {
        let lower_prefix = prefix.to_lowercase();
        if let Some(idx) = lower.find(&lower_prefix) {
            let line_start = raw[..idx].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_end = raw[idx..].find('\n').map(|i| idx + i).unwrap_or(raw.len());
            let line = &raw[line_start..line_end];
            let colon_pos = line.find(':').map(|i| i + 1).unwrap_or(0);
            let val = line[colon_pos..].trim().to_string();
            if !val.is_empty() && val != "?" && !val.contains("REDACTED") && !val.contains("PRIVACY") {
                return Some(val);
            }
        }
    }
    None
}

/// Extracts a value by scanning each line for a prefix (less strict matching).
fn extract_value_line(raw: &str, prefixes: &[&str]) -> Option<String> {
    for prefix in prefixes {
        let prefix_lower = prefix.to_lowercase();
        for line in raw.lines() {
            if line.to_lowercase().starts_with(&prefix_lower)
                || line.to_lowercase().contains(&format!("{}:", prefix_lower))
            {
                let colon_pos = line.find(':').map(|i| i + 1).unwrap_or(0);
                let val = line[colon_pos..].trim().to_string();
                if !val.is_empty() && val != "?" {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Extracts multi-line values (e.g., name servers, status codes) from raw WHOIS.
fn extract_multiline(raw: &str, prefixes: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    for prefix in prefixes {
        let lower_prefix = prefix.to_lowercase();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.to_lowercase().starts_with(&lower_prefix) {
                let start = prefix.len().min(trimmed.len());
                let val = trimmed[start..].trim().to_string();
                if !val.is_empty() && val != "?" {
                    values.push(val);
                }
            }
        }
    }
    values
}

/// Extracts a date value by finding a matching prefix and parsing it.
fn extract_date(raw: &str, prefixes: &[&str]) -> Option<NaiveDateTime> {
    let val = extract_value(raw, prefixes)?;
    parse_date_string(&val)
}

/// Parses a date string across multiple known WHOIS date formats.
pub(crate) fn parse_date_string(s: &str) -> Option<NaiveDateTime> {
    let s = s.trim();
    let formats = &[
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%S%.f%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%Y/%m/%d",
        "%d %b %Y %H:%M:%S",
        "%d %b %Y",
        "%d %B %Y %H:%M:%S",
        "%d %B %Y",
        "%B %d %Y",
        "%B %d %H:%M:%S %Y %Z",
        "%Y-%m-%dT%H:%M:%S.%f%:z",
        "%Y-%m-%d %H:%M:%S %Z",
        "%Y%m%d",
        "%Y-%m-%dT%H:%M:%S%:z",
        "%a %b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%S.%f%z",
    ];
    for fmt in formats {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
        // Try parsing just date
        if !fmt.contains("%H") && !fmt.contains("%M") {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, fmt) {
                return Some(d.and_hms_opt(0, 0, 0).unwrap());
            }
        }
    }
    // Try parsing with chrono's standard parser
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.naive_utc());
    }
    None
}

/// Parses an RDAP date string (delegates to the general date parser).
fn parse_rdap_date(s: &str) -> Option<NaiveDateTime> {
    parse_date_string(s)
}

/// Cleans an email string by trimming brackets and quotes.
fn clean_email(email: String) -> String {
    let email = email.trim().to_lowercase();
    let email = email.trim_start_matches('<').trim_end_matches('>').to_string();
    let email = email.trim_matches('"').to_string();
    email
}

/// Checks if an email address is redacted or privacy-protected.
fn is_redacted(email: &str) -> bool {
    let lower = email.to_lowercase();
    lower.contains("redacted")
        || lower.contains("privacy")
        || lower.contains("whoisguard")
        || lower.contains("domainsbyproxy")
        || lower.contains("@whois")
        || lower.contains("@privacy")
        || lower.contains("contact@")
        || lower.contains("noreply@")
        || lower.contains("no.reply@")
        || lower == "?"
}

/// Checks if an email domain looks like a privacy service.
fn looks_like_privacy(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let domain = parts[1].to_lowercase();
    domain.contains("privacy")
        || domain.contains("protect")
        || domain.contains("anonymize")
        || domain.contains("hide")
        || domain.contains("mask")
}
