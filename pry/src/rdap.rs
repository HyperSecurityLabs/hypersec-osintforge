/// RDAP (Registration Data Access Protocol) lookup for domains and IPs.
///
/// Queries RDAP servers from various TLD registries, parses the JSON response,
/// and extracts registrar, dates, contacts, name servers, DNSSEC, and statuses.
use crate::models::LookupResult;
use crate::stealth;
use std::net::IpAddr;
use std::time::Duration;

/// Map a TLD to its RDAP base URL.
fn base_url(tld: &str) -> Option<&'static str> {
    match tld {
        "com" | "net" => Some("https://rdap.verisign.com/com/v1"),
        "org" | "ngo" | "mobi" => Some("https://rdap.publicinterestregistry.org/rdap"),
        "in" => Some("https://rdap.registry.in"),
        "io" => Some("https://rdap.afilias.net/rdap"),
        "co" | "ly" => Some("https://rdap.nic.co"),
        "biz" => Some("https://rdap.nic.biz"),
        "info" => Some("https://rdap.afilias.net/rdap"),
        "uk" => Some("https://rdap.nic.uk"),
        "de" => Some("https://rdap.denic.de"),
        "eu" => Some("https://rdap.eu"),
        "us" => Some("https://rdap.nic.us"),
        "nl" => Some("https://rdap.domain-registry.nl"),
        "br" => Some("https://rdap.registro.br"),
        "au" => Some("https://rdap.auda.org.au"),
        "fr" => Some("https://rdap.nic.fr"),
        "ru" => Some("https://rdap.nic.ru"),
        "jp" => Some("https://rdap.nic.ad.jp"),
        "cn" => Some("https://rdap.cnnic.cn"),
        "cloud" => Some("https://rdap.nic.cloud"),
        "dev" | "app" => Some("https://rdap.nic.google"),
        "xyz" => Some("https://rdap.nic.xyz"),
        "me" => Some("https://rdap.nic.me"),
        "cc" => Some("https://rdap.nic.cc"),
        "tv" => Some("https://rdap.nic.tv"),
        "name" => Some("https://rdap.nic.name"),
        "pro" => Some("https://rdap.nic.pro"),
        _ => None,
    }
}

/// Build the ARIN RDAP URL for an IP address lookup.
fn ip_url(ip: &str) -> String {
    format!("https://rdap.arin.net/registry/ip/{}", ip)
}

/// Parse an RDAP domain response JSON into a LookupResult.
fn parse_rdap_domain(json: &serde_json::Value) -> LookupResult {
    let mut r = LookupResult::default();

    // Handle: extract event dates (registration, expiration, last changed)
    if let Some(events) = json.get("events").and_then(|e| e.as_array()) {
        for event in events {
            let action = event
                .get("eventAction")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let date = event
                .get("eventDate")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match action {
                "registration" => r.creation_date = Some(date.to_string()),
                "expiration" => r.expiration_date = Some(date.to_string()),
                "last changed" => r.updated_date = Some(date.to_string()),
                _ => {}
            }
        }
    }

    // Handle: extract entity information (registrar, abuse, registrant)
    if let Some(entities) = json.get("entities").and_then(|e| e.as_array()) {
        for entity in entities {
            let roles: Vec<&str> = entity
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let name = entity
                .get("vcardArray")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter().find_map(|item| {
                        item.as_array().and_then(|fields| {
                            if fields.first().and_then(|f| f.as_str()) == Some("fn") {
                                fields.get(3).and_then(|v| v.as_str())
                            } else {
                                None
                            }
                        })
                    })
                })
                .unwrap_or("");

            // Branch: extract registrar name
            if (roles.contains(&"registrar") || roles.contains(&"maintainer"))
                && r.registrar.is_none()
                && !name.is_empty()
            {
                r.registrar = Some(name.to_string());
            }

            // Branch: extract abuse / administrative email
            if roles.contains(&"abuse") || roles.contains(&"administrative") {
                let email = entity
                    .get("vcardArray")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        arr.iter().find_map(|item| {
                            item.as_array().and_then(|fields| {
                                if fields.first().and_then(|f| f.as_str())
                                    == Some("email")
                                {
                                    fields.get(3).and_then(|v| v.as_str())
                                } else {
                                    None
                                }
                            })
                        })
                    });
                if let Some(e) = email {
                    if r.abuse_email.is_none() {
                        r.abuse_email = Some(e.to_string());
                    }
                }
            }

            // Branch: extract registrant name
            if roles.contains(&"registrant") && r.registrant_org.is_none() {
                r.registrant_org = Some(name.to_string());
            }
        }
    }

    // Handle: extract name servers
    if let Some(ns) = json.get("nameservers").and_then(|n| n.as_array()) {
        for ns_entry in ns {
            if let Some(lfh) = ns_entry
                .get("ldhName")
                .and_then(|v| v.as_str())
            {
                if !r.name_servers.contains(&lfh.to_string()) {
                    r.name_servers.push(lfh.to_string());
                }
            }
        }
    }

    // Handle: extract domain statuses
    if let Some(status) = json.get("status").and_then(|s| s.as_array()) {
        for st in status {
            if let Some(s) = st.as_str() {
                if !r.domain_status.contains(&s.to_string()) {
                    r.domain_status.push(s.to_string());
                }
            }
        }
    }

    // Handle: extract DNSSEC information
    if let Some(sdns) = json.get("secureDNS") {
        if let Some(ds_data) = sdns.get("dsData").and_then(|d| d.as_array()) {
            if !ds_data.is_empty() {
                r.dnssec = Some("signedDelegation".to_string());
            }
        }
        if let Some(flags) = sdns.get("delegationSigned").and_then(|d| d.as_bool()) {
            if flags && r.dnssec.is_none() {
                r.dnssec = Some("signed".to_string());
            }
        }
    }

    // Handle: extract port43 WHOIS server as fallback registrar
    if let Some(port43) = json.get("port43").and_then(|v| v.as_str()) {
        if !port43.is_empty() && r.registrar.is_none() {
            r.registrar = Some(port43.to_string());
        }
    }

    r.source = "rdap".to_string();
    r
}

/// Parse an RDAP IP address response JSON into a LookupResult.
fn parse_rdap_ip(json: &serde_json::Value) -> LookupResult {
    let mut r = LookupResult::default();

    // Handle: extract creation date for the IP block
    if let Some(events) = json.get("events").and_then(|e| e.as_array()) {
        for event in events {
            let action = event
                .get("eventAction")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let date = event
                .get("eventDate")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if action == "registration" && r.creation_date.is_none() {
                r.creation_date = Some(date.to_string());
            }
        }
    }

    // Handle: extract entity information (registrant, abuse, country)
    if let Some(entities) = json.get("entities").and_then(|e| e.as_array()) {
        for entity in entities {
            let roles: Vec<&str> = entity
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let name = entity
                .get("vcardArray")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter().find_map(|item| {
                        item.as_array().and_then(|fields| {
                            if fields.first().and_then(|f| f.as_str()) == Some("fn") {
                                fields.get(3).and_then(|v| v.as_str())
                            } else {
                                None
                            }
                        })
                    })
                })
                .unwrap_or("");

            // Branch: extract registrant
            if roles.contains(&"registrant") && r.registrant_org.is_none() {
                r.registrant_org = Some(name.to_string());
            }

            // Branch: extract abuse / administrative email
            if roles.contains(&"abuse") || roles.contains(&"administrative") {
                let email = entity
                    .get("vcardArray")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        arr.iter().find_map(|item| {
                            item.as_array().and_then(|fields| {
                                if fields.first().and_then(|f| f.as_str())
                                    == Some("email")
                                {
                                    fields.get(3).and_then(|v| v.as_str())
                                } else {
                                    None
                                }
                            })
                        })
                    });
                if let Some(e) = email {
                    if r.abuse_email.is_none() {
                        r.abuse_email = Some(e.to_string());
                    }
                }
            }

            // Branch: extract country from address fields
            let country = entity
                .get("vcardArray")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter().find_map(|item| {
                        item.as_array().and_then(|fields| {
                            if fields.first().and_then(|f| f.as_str()) == Some("adr") {
                                fields.get(3).and_then(|v| v.as_array())
                                    .and_then(|adr_fields| adr_fields.get(6))
                                    .and_then(|v| v.as_str())
                            } else {
                                None
                            }
                        })
                    })
                });
            if let Some(c) = country {
                if r.registrant_country.is_none() {
                    r.registrant_country = Some(c.to_string());
                }
            }
        }
    }

    r.source = "rdap".to_string();
    r
}

/// Perform an RDAP lookup for a domain or IP address.
pub async fn lookup(target: &str, proxy: Option<&str>) -> LookupResult {
    let target = target.trim().to_lowercase();
    // Step: determine the RDAP URL based on target type
    let url = if let Ok(ip) = target.parse::<IpAddr>() {
        ip_url(&ip.to_string())
    } else {
        let tld = target.rsplit('.').next().unwrap_or("");
        match base_url(tld) {
            Some(base) => format!("{}/domain/{}", base, target),
            None => {
                let mut r = LookupResult::new(&target);
                r.error = Some(format!("No RDAP server known for .{}", tld));
                return r;
            }
        }
    };

    // Step: build the HTTP client with timeout and random User-Agent
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent(stealth::random_ua())
        .danger_accept_invalid_certs(false);

    // Branch: apply proxy if provided
    if let Some(proxy_url) = proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            let mut r = LookupResult::new(&target);
            r.error = Some(format!("HTTP client: {}", e));
            return r;
        }
    };

    // Step: send the RDAP request
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            let mut r = LookupResult::new(&target);
            r.error = Some(format!("RDAP request failed: {}", e));
            return r;
        }
    };

    // Check: verify success status
    let status = resp.status();
    if !status.is_success() {
        let mut r = LookupResult::new(&target);
        r.error = Some(format!("RDAP HTTP {}", status));
        return r;
    }

    // Step: parse the JSON response body
    let body: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            let mut r = LookupResult::new(&target);
            r.error = Some(format!("RDAP parse: {}", e));
            return r;
        }
    };

    // Dispatch: parse based on target type (domain vs IP)
    let mut result = if target.parse::<IpAddr>().is_ok() {
        parse_rdap_ip(&body)
    } else {
        parse_rdap_domain(&body)
    };
    result.target = target;
    result
}
