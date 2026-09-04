/// WHOIS lookup engine for PRY.
///
/// Connects to WHOIS servers via TCP port 43, sends queries, parses responses,
/// and follows referral WHOIS servers for more detailed data.
use crate::models::LookupResult;
use std::net::IpAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Determine the WHOIS server for a given TLD or IP address.
fn server_for(target: &str) -> &str {
    if target.parse::<IpAddr>().is_ok() {
        return "whois.arin.net";
    }
    let tld = target.rsplit('.').next().unwrap_or("");
    match tld {
        "com" | "net" | "edu" | "gov" => "whois.verisign-grs.com",
        "org" | "ngo" | "mobi" => "whois.pir.org",
        "in" => "whois.registry.in",
        "io" => "whois.nic.io",
        "co" | "ly" => "whois.nic.co",
        "biz" => "whois.nic.biz",
        "info" => "whois.nic.info",
        "xyz" => "whois.nic.xyz",
        "cloud" => "whois.nic.cloud",
        "dev" | "app" => "whois.nic.google",
        "uk" => "whois.nic.uk",
        "de" => "whois.denic.de",
        "eu" => "whois.eu",
        "us" => "whois.nic.us",
        "ru" => "whois.tcinet.ru",
        "br" => "whois.registro.br",
        "au" => "whois.auda.org.au",
        "fr" => "whois.nic.fr",
        "jp" => "whois.jprs.jp",
        "cn" => "whois.cnnic.cn",
        "nl" => "whois.domain-registry.nl",
        "it" => "whois.nic.it",
        "me" => "whois.nic.me",
        "tv" => "whois.nic.tv",
        "cc" => "whois.nic.cc",
        "ws" => "whois.nic.ws",
        "name" => "whois.nic.name",
        "pro" => "whois.nic.pro",
        "aero" => "whois.information.aero",
        "jobs" => "whois.nic.jobs",
        "travel" => "whois.nic.travel",
        "asia" => "whois.nic.asia",
        "cat" => "whois.nic.cat",
        "coop" => "whois.nic.coop",
        "int" => "whois.iana.org",
        "museum" => "whois.museum",
        "tel" => "whois.nic.tel",
        "post" => "whois.upu.int",
        "xxx" => "whois.nic.xxx",
        "blue" | "pink" | "red" | "green" | "yellow" | "purple" => "whois.afilias.net",
        "guru" | "club" | "life" | "today" | "tech" | "online" | "site" | "website"
        | "space" | "press" | "host" | "agency" | "email" | "tools" | "world" | "center"
        | "global" | "company" | "directory" | "plus" | "tips" | "zone"
        | "link" | "click" | "country" | "party" | "date" | "trade" | "win" | "review"
        | "kim" | "men" | "loan" => "whois.donuts.co",
        "icu" | "cyou" => "whois.nic.icu",
        _ => "whois.iana.org",
    }
}

/// Send a WHOIS query to a server and read the full response.
async fn query(server: &str, query: &str) -> Result<String, String> {
    let addr = format!("{}:43", server);
    // Step: connect to TCP port 43 with 15s timeout
    let mut stream = timeout(Duration::from_secs(15), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Connection timeout to {}", server))?
        .map_err(|e| format!("Connection failed to {}: {}", server, e))?;

    // Step: send query with CRLF termination
    let q = format!("{}\r\n", query);
    stream
        .write_all(q.as_bytes())
        .await
        .map_err(|e| format!("Write error to {}: {}", server, e))?;

    // Step: read response in chunks
    let mut response = String::new();
    let mut buf = [0u8; 8192];
    // Loop: read until the server closes the connection
    loop {
        let n = timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .map_err(|_| format!("Read timeout from {}", server))?
            .map_err(|e| format!("Read error from {}: {}", server, e))?;
        // Check: end of stream
        if n == 0 {
            break;
        }
        response.push_str(&String::from_utf8_lossy(&buf[..n]));
    }

    Ok(response)
}

/// Parse raw WHOIS text into a structured LookupResult.
fn parse(raw: &str) -> LookupResult {
    let mut r = LookupResult::default();
    // Loop: parse each line
    for line in raw.lines() {
        let line = line.trim();
        // Check: skip comments and empty lines
        if line.is_empty()
            || line.starts_with('%')
            || line.starts_with('#')
            || line.starts_with(">>>")
            || line.starts_with("<<<")
        {
            continue;
        }
        // Step: split key:value
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            continue;
        }
        let key = parts[0].trim().to_lowercase();
        let value = parts[1].trim().to_string();
        // Check: skip empty values
        if value.is_empty() {
            continue;
        }
        // Dispatch: map key to the appropriate field
        match key.as_str() {
            "registrar" | "registrar name" | "sponsoring registrar" => {
                r.registrar = Some(value);
            }
            "registrar url" | "registrar_url" | "url" => {
                r.registrar_url = Some(value);
            }
            "registrar iana id" | "registrar_iana_id" | "iana id" => {
                r.registrar_iana_id = Some(value);
            }
            "domain name" | "domain" | "domain_id" | "domain id" | "domain uid"
            | "roid" => {
                r.domain_id = Some(value);
            }
            "registry domain id" | "registry domain_id" => {
                r.domain_registry_id = Some(value);
            }
            "creation date" | "creation_date" | "domain created" | "created date"
            | "created" | "registered" | "regdate" => {
                r.creation_date = Some(value);
            }
            "expiration date" | "expiration_date" | "domain expires" | "expiry date"
            | "expire" | "paid till" | "registry expiry date" => {
                r.expiration_date = Some(value);
            }
            "updated date" | "updated_date" | "last updated" | "modified"
            | "last-modified" | "changed" | "last update" => {
                r.updated_date = Some(value);
            }
            "name server" | "nserver" | "nameserver" => {
                let ns = value.split_whitespace().next().unwrap_or(&value).to_string();
                if !r.name_servers.contains(&ns) {
                    r.name_servers.push(ns);
                }
            }
            "registrant name" | "registrant_name" => {
                r.registrant_name = Some(value);
            }
            "registrant organisation" | "registrant organization" | "org"
            | "organisation" | "orgname" => {
                r.registrant_org = Some(value);
            }
            "registrant email" | "registrant_email" => {
                r.registrant_email = Some(value);
            }
            "registrant phone" | "registrant_phone" | "registrant telephone"
            | "registrant tel" => {
                r.registrant_phone = Some(value);
            }
            "registrant street" | "registrant_street" => {
                r.registrant_street = Some(value);
            }
            "registrant city" | "registrant_city" => {
                r.registrant_city = Some(value);
            }
            "registrant state" | "registrant_state" | "registrant province"
            | "registrant state/province" => {
                r.registrant_state = Some(value);
            }
            "registrant country" | "country" => {
                r.registrant_country = Some(value);
            }
            "registrant postal" | "registrant_zip" | "registrant postal code"
            | "registrant zip" => {
                r.registrant_zip = Some(value);
            }
            "admin organisation" | "admin organization" | "admin org" => {
                r.admin_org = Some(value);
            }
            "admin email" | "admin_email" => {
                r.admin_email = Some(value);
            }
            "admin phone" | "admin_phone" | "admin telephone" | "admin tel" => {
                r.admin_phone = Some(value);
            }
            "tech organisation" | "tech organization" | "tech org" => {
                r.tech_org = Some(value);
            }
            "tech name" | "tech_name" => {
                r.tech_name = Some(value);
            }
            "tech street" | "tech_street" => {
                r.tech_street = Some(value);
            }
            "tech city" | "tech_city" => {
                r.tech_city = Some(value);
            }
            "tech state" | "tech_state" | "tech state/province" => {
                r.tech_state = Some(value);
            }
            "tech postal code" | "tech postal" | "tech_zip" | "tech zip" => {
                r.tech_zip = Some(value);
            }
            "tech country" | "tech_country" => {
                r.tech_country = Some(value);
            }
            "tech email" | "tech_email" => {
                r.tech_email = Some(value);
            }
            "tech phone" | "tech_phone" | "tech telephone" | "tech tel" => {
                r.tech_phone = Some(value);
            }
            "abuse email" | "abuse-mailbox" | "abuse_contact"
            | "abuse contact email" | "orgabuseemail" | "orgabusemail" => {
                r.abuse_email = Some(value);
            }
            "dnssec" | "dnssec signed" | "ds record" | "ds data" => {
                r.dnssec = Some(value);
            }
            "domain status" | "status" | "domain-status" => {
                let st = value.split_whitespace().next().unwrap_or(&value).to_string();
                if !r.domain_status.contains(&st) {
                    r.domain_status.push(st);
                }
            }
            _ => {}
        }
    }
    r
}

/// Search a WHOIS response for a referral WHOIS server.
fn find_referral(response: &str) -> Option<String> {
    // Loop: check each line for referral patterns
    for line in response.lines() {
        let l = line.trim().to_lowercase();
        if l.contains("whois server:")
            || l.contains("whoisserver:")
            || l.contains("referral whois server:")
            || l.contains("registrar whois:")
        {
            if let Some(val) = line.split(':').nth(1) {
                let server = val.trim().trim_matches('"').trim();
                let server = server.split(':').next().unwrap_or(server).trim();
                // Check: avoid known non-useful servers
                if !server.is_empty()
                    && !server.contains("whois.arin.net")
                    && !server.contains("whois.iana.org")
                    && server.contains('.')
                {
                    return Some(server.to_string());
                }
            }
        }
    }
    None
}

/// Perform a full WHOIS lookup for a domain or IP address.
///
/// Queries the appropriate WHOIS server, parses the response,
/// and follows referral servers for additional detail.
pub async fn lookup(target: &str) -> LookupResult {
    let target = target.trim().to_lowercase();
    let server = server_for(&target);
    let q = &target;

    // Step: query the primary WHOIS server
    match self::query(server, q).await {
        Ok(response) => {
            let mut result = parse(&response);
            result.source = "whois".to_string();
            result.raw_whois = response.clone();

            // Step: follow referral WHOIS server if present
            if let Some(ref_server) = find_referral(&response) {
                match self::query(&ref_server, q).await {
                    Ok(ref_response) => {
                        result.raw_referral = ref_response.clone();
                        let parsed = parse(&ref_response);
                        result.merge(&parsed);
                    }
                    Err(e) => {
                        result.error = Some(format!("Referral WHOIS ({}): {}", ref_server, e));
                    }
                }
            }

            result
        }
        Err(e) => {
            let mut result = LookupResult::new(&target);
            result.error = Some(e);
            result
        }
    }
}
