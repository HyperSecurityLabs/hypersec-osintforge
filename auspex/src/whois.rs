/// Auspex — WHOIS Lookup Engine
///
/// Connects to authoritative WHOIS servers via TCP port 43 for each TLD,
/// handles referral to registrar WHOIS servers, and merges RDAP data
/// to fill gaps in the structured result.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::WhoisInfo;
use crate::parser;
use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Maps TLDs to their authoritative WHOIS servers.
static TLD_SERVERS: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("com", "whois.verisign-grs.com");
    m.insert("net", "whois.verisign-grs.com");
    m.insert("org", "whois.pir.org");
    m.insert("gov", "whois.dotgov.gov");
    m.insert("edu", "whois.educause.edu");
    m.insert("mil", "whois.nic.mil");
    m.insert("int", "whois.iana.org");
    m.insert("biz", "whois.nic.biz");
    m.insert("info", "whois.nic.info");
    m.insert("name", "whois.nic.name");
    m.insert("pro", "whois.nic.pro");
    m.insert("mobi", "whois.nic.mobi");
    m.insert("asia", "whois.nic.asia");
    m.insert("tel", "whois.nic.tel");
    m.insert("xxx", "whois.nic.xxx");
    m.insert("aero", "whois.information.aero");
    m.insert("coop", "whois.nic.coop");
    m.insert("museum", "whois.museum");
    m.insert("travel", "whois.nic.travel");
    m.insert("jobs", "whois.nic.jobs");
    m.insert("cat", "whois.nic.cat");
    m.insert("post", "whois.nic.post");
    m.insert("eu", "whois.eu");
    m.insert("uk", "whois.nic.uk");
    m.insert("de", "whois.denic.de");
    m.insert("fr", "whois.nic.fr");
    m.insert("jp", "whois.jprs.jp");
    m.insert("cn", "whois.cnnic.cn");
    m.insert("ru", "whois.tcinet.ru");
    m.insert("au", "whois.auda.org.au");
    m.insert("ca", "whois.ca.fury.ca");
    m.insert("it", "whois.nic.it");
    m.insert("nl", "whois.domain-registry.nl");
    m.insert("br", "whois.registro.br");
    m.insert("pl", "whois.dns.pl");
    m.insert("es", "whois.nic.es");
    m.insert("ch", "whois.nic.ch");
    m.insert("se", "whois.iis.se");
    m.insert("no", "whois.norid.no");
    m.insert("dk", "whois.punktum.dk");
    m.insert("fi", "whois.fi");
    m.insert("be", "whois.dns.be");
    m.insert("at", "whois.nic.at");
    m.insert("io", "whois.nic.io");
    m.insert("co", "whois.nic.co");
    m.insert("me", "whois.nic.me");
    m.insert("tv", "whois.nic.tv");
    m.insert("cc", "whois.nic.cc");
    m.insert("ws", "whois.nic.ws");
    m.insert("bz", "whois.nic.bz");
    m.insert("nu", "whois.iis.nu");
    m.insert("li", "whois.nic.li");
    m.insert("xyz", "whois.nic.xyz");
    m.insert("club", "whois.nic.club");
    m.insert("online", "whois.nic.online");
    m.insert("site", "whois.nic.site");
    m.insert("top", "whois.nic.top");
    m.insert("wang", "whois.nic.wang");
    m.insert("press", "whois.nic.press");
    m.insert("tech", "whois.nic.tech");
    m.insert("space", "whois.nic.space");
    m.insert("store", "whois.nic.store");
    m.insert("link", "whois.uniregistry.net");
    m.insert("click", "whois.uniregistry.net");
    m.insert("uno", "whois.nic.uno");
    m.insert("email", "whois.nic.email");
    m.insert("today", "whois.nic.today");
    m.insert("ltd", "whois.nic.ltd");
    m.insert("live", "whois.nic.live");
    m.insert("life", "whois.nic.life");
    m.insert("world", "whois.nic.world");
    m.insert("zone", "whois.nic.zone");
    m.insert("guru", "whois.nic.guru");
    m.insert("app", "whois.nic.google");
    m.insert("dev", "whois.nic.google");
    m.insert("page", "whois.nic.google");
    m.insert("ai", "whois.nic.ai");
    m.insert("ly", "whois.nic.ly");
    m.insert("sg", "whois.sgnic.sg");
    m.insert("hk", "whois.hkirc.hk");
    m.insert("tw", "whois.twnic.net");
    m.insert("kr", "whois.kr");
    m.insert("in", "whois.registry.in");
    m.insert("mx", "whois.mx");
    m.insert("ar", "whois.nic.ar");
    m.insert("nz", "whois.srs.net.nz");
    m.insert("za", "whois.registry.net.za");
    m.insert("il", "whois.isoc.org.il");
    m.insert("ae", "whois.aeda.net.ae");
    m.insert("sa", "whois.nic.net.sa");
    m.insert("pk", "whois.pknic.pk");
    m.insert("ph", "whois.ph");
    m.insert("vn", "whois.vnnic.vn");
    m.insert("th", "whois.thnic.co.th");
    m.insert("id", "whois.id");
    m.insert("my", "whois.mynic.my");
    m.insert("ro", "whois.rotld.ro");
    m.insert("hu", "whois.nic.hu");
    m.insert("cz", "whois.nic.cz");
    m.insert("sk", "whois.sk-nic.sk");
    m.insert("bg", "whois.register.bg");
    m.insert("gr", "whois.gr");
    m.insert("ie", "whois.iedr.ie");
    m.insert("pt", "whois.dns.pt");
    m.insert("lt", "whois.domreg.lt");
    m.insert("lv", "whois.nic.lv");
    m.insert("ee", "whois.tld.ee");
    m.insert("ua", "whois.ua");
    m.insert("by", "whois.cctld.by");
    m.insert("kz", "whois.nic.kz");
    m.insert("ir", "whois.nic.ir");
    m.insert("sa", "whois.nic.net.sa");
    m
});

/// Extracts the TLD from a domain string.
fn extract_tld(domain: &str) -> &str {
    let domain = domain.trim_end_matches('.');
    domain.rsplit('.').next().unwrap_or(domain)
}

/// Finds the authoritative WHOIS server for a given domain.
fn find_whois_server(domain: &str) -> Option<&'static str> {
    let tld = extract_tld(domain);
    TLD_SERVERS.get(tld).copied()
}

/// Checks the raw WHOIS response for a referral to a registrar WHOIS server.
fn get_referral_server(raw: &str) -> Option<String> {
    for line in raw.lines() {
        let lower = line.trim().to_lowercase();
        if let Some(val) = lower.strip_prefix("whois server:") {
            let server = val.trim();
            if !server.is_empty() && server != "whois.verisign-grs.com" {
                return Some(server.to_string());
            }
        }
        if let Some(val) = lower.strip_prefix("whois server name:") {
            let server = val.trim();
            if !server.is_empty() {
                return Some(server.to_string());
            }
        }
        if lower.contains("whois server:") && !lower.contains("whois server: whois.verisign-grs.com") {
            if let Some(idx) = lower.find("whois server:") {
                let rest = &lower[idx + 13..];
                let server = rest.trim().trim_matches(':').trim();
                if !server.is_empty() {
                    return Some(server.to_string());
                }
            }
        }
    }
    None
}

/// Connects to a WHOIS server on port 43 and sends a domain query.
async fn query_whois(domain: &str, server: &str) -> Result<String, String> {
    let addr = format!("{}:43", server);
    let stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Connection to {} timed out", server))?
        .map_err(|e| format!("Failed to connect to {}: {}", server, e))?;

    let mut reader = BufReader::new(stream);
    let query = format!("{}\r\n", domain);
    reader
        .write_all(query.as_bytes())
        .await
        .map_err(|e| format!("Write error to {}: {}", server, e))?;
    reader
        .shutdown()
        .await
        .map_err(|e| format!("Shutdown error: {}", e))?;

    let mut raw = String::new();
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = reader
            .read_line(&mut buf)
            .await
            .map_err(|e| format!("Read error from {}: {}", server, e))?;
        if n == 0 {
            break;
        }
        raw.push_str(&buf);
    }

    if raw.is_empty() {
        return Err(format!("Empty response from {}", server));
    }

    // Check for not-found indicators
    if raw.to_lowercase().contains("no match for")
        || raw.to_lowercase().contains("not found")
        || raw.to_lowercase().contains("no data found")
        || raw.to_lowercase().contains("domain not found")
        || raw.to_lowercase().contains("status: free")
    {
        return Err("Domain not registered".to_string());
    }

    Ok(raw)
}

/// Performs a full WHOIS lookup for the given domain.
///
/// Queries the TLD WHOIS server, follows referrals, and merges RDAP
/// data to provide the most complete result possible.
pub async fn lookup(domain: &str) -> Option<WhoisInfo> {
    let clean = domain.trim().trim_end_matches('.').to_lowercase();

    // Try RDAP first for structured data
    let rdap_result = rdap_lookup(&clean).await;

    // Find and query the WHOIS server
    let whois_server = match find_whois_server(&clean) {
        Some(s) => s,
        None => "whois.iana.org",
    };

    let raw = match query_whois(&clean, whois_server).await {
        Ok(r) => r,
        Err(_) => {
            // Fall back to RDAP if WHOIS failed
            if let Some(rdap_info) = rdap_result {
                return Some(rdap_info);
            }
            return None;
        }
    };

    // Follow referral to registrar WHOIS if available
    let final_raw = if let Some(referral) = get_referral_server(&raw) {
        match query_whois(&clean, &referral).await {
            Ok(detailed) => detailed,
            Err(_) => raw,
        }
    } else {
        raw
    };

    let mut info = parser::parse_whois(&clean, &final_raw, whois_server);

    // Merge RDAP data to fill gaps
    if let Some(rdap) = rdap_result {
        if info.registrar.is_none() && rdap.registrar.is_some() {
            info.registrar = rdap.registrar;
        }
        if info.creation_date.is_none() && rdap.creation_date.is_some() {
            info.creation_date = rdap.creation_date;
        }
        if info.expiration_date.is_none() && rdap.expiration_date.is_some() {
            info.expiration_date = rdap.expiration_date;
        }
        if info.updated_date.is_none() && rdap.updated_date.is_some() {
            info.updated_date = rdap.updated_date;
        }
        if info.name_servers.is_empty() && !rdap.name_servers.is_empty() {
            info.name_servers = rdap.name_servers;
        }
        if info.dnssec.is_none() && rdap.dnssec.is_some() {
            info.dnssec = rdap.dnssec;
        }
        if info.status_codes.is_empty() && !rdap.status_codes.is_empty() {
            info.status_codes = rdap.status_codes;
        }
    }

    Some(info)
}

/// Performs an RDAP lookup specifically for WHOIS data merging.
async fn rdap_lookup(domain: &str) -> Option<WhoisInfo> {
    let url = format!("https://rdap.org/domain/{}", domain);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent(crate::stealth::random_ua())
        .build()
        .ok()?;

    let resp = client.get(&url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }

    let json: serde_json::Value = resp.json().await.ok()?;
    Some(parser::parse_rdap_to_whois(domain, &json))
}
