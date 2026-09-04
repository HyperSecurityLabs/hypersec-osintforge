/// IdentifyNet — IP Intelligence & Geolocation Engine
///
/// Version: 4.0.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod asn;
mod display;
mod dns;
mod geo;
mod http;
mod models;
mod portscan;
mod stealth;
mod updatedb;
mod whois;

use clap::Parser;
use colored::*;
use display::{banner, TOKYO_BLUE, TOKYO_PINK};
use models::IdentifyResult;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

/// Default filename for the GeoLite2 City database.
const GEO_DB: &str = "GeoLite2-City.mmdb";
/// Default filename for the GeoLite2 ASN database.
const ASN_DB: &str = "GeoLite2-ASN.mmdb";

/// Command-line arguments for identifynet.
#[derive(Parser)]
#[command(name = "identifynet")]
#[command(version = "4.0.0")]
#[command(about = "IdentifyNet — IP intelligence and geolocation profiler")]
struct Cli {
    /// Target IP address or domain name.
    target: Option<String>,

    /// Output results as JSON.
    #[arg(short = 'j', long)]
    json: bool,

    /// Write JSON output to a file.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Skip TCP port scanning.
    #[arg(short = 'p', long)]
    no_portscan: bool,

    /// Skip WHOIS lookup.
    #[arg(short = 'w', long)]
    no_whois: bool,

    /// Path to directory containing GeoIP databases.
    #[arg(long)]
    db_path: Option<PathBuf>,

    /// Look up your own public IP instead of a target.
    #[arg(short = 'm', long)]
    my_ip: bool,

    /// MaxMind license key for database downloads.
    #[arg(long)]
    maxmind_key: Option<String>,

    /// HTTP/SOCKS proxy URL.
    #[arg(short = 'P', long)]
    proxy: Option<String>,

    /// Maximum jitter delay in milliseconds (0 = disabled).
    #[arg(long, default_value = "0")]
    jitter: u64,
}

/// Process a single target through all intelligence modules.
async fn process_target(
    target: String,
    db_path: &Path,
    no_portscan: bool,
    no_whois: bool,
) -> IdentifyResult {
    let start = Instant::now();
    let mut result = IdentifyResult {
        target: target.clone(),
        ..Default::default()
    };

    // Step: resolve target to an IP address
    let ip: IpAddr = if let Ok(ip) = target.parse::<IpAddr>() {
        // Branch: target is already a raw IP
        ip
    } else if let Ok(mut addrs) = tokio::net::lookup_host((target.as_str(), 0)).await {
        // Branch: target is a domain, perform DNS resolution
        match addrs.next() {
            Some(addr) => addr.ip(),
            None => {
                result.error = Some("DNS resolution failed".to_string());
                return result;
            }
        }
    } else {
        result.error = Some("DNS resolution failed".to_string());
        return result;
    };

    result.ip = Some(ip.to_string());

    // Step: geolocation lookup
    let t0 = Instant::now();
    result.geo = geo::lookup(ip, db_path);
    result.timing.geo_ms = t0.elapsed().as_millis() as u64;

    // Step: ASN lookup
    let t0 = Instant::now();
    result.asn = asn::lookup(ip, db_path);
    result.timing.asn_ms = t0.elapsed().as_millis() as u64;

    // Step: concurrent DNS, WHOIS, and port scan
    let t0 = Instant::now();
    let dns_fut = dns_info(ip, &target);

    let whois_fut: tokio::task::JoinHandle<Option<models::WhoisInfo>> =
        tokio::spawn(async move { whois::lookup(ip).await });
    let port_fut: tokio::task::JoinHandle<Option<models::PortScanInfo>> = if !no_portscan {
        tokio::spawn(async move { portscan::scan(ip).await })
    } else {
        tokio::spawn(async { None })
    };

    // Handle: collect DNS results
    let dns_r = dns_fut.await;
    result.dns = Some(dns_r);
    result.timing.dns_ms = t0.elapsed().as_millis() as u64;

    // Branch: collect WHOIS results (if enabled)
    if !no_whois {
        result.whois = whois_fut.await.ok().flatten();
    }
    // Branch: collect port scan results (if enabled)
    if !no_portscan {
        result.ports = port_fut.await.ok().flatten();
    }

    result.timing.total_ms = start.elapsed().as_millis() as u64;
    result
}

/// Gather DNS information (PTR, MX, NS, TXT) for an IP/domain.
async fn dns_info(ip: IpAddr, target: &str) -> models::DnsInfo {
    let ptr = dns::ptr_lookup(ip).await;

    // Step: determine the domain to query for records
    let domain = if target.parse::<IpAddr>().is_ok() {
        ptr.as_deref().unwrap_or(target)
    } else {
        target
    };
    let domain_clean = domain.trim_end_matches('.');

    // Step: concurrent MX, NS, TXT lookups
    let (mx, ns, txt) = tokio::join!(
        dns::mx_lookup(domain_clean),
        dns::ns_lookup(domain_clean),
        dns::txt_lookup(domain_clean),
    );

    models::DnsInfo { ptr, mx, ns, txt }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Step: print banner unless JSON mode
    if !args.json {
        banner();
    }

    // Step: resolve database directory
    let db_path = args
        .db_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));

    let geo_db = db_path.join(GEO_DB);
    let asn_db = db_path.join(ASN_DB);

    // Step: check for MaxMind license key
    let env_key = std::env::var("MAXMIND_LICENSE_KEY").ok();
    let license_key = args
        .maxmind_key
        .as_deref()
        .or(env_key.as_deref());

    // Step: ensure databases exist (download if needed)
    let (geo_status, asn_status) = updatedb::ensure(&geo_db, &asn_db, license_key);

    // Handle: display database status messages
    if !args.json {
        match geo_status {
            updatedb::DbStatus::Downloaded => {
                println!(
                    "  {} {}",
                    "✓".color(TOKYO_PINK).bold(),
                    "GeoLite2-City.mmdb downloaded".color(TOKYO_BLUE)
                );
            }
            updatedb::DbStatus::Missing(msg) => {
                println!(
                    "  {} {}",
                    "⚠".color(TOKYO_PINK).bold(),
                    msg.color(TOKYO_BLUE)
                );
            }
            _ => {}
        }
        match asn_status {
            updatedb::DbStatus::Downloaded => {
                println!(
                    "  {} {}",
                    "✓".color(TOKYO_PINK).bold(),
                    "GeoLite2-ASN.mmdb downloaded".color(TOKYO_BLUE)
                );
            }
            updatedb::DbStatus::Missing(msg) => {
                println!(
                    "  {} {}",
                    "⚠".color(TOKYO_PINK).bold(),
                    msg.color(TOKYO_BLUE)
                );
            }
            _ => {}
        }
    }

    // Step: build the list of targets
    let targets: Vec<String> = if args.my_ip {
        // Branch: discover public IP
        match http::public_ip(args.proxy.as_deref()).await {
            Some(ip) => vec![ip.to_string()],
            None => {
                eprintln!("Could not determine public IP");
                return;
            }
        }
    } else if let Some(t) = &args.target {
        vec![t.clone()]
    } else {
        eprintln!("Usage: identifynet <IP or domain>");
        eprintln!("       identifynet -m");
        return;
    };

    // Loop: process each target
    let mut results = Vec::new();
    for target in targets {
        stealth::jitter(args.jitter).await;
        let geo_db = db_path.join(GEO_DB);
        let result = process_target(target, &geo_db, args.no_portscan, args.no_whois).await;

        // Handle: display result (unless JSON mode)
        if !args.json {
            display::result(&result);
            println!();
        }
        results.push(result);
    }

    // Branch: JSON output to stdout
    if args.json {
        if let Ok(json) = serde_json::to_string_pretty(&results) {
            println!("{}", json);
        }
    }

    // Branch: write JSON output to file
    if let Some(path) = &args.output {
        let out = serde_json::to_string_pretty(&results).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            if !args.json {
                println!(
                    "  {} {}",
                    "✗".color(TOKYO_PINK).bold(),
                    format!("Write failed: {}", e).color(TOKYO_PINK)
                );
            }
        } else if !args.json {
            println!(
                "  {} {}",
                "•".color(TOKYO_PINK).dimmed(),
                format!("Saved to {}", path.display()).dimmed()
            );
        }
    }
}
