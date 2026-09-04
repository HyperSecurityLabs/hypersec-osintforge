/// Shroud — Stealth Network Topology Discovery & Forensics
///
/// Version: 4.9.0
/// Author: khaninkali · HyperSecurity Offensive Labs

mod dns;
mod geo;
mod http;
mod models;
mod port;
mod stealth;

use clap::Parser;
use colored::Colorize;
use models::{Node, ScanResult, ServiceFingerprint};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Command-line arguments for Shroud.
#[derive(Parser)]
#[command(name = "Shroud")]
#[command(version = "0.2.0")]
#[command(about = "Stealth Network Topology Discovery & Forensics Framework")]
struct Cli {
    #[arg(short = 'u', long)]
    target: String,

    #[arg(short = 'j', long, default_value = "150")]
    jitter: u64,

    #[arg(long)]
    json: bool,

    #[arg(short = 'o', long)]
    output: Option<String>,

    #[arg(short = 'p', long)]
    proxy: Option<String>,

    #[arg(long, default_value = "false")]
    port_scan: bool,

    #[arg(long, default_value = "false")]
    crt: bool,

    #[arg(long, default_value = "false")]
    no_geo: bool,

    #[arg(long, default_value = "3000")]
    port_timeout: u64,
}

/// Computes /24 CIDR ranges from a list of IPv4 addresses.
fn compute_cidr_ranges(ips: &[IpAddr]) -> Vec<String> {
    let mut ranges: Vec<String> = Vec::new();
    let mut seen: HashMap<u32, Vec<u8>> = HashMap::new();

    for ip in ips {
        if let IpAddr::V4(v4) = ip {
            let octets = v4.octets();
            let prefix = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
            seen.entry(prefix).or_default().push(octets[3]);
        }
    }

    for prefix in seen.keys() {
        let bytes = prefix.to_be_bytes();
        ranges.push(format!("{}.{}.{}.0/24", bytes[0], bytes[1], bytes[2]));
    }

    ranges.sort();
    ranges.dedup();
    ranges
}

/// Classifies a node's network layer based on IP range and server header.
fn classify_layer(ip: IpAddr, server_header: &Option<String>) -> String {
    if let IpAddr::V4(v4) = ip {
        let octets = v4.octets();
        match octets[0] {
            216 if octets[1] == 150 => {
                if let Some(srv) = server_header {
                    if srv.to_lowercase().contains("vercel") {
                        return "Edge (Vercel)".to_string();
                    }
                }
                return "WAF/CDN".to_string();
            }
            15 | 13 | 43 => return "Origin (AWS)".to_string(),
            205 => return "DNS (Route53)".to_string(),
            104 | 172 | 103 => return "CDN".to_string(),
            _ => {}
        }
    }
    "Unknown".to_string()
}

/// Groups nodes by ASN for network mapping.
fn build_asn_map(nodes: &[Node]) -> HashMap<String, Vec<IpAddr>> {
    let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for node in nodes {
        if let Some(ref geo) = node.geo {
            if !geo.asn.is_empty() {
                map.entry(geo.asn.clone()).or_default().push(node.ip);
            }
        }
    }
    map
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let start_time = Instant::now();

    if !args.target.starts_with("http") {
        eprintln!("{} Target must be a URL (e.g. https://example.com)", "[!]".red());
        std::process::exit(1);
    }

    let domain = args
        .target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(&args.target)
        .to_string();

    // Display header
    let banner = format!(
        "{} Shroud v{} — {} {}",
        "[*]".cyan(),
        "0.2.0".bold(),
        domain.bold(),
        if args.proxy.is_some() { "(routed through proxy)".dimmed().to_string() } else { "".to_string() }
    );
    println!("{}", banner);
    println!("{}", "─".repeat(55).dimmed());

    // Stage 1: DNS reconnaissance
    println!("{} DNS reconnaissance...", "[1/5]".green());
    let resolver_chain = vec!["Cloudflare".to_string(), "Google".to_string(), "Quad9".to_string()];
    let (ips, cnames, nameservers, mx_records, txt_records) =
        dns::gather_nodes(&domain, args.jitter).await;

    println!("  {} IPs found: {}", "✓".green(), ips.len());
    if !cnames.is_empty() {
        println!("  {} CNAME chain: {}", "✓".green(), cnames.join(" → "));
    }
    println!("  {} Nameservers: {}", "✓".green(), nameservers.len());
    println!("  {} MX records: {}", "✓".green(), mx_records.len());

    // Stage 2: Passive recon via Certificate Transparency
    let subdomains = if args.crt {
        println!("\n{} Passive recon (crt.sh)...", "[2/5]".green());
        let subs = http::fetch_crt_sh(&domain, args.jitter).await;
        println!("  {} Subdomains found via CRT: {}", "✓".green(), subs.len());
        for s in subs.iter().take(10) {
            println!("    {}", s.dimmed());
        }
        if subs.len() > 10 {
            println!("    ... and {} more", (subs.len() - 10).to_string().dimmed());
        }
        subs
    } else {
        Vec::new()
    };

    // Stage 3: HTTP probing
    let probe_step = if args.crt { 3 } else { 2 };
    println!("\n{} HTTP probing...", format!("[{}/5]", probe_step).green());
    let probe_result = http::probe_target(&args.target, args.proxy.as_deref()).await;
    let server_header = probe_result.as_ref().and_then(|p| p.server.clone());
    let waf = probe_result.as_ref().and_then(|p| p.waf.clone());

    if let Some(ref probe) = probe_result {
        println!("  {} Status: {}", "✓".green(), probe.status);
        if let Some(ref srv) = probe.server {
            println!("  {} Server: {}", "✓".green(), srv);
        }
        if let Some(ref w) = probe.waf {
            println!("  {} WAF: {}", "✓".green(), w.red());
        }
        println!("  {} Latency: {:.1}ms", "✓".green(), probe.latency_ms);
    }

    // Stage 4: Geo enrichment, reverse DNS, port scanning
    let geo_step = if args.crt { 4 } else { 3 };
    println!("\n{} Enriching nodes...", format!("[{}/5]", geo_step).green());
    let mut nodes: Vec<Node> = Vec::new();

    for ip in &ips {
        let geo = if args.no_geo { None } else { geo::geo_lookup(*ip).await };
        let reverse_dns = dns::resolve_ptr(*ip, args.jitter / 2).await;
        let open_ports = if args.port_scan {
            port::scan_ports_concurrent(*ip, None, args.port_timeout).await
        } else {
            Vec::new()
        };
        let latency = probe_result.as_ref().map_or(0.0, |p| p.latency_ms);
        let layer = classify_layer(*ip, &server_header);

        nodes.push(Node {
            ip: *ip,
            hostname: domain.clone(),
            layer,
            source: "DNS".to_string(),
            latency_ms: latency,
            geo,
            reverse_dns,
            open_ports,
            asn_cidr: None,
        });
    }

    // Stage 5: CIDR and ASN analysis
    let final_step = if args.crt { 5 } else { 4 };
    println!("\n{} Analysis...", format!("[{}/5]", final_step).green());
    let cidr_ranges = compute_cidr_ranges(&ips);
    let asn_map = build_asn_map(&nodes);
    let duration_secs = start_time.elapsed().as_secs_f64();

    let services: Vec<ServiceFingerprint> = nodes
        .iter()
        .flat_map(|node| {
            node.open_ports.iter().map(|&port| ServiceFingerprint {
                ip: node.ip,
                port,
                service: None,
                banner: None,
            })
        })
        .collect();

    let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let result = ScanResult {
        target: args.target.clone(),
        timestamp: timestamp.clone(),
        duration_secs,
        resolver_chain,
        nodes: nodes.clone(),
        cidr_ranges: cidr_ranges.clone(),
        cname_chain: cnames,
        nameservers,
        mx_records,
        txt_records,
        subdomains,
        ssl_cert_issuer: probe_result.as_ref().and_then(|p| p.cert_issuer.clone()),
        server_header,
        waf,
        services,
        asn_map,
    };

    // Output handling
    if args.json {
        let json_output = serde_json::to_string_pretty(&result).unwrap_or_default();
        println!("\n{}", json_output);
        if let Some(path) = &args.output {
            if let Err(e) = std::fs::write(path, &json_output) {
                eprintln!("{} Failed to write output: {}", "[!]".red(), e);
            }
        }
    } else {
        print_summary(&result, nodes, cidr_ranges, duration_secs);
        if let Some(path) = &args.output {
            let json_output = serde_json::to_string_pretty(&result).unwrap_or_default();
            if let Err(e) = std::fs::write(path, &json_output) {
                eprintln!("{} Failed to write output: {}", "[!]".red(), e);
            }
        }
    }
}

/// Prints the formatted scan summary to the terminal.
fn print_summary(result: &ScanResult, nodes: Vec<Node>, cidr_ranges: Vec<String>, duration: f64) {
    println!("\n{}", "═══════════════════════════════════════".bold());
    println!("{}", "  SHROUD SCAN COMPLETE".bold().green());
    println!("{}", "═══════════════════════════════════════".bold());

    println!("\n{} {}", "Target:".bold(), result.target);
    println!("{} {}", "Time:".bold(), result.timestamp);
    println!("{} {:.1}s", "Duration:".bold(), duration);

    println!("\n{}", "── Nodes ──".bold());
    for node in &nodes {
        let ip_str = node.ip.to_string().yellow();
        let layer_str = node.layer.cyan();
        if let Some(ref geo) = node.geo {
            println!(
                "  {} [{}] {} (AS{}: {}, {}, {})",
                ip_str, layer_str, geo.org, geo.asn, geo.city, geo.region, geo.country
            );
        } else {
            println!("  {} [{}]", ip_str, layer_str);
        }
        if let Some(ref ptr) = node.reverse_dns {
            println!("    PTR: {}", ptr.dimmed());
        }
        if !node.open_ports.is_empty() {
            let ports: Vec<String> = node.open_ports.iter().map(|p| p.to_string()).collect();
            println!("    Ports: {}", ports.join(", ").magenta());
        }
    }

    if !cidr_ranges.is_empty() {
        println!("\n{}", "── CIDR Ranges ──".bold());
        for cidr in &cidr_ranges {
            println!("  {}", cidr.magenta());
        }
    }

    if let Some(ref waf) = result.waf {
        println!("\n{} {}", "WAF:".bold(), waf.red());
    }
    if let Some(ref server) = result.server_header {
        println!("{} {}", "Server:".bold(), server);
    }
    if let Some(ref issuer) = result.ssl_cert_issuer {
        println!("{} {}", "SSL Issuer:".bold(), issuer);
    }

    if !result.asn_map.is_empty() {
        println!("\n{}", "── ASN Map ──".bold());
        for (asn, ips) in &result.asn_map {
            println!("  {} ({} IPs): {}", asn, ips.len(), ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "));
        }
    }

    if !result.subdomains.is_empty() {
        println!("\n{}", "── Subdomains (crt.sh) ──".bold());
        for s in result.subdomains.iter().take(10) {
            println!("  {}", s);
        }
        if result.subdomains.len() > 10 {
            println!("  ... {} more", result.subdomains.len() - 10);
        }
    }

    if !result.services.is_empty() {
        println!("\n{}", "── Open Services ──".bold());
        for svc in &result.services {
            println!("  {}:{}", svc.ip, svc.port);
        }
    }

    if !result.txt_records.is_empty() {
        println!("\n{}", "── TXT Records ──".bold());
        for txt in &result.txt_records {
            println!("  {}", txt.dimmed());
        }
    }

    println!(
        "\n{} {} nodes, {} CIDR ranges, {} ASNs, {} services",
        "✓".green(),
        nodes.len(),
        cidr_ranges.len(),
        result.asn_map.len(),
        result.services.len(),
    );
}
