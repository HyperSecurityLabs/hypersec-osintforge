/// SNIFF — Subdomain hunter with passive recon, DNS brute-force,
/// HTTP probing, and subdomain takeover detection.
///
/// Version: 3.0.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod crtsh;
mod display;
mod dns;
mod httpprobe;
mod models;
mod otx;
mod stealth;
mod takeover;

use clap::Parser;
use colored::*;
use display::{banner, ROSE_PINE_GOLD, ROSE_PINE_PINE};
use models::SniffResult;
use std::path::PathBuf;
use std::time::Instant;

/// Default wordlist used when no external wordlist file is provided.
const DEFAULT_WORDLIST: &[&str] = &[
    // Core
    "www", "mail", "admin", "api", "blog", "dev", "test", "staging",
    "vpn", "remote", "webmail", "smtp", "pop3", "imap", "ns1", "ns2",
    "ns3", "ns4", "cpanel", "whm", "ftp", "ssh", "git", "jenkins",
    // Infrastructure
    "jira", "confluence", "grafana", "prometheus", "kibana", "status",
    "statuspage", "help", "support", "docs", "wiki", "app", "m", "mobile",
    "shop", "store", "cdn", "static", "assets", "img", "media", "video",
    "upload", "download", "files", "backup", "db", "database", "mysql",
    "redis", "elasticsearch", "rabbitmq", "kafka", "jenkins", "travis",
    "ci", "cd", "build", "deploy", "release", "beta", "alpha", "demo",
    "sandbox", "playground", "lab", "internal", "corp", "portal", "web",
    "mail2", "mail3", "mx", "mx1", "mx2", "autodiscover", "owa", "exchange",
    // Security
    "security", "auth", "login", "sso", "oauth", "saml", "ldap",
    "radius", "tacacs", "pki", "ca", "cert", "crl", "ocsp", "hsm",
    // Observability
    "monitor", "monitoring", "nagios", "zabbix", "icinga", "munin",
    "log", "logs", "syslog", "splunk", "elk", "newrelic", "datadog",
    // Cloud
    "s3", "bucket", "storage", "object", "blob", "cloud", "compute",
    "instance", "container", "docker", "k8s", "kubernetes", "registry",
    // Network
    "proxy", "gateway", "router", "switch", "firewall", "ids", "ips",
    "waf", "loadbalancer", "lb", "haproxy", "nginx", "apache", "tomcat",
    // Other
    "chat", "slack", "discord", "teams", "meet", "zoom", "webex",
    "calendar", "drive", "docs", "sheets", "forms", "mail", "contacts",
    "news", "newsletter", "info", "about", "contact", "careers", "jobs",
    "recruitment", "hr", "people", "directory", "phone", "invoice",
    "billing", "payment", "checkout", "cart", "orders", "returns",
    "partner", "partners", "vendor", "vendors", "supplier", "suppliers",
    "api", "api2", "api3", "rest", "graphql", "soap", "xml", "json",
];

/// Command-line interface definition for SNIFF.
#[derive(Parser)]
#[command(name = "sniff")]
#[command(version = "3.0.0")]
#[command(about = "SNIFF — Subdomain hunter with passive recon, DNS brute-force, and takeover detection")]
struct Cli {
    target: Option<String>,

    #[arg(short = 'f', long)]
    wordlist: Option<PathBuf>,

    #[arg(short = 'j', long)]
    json: bool,

    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    #[arg(short = 'b', long)]
    no_bruteforce: bool,

    #[arg(short = 'z', long)]
    zone_transfer: bool,

    #[arg(short = 't', long, default_value = "10")]
    threads: usize,

    #[arg(short = 'p', long)]
    no_probe: bool,

    #[arg(short = 'w', long)]
    no_wildcard: bool,

    #[arg(long)]
    no_otx: bool,

    #[arg(short = 'P', long)]
    proxy: Option<String>,

    #[arg(long, default_value = "0")]
    jitter: u64,
}

/// Load the wordlist from a file path, or fall back to `DEFAULT_WORDLIST`.
fn load_wordlist(path: Option<&PathBuf>) -> Vec<String> {
    // Check: Try reading from the provided file path
    if let Some(p) = path {
        if let Ok(content) = std::fs::read_to_string(p) {
            return content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        }
    }
    // Fallback: Use the built-in default wordlist
    DEFAULT_WORDLIST.iter().map(|s| s.to_string()).collect()
}

/// Entry-point: parses CLI arguments, runs all recon stages, and
/// displays or exports the results.
#[tokio::main]
async fn main() {
    // Step: Parse CLI arguments
    let args = Cli::parse();

    // Branch: Show banner when not in JSON mode
    if !args.json {
        banner();
    }

    // Step: Extract and normalise the target domain
    let target = match &args.target {
        Some(t) => t.trim().to_lowercase(),
        None => {
            eprintln!("Usage: sniff example.com");
            return;
        }
    };

    // Step: Load wordlist (file or default)
    let wordlist = load_wordlist(args.wordlist.as_ref());

    // Branch: Print scanning header when not in JSON mode
    if !args.json {
        println!(
            "  {} {}",
            "▸".color(ROSE_PINE_GOLD).bold(),
            format!("Sniffing {}", target).color(ROSE_PINE_PINE)
        );
    }

    let start = Instant::now();
    let mut result = SniffResult {
        target: target.clone(),
        ..Default::default()
    };

    // Stage: Wildcard detection
    if !args.no_wildcard {
        result.wildcard = dns::detect_wildcard(&target).await;
        // Branch: Warn user about wildcard-induced false positives
        if result.wildcard && !args.json {
            println!(
                "  {} {}",
                "⚠".color(colored::Color::TrueColor { r: 235, g: 111, b: 146 }).bold(),
                "Wildcard DNS detected — results may include false positives".color(colored::Color::TrueColor { r: 156, g: 207, b: 216 })
            );
        }
    }

    // Stage: Passive recon via crt.sh
    let crt_subs = crtsh::query(&target).await;
    result.subdomains.extend(crt_subs);

    // Stage: Passive recon via AlienVault OTX
    if !args.no_otx {
        let otx_subs = otx::query(&target).await;
        result.subdomains.extend(otx_subs);
    }

    // Stage: DNS brute-force
    if !args.no_bruteforce {
        let bf_subs = dns::brute_force(&target, &wordlist, args.threads).await;
        result.subdomains.extend(bf_subs);
    }

    // Stage: Resolve all collected subdomains
    dns::resolve(&mut result.subdomains).await;

    // Stage: Deduplicate by name, keeping the first occurrence
    let mut seen = std::collections::HashSet::new();
    result.subdomains.retain(|s| seen.insert(s.name.clone()));

    // Stage: Check each subdomain for takeover vulnerability
    for sd in result.subdomains.iter_mut() {
        sd.takeover = takeover::check(&sd.name).await;
    }

    // Stage: HTTP probe (unless disabled or empty)
    if !args.no_probe && !result.subdomains.is_empty() {
        stealth::jitter(args.jitter).await;
        result.subdomains = httpprobe::probe(&result.subdomains, args.proxy.as_deref()).await;
    }

    // Step: Sort subdomains for deterministic output
    result.subdomains.sort_by(|a, b| a.name.cmp(&b.name));

    // Stage: Zone-transfer check
    if args.zone_transfer {
        let ns_list = dns::ns_list(&target).await;
        for ns in &ns_list {
            if let Some(zt) = dns::check_zone_transfer(&target, ns).await {
                result.zone_transfer = Some(zt);
                break;
            }
        }
    }

    // Step: Re-sort subdomains after zone-transfer stage
    result.subdomains.sort_by(|a, b| a.name.cmp(&b.name));

    // Branch: Terminal output
    if !args.json {
        display::result(&result);
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "  {} {}",
            "▸".color(ROSE_PINE_GOLD).bold(),
            format!("{} subdomains in {:.1}s", result.subdomains.len(), elapsed).color(ROSE_PINE_PINE)
        );
    }

    // Branch: JSON output to stdout
    if args.json {
        if let Ok(json) = serde_json::to_string_pretty(&result) {
            println!("{}", json);
        }
    }

    // Branch: Write output to file
    if let Some(path) = &args.output {
        let out = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            eprintln!("Write failed: {}", e);
        }
    }
}
