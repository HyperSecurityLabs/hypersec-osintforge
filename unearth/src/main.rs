/// UNEARTH — Origin IP Discovery Framework (4-toolkit suite).
///
/// Version: 3.6.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod display;
mod matcher;
mod models;
mod recon;
mod scanner;
mod stealth;
mod tracer;

use clap::Parser;
use colored::Colorize;
use display::{banner, toolkit_header, found, info, warning, section, result_line};
use models::{OriginCandidate, ToolkitResult, UnearthResult};
use std::collections::HashSet;
use std::time::Instant;

/// Command-line interface definition for UNEARTH.
#[derive(Parser)]
#[command(name = "Unearth")]
#[command(version = "3.6.0")]
#[command(about = "Origin IP Discovery Framework — 4 Toolkit Suite")]
struct Cli {
    #[arg(short = 'u', long)]
    target: Option<String>,

    #[arg(short = 'j', long, default_value = "100")]
    jitter: u64,

    #[arg(short = 't', long, default_value = "4")]
    threads: usize,

    #[arg(short = 'o', long)]
    output: Option<String>,

    #[arg(short = 'p', long)]
    proxy: Option<String>,

    #[arg(long, default_value = "3000")]
    port_timeout: u64,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    skip_recon: bool,

    #[arg(long)]
    skip_scanner: bool,

    #[arg(long)]
    skip_tracer: bool,

    #[arg(long)]
    skip_matcher: bool,
}

/// Extract the bare domain from a full URL.
fn extract_domain(target: &str) -> String {
    target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(target)
        .to_string()
}

/// Build a set of /24 CIDR ranges from a list of origin IPs.
fn cidr_from_ips(origins: &[OriginCandidate]) -> Vec<String> {
    let mut ranges = Vec::new();
    let mut seen = HashSet::new();
    // Loop: Extract /24 prefix from each IPv4 origin
    for o in origins {
        if let std::net::IpAddr::V4(v4) = o.ip {
            let octets = v4.octets();
            let cidr = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            if seen.insert(cidr.clone()) {
                ranges.push(cidr);
            }
        }
    }
    ranges
}

/// Fetch the reference fingerprint (Server header + body SHA-256)
/// from the target domain over HTTPS.
async fn get_reference_fingerprint(domain: &str) -> (Option<String>, Option<String>) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(stealth::random_ua())
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(_) => return (None, None),
    };

    let url = format!("https://{}", domain);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return (None, None),
    };

    // Step: Extract Server header
    let server = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Step: Read and hash the response body
    let body = match response.bytes().await {
        Ok(b) => b,
        Err(_) => return (server, None),
    };

    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&body);
    let hash = hex::encode(hasher.finalize());

    (server, Some(hash))
}

/// Entry-point: parses CLI and runs toolkit stages sequentially.
#[tokio::main]
async fn main() {
    // Step: Parse CLI arguments
    let args = Cli::parse();

    banner();

    // Step: Extract target
    let target = match &args.target {
        Some(t) => t.clone(),
        None => {
            println!("\n  {} {}", "[!]".color(display::JADE), "No target provided. Use -u <URL>".color(display::LIGHT_BLUE));
            println!("  {} unearth -u https://example.com", "Usage:".color(display::JADE));
            return;
        }
    };

    let start = Instant::now();
    let domain = extract_domain(&target);

    let mut all_origins: Vec<OriginCandidate> = Vec::new();
    let mut toolkit_results: Vec<ToolkitResult> = Vec::new();

    // Toolkit 1: Reconnaissance
    if !args.skip_recon {
        toolkit_header("Reconnaissance", 1);
        let recon = recon::ReconToolkit::new(&domain, args.jitter);
        let (records, subdomains, history, origins) = recon.run().await;

        found(&format!("{} DNS records", records.len()), "");
        found(&format!("{} subdomains", subdomains.len()), "(crt.sh)");
        found(&format!("{} historical IPs", history.len()), "");

        // Loop: Display DNS records
        for r in &records {
            info(&format!("{} {}", r.record_type, r.value));
        }

        section("Subdomains");
        // Loop: Display up to 15 subdomains
        for sub in subdomains.iter().take(15) {
            info(&sub.name);
        }
        if subdomains.len() > 15 {
            info(&format!("... and {} more", subdomains.len() - 15));
        }

        section("Historical IPs");
        // Loop: Display historical IPs
        for h in &history {
            info(&format!("{} ({})", h.ip, h.source));
        }

        all_origins.extend(origins.clone());

        toolkit_results.push(ToolkitResult {
            name: "Reconnaissance".to_string(),
            origins,
            subdomains,
            dns_records: records,
            historical_ips: history,
            open_targets: Vec::new(),
        });
        println!();
    }

    // Toolkit 2: Scanner
    if !args.skip_scanner {
        toolkit_header("Scanner", 2);
        let cidrs = cidr_from_ips(&all_origins);
        let scanner = scanner::ScannerToolkit::new(&domain, cidrs.clone(), args.port_timeout, args.threads);
        let (origins, targets) = scanner.run().await;

        found(&format!("{} IPs probed", targets.len()), "");
        // Loop: Display probed origins
        for o in &origins {
            result_line(
                &format!("{}:{}", o.ip, o.port),
                &format!("status={} server={} ({}%)", o.status_code.unwrap_or(0), o.server_header.as_deref().unwrap_or("-"), o.confidence),
            );
        }

        all_origins.extend(origins.clone());

        toolkit_results.push(ToolkitResult {
            name: "Scanner".to_string(),
            origins,
            subdomains: Vec::new(),
            dns_records: Vec::new(),
            historical_ips: Vec::new(),
            open_targets: targets,
        });
        println!();
    }

    // Toolkit 3: Tracer
    if !args.skip_tracer {
        toolkit_header("Tracer", 3);
        let cidrs = cidr_from_ips(&all_origins);
        let tracer = tracer::TracerToolkit::new(&domain, args.jitter, args.port_timeout);
        let (origins, targets, ptr_records) = tracer.run(&cidrs).await;

        found(&format!("{} MX/NS origins", origins.len()), "");

        // Loop: Display traced origins
        for o in &origins {
            result_line(
                &format!("{}:{}", o.ip, o.port),
                o.hostname.as_deref().unwrap_or("unknown"),
            );
        }

        if !ptr_records.is_empty() {
            section("PTR Records");
            // Loop: Display PTR records
            for ptr in &ptr_records {
                info(&ptr.value);
            }
        }

        all_origins.extend(origins.clone());

        toolkit_results.push(ToolkitResult {
            name: "Tracer".to_string(),
            origins,
            subdomains: Vec::new(),
            dns_records: ptr_records,
            historical_ips: Vec::new(),
            open_targets: targets,
        });
        println!();
    }

    // Toolkit 4: Matcher
    if !args.skip_matcher {
        toolkit_header("Matcher", 4);

        section("Fingerprinting target");
        let (ref_server, ref_hash) = get_reference_fingerprint(&domain).await;
        if let Some(ref srv) = &ref_server {
            result_line("Server", srv);
        }
        if let Some(ref h) = &ref_hash {
            result_line("Body hash", &h[..16]);
        }

        let matcher = matcher::MatcherToolkit::new(&domain, all_origins.clone(), args.threads);
        let matched = matcher.run(&ref_hash, &ref_server).await;

        found(&format!("{} origin candidates matched", matched.len()), "");

        // Loop: Display matched candidates
        for o in &matched {
            let label = format!("{}:{}", o.ip, o.port);
            let detail = format!("{}% | status={} server={}", o.confidence, o.status_code.unwrap_or(0), o.server_header.as_deref().unwrap_or("-"));
            if o.confidence >= 60 {
                warning(&format!("{} {}", label, detail));
            } else {
                result_line(&label, &detail);
            }
        }

        all_origins.extend(matched.clone());

        toolkit_results.push(ToolkitResult {
            name: "Matcher".to_string(),
            origins: matched,
            subdomains: Vec::new(),
            dns_records: Vec::new(),
            historical_ips: Vec::new(),
            open_targets: Vec::new(),
        });
    }

    // Summary: Deduplicate and sort all origins
    let duration_secs = start.elapsed().as_secs_f64();
    let cidr_ranges = cidr_from_ips(&all_origins);

    all_origins.sort_by_key(|b| std::cmp::Reverse(b.confidence));
    all_origins.dedup_by(|a, b| a.ip == b.ip && a.port == b.port);

    let result = UnearthResult {
        target: target.clone(),
        timestamp: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        duration_secs,
        results: toolkit_results,
        all_origins: all_origins.clone(),
        cidr_ranges: cidr_ranges.clone(),
    };

    // Final output
    println!("\n{}", "═".repeat(55).color(display::LIGHT_BLUE).bold());
    println!(
        "  {} {} {}",
        "UNEARTH".bold().color(display::LIGHT_BLUE),
        "COMPLETE".color(display::JADE).bold(),
        format!("({:.1}s)", duration_secs).color(display::LIGHT_BLUE)
    );
    println!("{}", "═".repeat(55).color(display::LIGHT_BLUE).bold());

    let high_conf: Vec<_> = all_origins.iter().filter(|o| o.confidence >= 60).collect();
    if !high_conf.is_empty() {
        section("HIGH CONFIDENCE ORIGINS");
        // Loop: Display high-confidence origins
        for o in &high_conf {
            warning(&format!("{}:{}  ({}%)  {}", o.ip, o.port, o.confidence, o.server_header.as_deref().unwrap_or(&o.source)));
        }
    }

    section("All Candidates");
    // Loop: Display all candidates
    for o in &all_origins {
        info(&format!("{}:{}  {}%  [{}]", o.ip, o.port, o.confidence, o.source));
    }

    // Branch: JSON output
    if args.json {
        let json_output = serde_json::to_string_pretty(&result).unwrap_or_default();
        println!("\n{}", json_output);
    }

    // Branch: Save to file
    if let Some(path) = &args.output {
        let json_output = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &json_output) {
            eprintln!("Write failed: {}", e);
        } else {
            println!("\n{} Output saved to {}", "[✓]".color(display::JADE), path.color(display::LIGHT_BLUE));
        }
    }
}
