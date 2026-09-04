/// Auspex — Domain Intelligence Oracle
///
/// Version: 3.9.0
/// Author: khaninkali · HyperSecurity Offensive Labs

mod display;
mod dns;
mod models;
mod parser;
mod rdap;
mod spinner;
mod stealth;
mod whois;

use clap::Parser;
use colored::Colorize;
use display::{banner, section, section_end};
use spinner::Spinner;
use std::time::Instant;

/// Command-line arguments for Auspex.
#[derive(Parser)]
#[command(name = "auspex")]
#[command(version = "3.9.0")]
#[command(about = "AUSPEX — Domain Intelligence Oracle: WHOIS, RDAP, DNS correlation with cybernetic precision")]
struct Cli {
    #[arg(help = "Domain name to investigate")]
    target: Option<String>,

    #[arg(short = 'j', long, help = "JSON output (no banner, machine-readable)")]
    json: bool,

    #[arg(short = 'o', long, help = "Save results to file")]
    output: Option<String>,

    #[arg(long, help = "Skip RDAP lookup")]
    no_rdap: bool,

    #[arg(long, help = "Skip DNS correlation")]
    no_dns: bool,

    #[arg(long, help = "Show raw WHOIS response")]
    raw: bool,

    #[arg(short = 'P', long, help = "Proxy URL (SOCKS5 or HTTP)")]
    proxy: Option<String>,

    #[arg(long, default_value = "0", help = "Random delay (ms) before request")]
    jitter: u64,
}

/// Runs all intelligence gathering phases for a single target domain.
async fn process_target(target: &str, skip_rdap: bool, skip_dns: bool, jitter_ms: u64) -> models::AuspexResult {
    let start = Instant::now();
    let clean = target.trim().trim_end_matches('.').to_lowercase();
    let mut result = models::AuspexResult {
        target: clean.clone(),
        ..Default::default()
    };

    // Phase 1: WHOIS lookup
    stealth::jitter(jitter_ms).await;
    let sp = Spinner::start("querying WHOIS servers");
    let whois_result = whois::lookup(&clean).await;
    sp.stop("✓");

    match whois_result {
        Some(info) => {
            let is_registered = info.registrar.is_some()
                || info.creation_date.is_some()
                || !info.status_codes.is_empty()
                || (!info.name_servers.is_empty()
                    && !info.name_servers.iter().any(|ns| ns.is_empty()));

            result.is_registered = is_registered;
            result.whois = Some(info);

            // Compute domain age and expiry
            if let Some(ref w) = result.whois {
                if let Some(created) = w.creation_date {
                    let now = chrono::Utc::now().naive_utc();
                    let age = (now - created).num_days();
                    result.domain_age_days = Some(age);
                }
                if let Some(expires) = w.expiration_date {
                    let now = chrono::Utc::now().naive_utc();
                    let days = (expires - now).num_days();
                    result.days_until_expiry = Some(days);
                }
            }

            result.registrar_abuse_email = result.whois.as_ref().and_then(|w| w.abuse_email.clone());
        }
        None => {
            result.is_registered = false;
        }
    }

    // Phase 2: RDAP as secondary source
    if !skip_rdap {
        stealth::jitter(jitter_ms).await;
        let sp = Spinner::start("querying RDAP database");
        let rdap_result = rdap::lookup(&clean).await;
        sp.stop("✓");
        result.rdap = rdap_result;

        // Fallback: use RDAP data if WHOIS returned nothing
        if result.whois.is_none() && result.rdap.is_some() {
            let rdap = result.rdap.as_ref().unwrap();
            result.is_registered = !rdap.events.is_empty() || !rdap.status_codes.is_empty();
            if result.is_registered {
                result.whois = Some(models::WhoisInfo {
                    domain: clean.clone(),
                    registrar: rdap.entities.iter().find(|e| e.role == "registrar").and_then(|e| e.name.clone()),
                    creation_date: rdap.events.iter().find(|e| e.action == "registration").and_then(|e| e.date),
                    expiration_date: rdap.events.iter().find(|e| e.action == "expiration").and_then(|e| e.date),
                    updated_date: rdap.events.iter().find(|e| e.action == "last changed").and_then(|e| e.date),
                    status_codes: rdap.status_codes.clone(),
                    name_servers: rdap.name_servers.clone(),
                    dnssec: rdap.dnssec.clone(),
                    source_server: Some("rdap.org".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    // Phase 3: DNS correlation
    if !skip_dns {
        stealth::jitter(jitter_ms).await;
        let sp = Spinner::start("correlating DNS records");
        let dns_result = dns::correlate(&clean).await;
        sp.stop("✓");
        result.dns = Some(dns_result);
    }

    result.timing_ms = start.elapsed().as_millis() as u64;
    result
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    if !args.json {
        banner();
    }

    let target = match &args.target {
        Some(t) => t.trim().to_lowercase(),
        None => {
            eprintln!(
                "  {} {}",
                "✗".bright_red().bold(),
                "Usage: auspex <domain> [options]".white()
            );
            return;
        }
    };

    if !args.json {
        println!(
            "  {} {}",
            "◈".bright_magenta().bold(),
            format!("Analyzing {}", target).bright_cyan()
        );
        println!();
    }

    let result = process_target(&target, args.no_rdap, args.no_dns, args.jitter).await;

    // Output handling
    if args.json {
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        println!("{}", json);
    } else {
        display::result(&result);

        // Raw WHOIS output
        if args.raw {
            if let Some(ref w) = result.whois {
                if let Some(ref raw) = w.raw {
                    section("RAW WHOIS");
                    println!("{}", raw.dimmed());
                    section_end();
                }
            }
        }

        // Timing summary
        let elapsed = result.timing_ms as f64 / 1000.0;
        let time_str = format!("done in {:.2}s", elapsed);
        if result.is_registered {
            println!("  {} {}", "◈".bright_magenta().bold(), time_str.green().bold());
        } else {
            println!("  {} {}", "◈".bright_magenta().bold(), time_str.bright_red().bold());
        }
    }

    // File output
    if let Some(path) = &args.output {
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &json) {
            eprintln!("Write failed: {}", e);
        }
    }
}
