/// SPOOF — Mail Forger: SPF/DMARC/DKIM Audit, SMTP Relay Test, Spoofability Check
///
/// Version: 5.0.0
/// Author: khaninkali · HyperSecurity Offensive Labs

mod display;
mod dns;
mod models;
mod smtp;
mod spinner;
mod spoof;

use clap::Parser;
use colored::*;
use display::{banner, BANNER, BORDER, TEXT};
use spinner::Spinner;
use std::time::Instant;

const DKIM_SELECTORS: &[&str] = &[
    "default", "google", "selector1", "selector2",
    "dkim", "mail", "zoho", "mx", "spf", "protonmail",
];

/// Command-line arguments for SPOOF.
#[derive(Parser)]
#[command(name = "spoof")]
#[command(version = "0.1.0")]
#[command(about = "SPOOF — Mail forger: SPF/DMARC/DKIM audit, SMTP relay test, spoofability check")]
struct Cli {
    #[arg(help = "Domain to audit")]
    target: Option<String>,

    #[arg(short = 'j', long, help = "JSON output (no banner, machine-readable)")]
    json: bool,

    #[arg(short = 'o', long, help = "Save results to file")]
    output: Option<String>,

    #[arg(long, help = "Skip MX lookup")]
    no_mx: bool,

    #[arg(long, help = "Skip DKIM lookup")]
    no_dkim: bool,

    #[arg(long, help = "Test SMTP relay on port 25")]
    relay: bool,

    #[arg(long, default_value = "test@spoof-check.local", help = "From address for relay test")]
    relay_from: String,

    #[arg(long, default_value = "postmaster@example.com", help = "To address for relay test")]
    relay_to: String,

}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    if !args.json {
        banner();
    }

    let start = Instant::now();

    let target = match &args.target {
        Some(t) => t.trim().to_lowercase(),
        None => {
            eprintln!("Usage: spoof <domain>");
            return;
        }
    };

    if !args.json {
        println!(
            "  {} {} {}",
            "▸".color(BANNER).bold(),
            "Auditing".color(BORDER),
            target.bold().color(TEXT),
        );
    }

    let mut result = models::SpoofResult {
        target: target.clone(),
        ..Default::default()
    };

    // MX lookup
    if !args.no_mx {
        let sp = Spinner::start("looking up MX records");
        let mut mx = dns::mx_lookup(&target).await;
        sp.stop("✓");

        // Resolve MX hostnames to IP addresses
        for mx in mx.iter_mut() {
            if let Ok(addrs) = tokio::net::lookup_host((mx.host.as_str(), 0)).await {
                if let Some(addr) = addrs.into_iter().next() {
                    mx.ip = Some(addr.ip().to_string());
                }
            }
        }
        result.mx = mx;
    }

    // SPF check
    let sp = Spinner::start("checking SPF records");
    result.spf = dns::spf_check(&target).await;
    sp.stop("✓");

    // DMARC check
    let sp = Spinner::start("checking DMARC records");
    result.dmarc = dns::dmarc_check(&target).await;
    sp.stop("✓");

    // DKIM check
    if !args.no_dkim {
        let sp = Spinner::start("checking DKIM records");
        result.dkim = dns::dkim_check(&target, DKIM_SELECTORS).await;
        sp.stop("✓");
    }

    // SMTP relay test
    if args.relay {
        let relay_targets: Vec<String> = if result.mx.is_empty() {
            vec![target.clone()]
        } else {
            result.mx.iter().map(|m| m.host.clone()).collect()
        };
        let sp = Spinner::start("testing SMTP relay");
        if let Some(host) = relay_targets.first() {
            result.relay = smtp::check_relay(host, 25, &args.relay_from, &args.relay_to).await;
        }
        sp.stop("✓");
    }

    // Spoofability analysis
    result.spoofable = spoof::analyze(&result);

    // Output
    if !args.json {
        display::result(&result);
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "  {} {}",
            "▸".color(BANNER).bold(),
            format!("done in {:.1}s", elapsed).color(BORDER)
        );
    }

    if args.json {
        if let Ok(json) = serde_json::to_string_pretty(&result) {
            println!("{}", json);
        }
    }

    if let Some(path) = &args.output {
        let out = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            eprintln!("Write failed: {}", e);
        }
    }
}
