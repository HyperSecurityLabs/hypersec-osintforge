/// PRY — Precision Reconnaissance Yield
///
/// Version: 2.5.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod display;
mod dns;
mod models;
mod rdap;
mod stealth;
mod whois;

use clap::Parser;
use colored::Colorize;
use display::{banner, divider, info, result, summary, CRIMSON, GOLD};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Command-line arguments for PRY.
#[derive(Parser)]
#[command(name = "pry")]
#[command(version = "2.5.0")]
#[command(about = "Precision Reconnaissance Yield — pry open any domain or IP")]
struct Cli {
    /// Single target domain or IP.
    target: Option<String>,

    /// File containing a list of targets (one per line).
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,

    /// Maximum concurrent lookups.
    #[arg(short = 'c', long, default_value = "50")]
    concurrency: usize,

    /// Output results as JSON.
    #[arg(short = 'j', long)]
    json: bool,

    /// Write JSON output to a file.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Use RDAP only (skip WHOIS and DNS).
    #[arg(long)]
    rdap_only: bool,

    /// Use WHOIS only (skip RDAP and DNS).
    #[arg(long)]
    whois_only: bool,

    /// Show raw WHOIS output instead of parsed fields.
    #[arg(short = 'r', long)]
    raw: bool,

    /// HTTP/SOCKS proxy URL.
    #[arg(short = 'P', long)]
    proxy: Option<String>,

    /// Maximum jitter delay in milliseconds (0 = disabled).
    #[arg(long, default_value = "0")]
    jitter: u64,
}

/// Load targets from CLI argument and/or file.
fn load_targets(cli: &Cli) -> Vec<String> {
    let mut targets = Vec::new();

    // Step: add single target from CLI argument
    if let Some(target) = &cli.target {
        targets.push(target.clone());
    }

    // Step: load targets from file
    if let Some(path) = &cli.file {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cannot read {}: {}", path.display(), e);
                return targets;
            }
        };
        // Loop: parse each line, stripping protocols and paths
        for line in content.lines() {
            let line = line.trim();
            // Check: skip empty lines and comments
            if !line.is_empty() && !line.starts_with('#') {
                let clean = line
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(line)
                    .to_string();
                if !targets.contains(&clean) {
                    targets.push(clean);
                }
            }
        }
    }

    targets
}

/// Look up a single target using the selected engines.
async fn lookup_target(target: String, rdap_only: bool, whois_only: bool, proxy: Option<String>) -> models::LookupResult {
    let mut result = models::LookupResult::new(&target);

    // Dispatch: select engine based on CLI flags
    match (rdap_only, whois_only) {
        (true, false) => {
            let rdap_r = rdap::lookup(&target, proxy.as_deref()).await;
            if rdap_r.error.is_none() {
                result.merge(&rdap_r);
                result.source = "rdap".to_string();
            }
        }
        (false, true) => {
            let whois_r = whois::lookup(&target).await;
            if whois_r.error.is_none() {
                result.merge(&whois_r);
                result.source = "whois".to_string();
            }
        }
        _ => {
            // Step: concurrent RDAP + WHOIS
            let (rdap_r, whois_r) = tokio::join!(rdap::lookup(&target, proxy.as_deref()), whois::lookup(&target));
            if rdap_r.error.is_none() {
                result.merge(&rdap_r);
            }
            if whois_r.error.is_none() {
                result.merge(&whois_r);
            }
            result.source = if rdap_r.error.is_none() {
                "rdap+whois"
            } else if whois_r.error.is_none() {
                "whois"
            } else {
                "unknown"
            }
            .to_string();
        }
    }

    // Step: append DNS lookup data
    let dns_r = dns::lookup(&target).await;
    result.merge(&dns_r);

    result.target = target;
    result
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Step: print banner
    banner();

    // Step: load all targets
    let targets = load_targets(&args);
    // Check: no targets provided
    if targets.is_empty() {
        println!("  {} No targets provided", "✗".color(GOLD).bold());
        println!(
            "  {} pry example.com",
            "Usage:".color(GOLD)
        );
        println!(
            "  {} pry -f targets.txt -c 100 -j -o results.json",
            "       ".color(GOLD)
        );
        println!(
            "  {} pry --rdap-only example.com",
            "       ".color(GOLD)
        );
        println!(
            "  {} pry -r example.com",
            "       ".color(GOLD)
        );
        return;
    }

    // Branch: inform user about raw mode
    if args.raw && args.whois_only {
        println!(
            "  {} {}",
            "•".color(CRIMSON),
            "Raw mode forces WHOIS-only".color(GOLD)
        );
    }

    // Step: print run configuration
    println!(
        "  {} {} {}",
        "▸".color(CRIMSON).bold(),
        "Targets".color(CRIMSON),
        format!("{} domains/IPs", targets.len()).color(GOLD)
    );
    println!(
        "  {} {} {}",
        "▸".color(CRIMSON).bold(),
        "Engine".color(CRIMSON),
        if args.raw {
            "WHOIS (raw)".color(GOLD)
        } else if args.rdap_only {
            "RDAP only".color(GOLD)
        } else if args.whois_only {
            "WHOIS only".color(GOLD)
        } else {
            "RDAP + WHOIS + DNS".color(GOLD)
        }
    );
    println!(
        "  {} {} {}",
        "▸".color(CRIMSON).bold(),
        "Concurrency".color(CRIMSON),
        format!("{} workers", args.concurrency).color(GOLD)
    );
    divider();

    let concurrency = args.concurrency.max(1);
    let start = Instant::now();
    let jitter_ms = args.jitter;
    let proxy = args.proxy.clone();
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    // Loop: spawn concurrent lookup tasks with semaphore limiting
    for target in targets {
        let sem = sem.clone();
        let proxy = proxy.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");
            stealth::jitter(jitter_ms).await;
            lookup_target(target, args.rdap_only, args.whois_only, proxy).await
        }));
    }

    let raw = args.raw;
    let mut results = Vec::new();
    // Loop: collect results from spawned tasks
    for handle in handles {
        match handle.await {
            Ok(r) => {
                if !args.json {
                    result(&r, raw);
                    println!();
                }
                results.push(r);
            }
            Err(e) => {
                println!("  {} {}", "✗".color(CRIMSON).bold(), format!("Task: {}", e).color(CRIMSON));
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();

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
            println!("  {} {}", "✗".color(CRIMSON).bold(), format!("Write failed: {}", e).color(CRIMSON));
        } else {
            info(&format!("Saved to {}", path.display()));
        }
    }

    // Handle: print final summary
    summary(results.len(), elapsed);
}
