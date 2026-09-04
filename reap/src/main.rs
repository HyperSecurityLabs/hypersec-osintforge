/// REAP — Web Intelligence Profiler
///
/// Version: 4.3.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod content;
mod display;
mod dns;
mod endpoints;
mod fingerprint;
mod http;
mod js;
mod models;
mod secheaders;
mod stealth;
mod waf;

use clap::Parser;
use colored::Colorize;
use display::{banner, divider, info, result, summary, TOKYO_BLUE, TOKYO_PINK};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

/// Command-line arguments for REAP.
#[derive(Parser)]
#[command(name = "reap")]
#[command(version = "4.3.0")]
#[command(about = "Web Intelligence Profiler — advanced web recon & analysis")]
struct Cli {
    /// Single target domain or URL.
    target: Option<String>,

    /// File containing a list of targets (one per line).
    #[arg(short = 'f', long)]
    file: Option<PathBuf>,

    /// Maximum concurrent scans.
    #[arg(short = 'c', long, default_value = "10")]
    concurrency: usize,

    /// Output results as JSON.
    #[arg(short = 'j', long)]
    json: bool,

    /// Write JSON output to a file.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Hide security headers section in output.
    #[arg(long)]
    no_headers: bool,

    /// Hide links section in output.
    #[arg(long)]
    no_links: bool,

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
        // Loop: parse each line
        for line in content.lines() {
            let line = line.trim();
            // Check: skip empty lines and comments
            if !line.is_empty() && !line.starts_with('#') {
                if !targets.contains(&line.to_string()) {
                    targets.push(line.to_string());
                }
            }
        }
    }

    targets
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
        println!("  {} No targets provided", "✗".color(TOKYO_PINK).bold());
        println!("  {} reap example.com", "Usage:".color(TOKYO_PINK));
        println!("  {} reap -f targets.txt -c 50 -j -o results.json", "       ".color(TOKYO_PINK));
        return;
    }

    // Step: print run configuration
    println!("  {} {} {}", "▸".color(TOKYO_BLUE).bold(), "Targets".color(TOKYO_BLUE), format!("{} hosts", targets.len()).color(TOKYO_PINK));
    println!("  {} {} {}", "▸".color(TOKYO_BLUE).bold(), "Concurrency".color(TOKYO_BLUE), format!("{} workers", args.concurrency).color(TOKYO_PINK));
    divider();

    let concurrency = args.concurrency.max(1);
    let jitter_ms = args.jitter;
    let proxy = args.proxy.clone();
    let start = Instant::now();
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut handles = Vec::new();

    // Loop: spawn concurrent scan tasks with semaphore limiting
    for target in targets {
        let sem = sem.clone();
        let proxy = proxy.clone();
        handles.push(tokio::spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return crate::models::ReapResult {
                    target: target.clone(),
                    error: Some("Semaphore closed".to_string()),
                    ..Default::default()
                },
            };
            crate::stealth::jitter(jitter_ms).await;
            http::fetch(&target, proxy.as_deref()).await
        }));
    }

    // Step: collect and display results
    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(r) => {
                if !args.json {
                    result(&r, !args.no_headers, !args.no_links);
                    println!();
                }
                results.push(r);
            }
            Err(e) => {
                println!("  {} {}", "✗".color(TOKYO_PINK).bold(), format!("Task failed: {}", e).color(TOKYO_PINK));
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

    // Branch: save results to file if requested
    if let Some(path) = &args.output {
        let out = serde_json::to_string_pretty(&results).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            println!("  {} {}", "✗".color(TOKYO_BLUE).bold(), format!("Write failed: {}", e).color(TOKYO_BLUE));
        } else {
            info(&format!("Saved to {}", path.display()));
        }
    }

    // Handle: print final summary
    summary(results.len(), elapsed, false);
}
