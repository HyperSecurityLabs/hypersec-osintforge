/// STALK — Identity mapper: cross-platform username correlation,
/// GitHub OSINT, breach checks, password pwned, and Google dorking.
///
/// Version: 3.3.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod breach;
mod display;
mod dork;
mod github;
mod models;
mod spinner;
mod stealth;
mod username;

use clap::Parser;
use colored::*;
use display::{banner, GB_AQUA, GB_BLUE, GB_BRIGHT_YELLOW, GB_GREEN, GB_RED};
use models::StalkResult;
use reqwest::Client;
use spinner::Spinner;
use std::time::Instant;

/// Command-line interface definition for STALK.
#[derive(Parser)]
#[command(name = "stalk")]
#[command(version = "3.3.0")]
#[command(about = "STALK — Identity mapper: cross-platform username correlation, GitHub OSINT, breach checks, Google dorking")]
struct Cli {
    #[arg(help = "Username or email to investigate")]
    target: Option<String>,

    #[arg(short = 'j', long, help = "JSON output (no banner, machine-readable)")]
    json: bool,

    #[arg(short = 'o', long, help = "Save results to file")]
    output: Option<String>,

    #[arg(short = 't', long, help = "Target type: username (default) or email")]
    target_type: Option<String>,

    #[arg(long, help = "Skip username platform scan (77 sites)")]
    no_username: bool,

    #[arg(long, help = "Skip GitHub API lookup")]
    no_github: bool,

    #[arg(long, help = "Skip HIBP breach check")]
    no_breach: bool,

    #[arg(long, help = "Skip Google dork generation")]
    no_dorks: bool,

    #[arg(long, help = "Check if password was pwned (k-anonymity)")]
    password_check: Option<String>,

    #[arg(short = 'P', long)]
    proxy: Option<String>,

    #[arg(long, default_value = "0", help = "Random delay (ms) before each request")]
    jitter: u64,
}

/// Build a reqwest HTTP client with optional proxy and stealth UA.
fn build_client(proxy: Option<&str>) -> Result<Client, String> {
    let mut builder = Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent(stealth::random_ua())
        .redirect(reqwest::redirect::Policy::limited(5));

    // Check: Apply optional proxy configuration
    if let Some(proxy_url) = proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }

    builder.build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))
}

/// Entry-point: parses CLI arguments and orchestrates all OSINT stages.
#[tokio::main]
async fn main() {
    // Step: Parse CLI arguments
    let args = Cli::parse();

    // Branch: Show banner when not in JSON mode
    if !args.json {
        banner();
    }

    let start = Instant::now();
    let mut result = StalkResult {
        ..Default::default()
    };

    // Dispatch: Password check mode (short-circuits all other stages)
    if let Some(pw) = &args.password_check {
        let spinner = Spinner::start("checking password breach status");
        let count = breach::check_password(pw).await;
        spinner.stop(if count > 0 { "⚠" } else { "✔" });
        // Branch: Terminal output vs JSON output
        if !args.json {
            if count > 0 {
                println!(
                    "  {} {} ({})",
                    "⚠".color(GB_RED).bold(),
                    "Password pwned".color(GB_RED),
                    format!("{} times", count).color(GB_BRIGHT_YELLOW)
                );
            } else {
                println!("  {} {}", "✔".color(GB_GREEN).bold(), "Password not found in breaches".color(GB_GREEN));
            }
        } else {
            let pw_result = serde_json::json!({
                "password": pw,
                "pwned_count": count,
            });
            println!("{}", serde_json::to_string_pretty(&pw_result).unwrap_or_default());
        }
        return;
    }

    // Step: Extract and normalise target
    let target = match &args.target {
        Some(t) => t.trim().to_lowercase(),
        None => {
            eprintln!("Usage: stalk <username|email>");
            return;
        }
    };

    let target_type = args.target_type.as_deref().unwrap_or("username");
    result.target = target.clone();
    result.target_type = target_type.to_string();

    // Branch: Print scanning header
    if !args.json {
        println!(
            "  {} {} {} {}",
            "▸".color(GB_BRIGHT_YELLOW).bold(),
            "Stalking".color(GB_BLUE),
            target_type.color(GB_AQUA),
            target.bold().color(GB_BRIGHT_YELLOW),
        );
    }

    // Step: Build shared HTTP client
    let client = match build_client(args.proxy.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    // Stage: Username enumeration across platforms
    if target_type == "username" && !args.no_username {
        let spinner = Spinner::start("scanning 77 platforms for accounts");
        let sites = username::enumerate(&target, &client, args.jitter).await;
        spinner.stop("✓");
        result.sites = sites;
    }

    // Stage: GitHub profile lookup
    if !args.no_github {
        let spinner = Spinner::start("fetching GitHub profile");
        let gh = github::lookup(&target).await;
        spinner.stop("✓");
        result.github = gh;
    }

    // Stage: Breach check (only for email-type targets)
    if !args.no_breach && target.contains('@') {
        let spinner = Spinner::start("checking email breach status");
        let breaches = breach::check_email(&target).await;
        spinner.stop("✓");
        result.breaches = breaches;
    }

    // Stage: Google dork generation
    if !args.no_dorks {
        result.dorks = if target.contains('@') {
            let domain = target.split('@').nth(1).unwrap_or(&target);
            dork::dorks_for_email(domain)
        } else {
            dork::dorks_for_username(&target)
        };
    }

    // Branch: Terminal output
    if !args.json {
        display::result(&result);
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "  {} {}",
            "▸".color(GB_BRIGHT_YELLOW).bold(),
            format!("done in {:.1}s", elapsed).color(GB_BLUE)
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
