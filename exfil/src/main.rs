/// EXFIL — Data Bleed Scanner.
///
/// Version: 5.3.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod cors;
mod display;
mod fuzz;
mod idor;
mod models;
mod s3;
mod spinner;
mod stealth;

use clap::Parser;
use colored::*;
use display::{banner, GRAVEL, JADE, LIGHT_BLUE};
use spinner::Spinner;
use std::time::Instant;

/// CLI argument structure for exfil.
#[derive(Parser)]
#[command(name = "exfil")]
#[command(version = "0.1.0")]
#[command(about = "EXFIL — Data Bleed Scanner: CORS misconfiguration detection, IDOR pattern discovery, S3 bucket auditing, hidden parameter fuzzing, information disclosure analysis")]
struct Cli {
    #[arg(help = "Target URL or domain to scan")]
    target: Option<String>,

    #[arg(short = 'j', long, help = "JSON output (no banner, machine-readable)")]
    json: bool,

    #[arg(short = 'o', long, help = "Save results to file")]
    output: Option<String>,

    #[arg(long, help = "Skip CORS scanning")]
    no_cors: bool,

    #[arg(long, help = "Skip IDOR checking")]
    no_idor: bool,

    #[arg(long, help = "Skip S3 bucket checks")]
    no_s3: bool,

    #[arg(long, help = "Skip parameter fuzzing")]
    no_fuzz: bool,

    #[arg(long, help = "S3 bucket name to check (e.g. my-bucket)")]
    bucket: Option<String>,

    #[arg(short = 'P', long)]
    proxy: Option<String>,

    #[arg(long, default_value = "0")]
    jitter: u64,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Branch: print banner unless JSON mode
    if !args.json {
        banner();
    }

    let start = Instant::now();

    // Step: resolve the target URL
    let target = match &args.target {
        Some(t) => t.trim().to_lowercase(),
        None => {
            // Check: bucket provided?
            if let Some(b) = &args.bucket {
                format!("https://{}.s3.amazonaws.com", b)
            } else {
                eprintln!("Usage: exfil [OPTIONS] <target-url>");
                eprintln!("   or: exfil --bucket <bucket-name>");
                return;
            }
        }
    };

    if !args.json {
        println!(
            "  {} {} {}",
            "▸".color(JADE).bold(),
            "Scanning".color(GRAVEL),
            target.bold().color(LIGHT_BLUE),
        );
    }

    let mut result = models::ExfilResult {
        target: target.clone(),
        ..Default::default()
    };

    // Step: CORS scan
    if !args.no_cors {
        stealth::jitter(args.jitter).await;
        let sp = Spinner::start("checking CORS misconfigurations");
        result.cors = cors::check_cors(&target, args.proxy.as_deref()).await;
        result.endpoints_scanned += 1;
        sp.stop("✓");
    }

    // Step: IDOR check
    if !args.no_idor {
        stealth::jitter(args.jitter).await;
        let sp = Spinner::start("testing for IDOR patterns");
        result.idor = idor::check_idor(&target, args.proxy.as_deref()).await;
        result.endpoints_scanned += 1;
        sp.stop("✓");
    }

    // Step: S3 bucket check
    if !args.no_s3 {
        stealth::jitter(args.jitter).await;
        let sp = Spinner::start("auditing S3 bucket access");
        // Branch: bucket name explicitly provided?
        if let Some(bucket) = &args.bucket {
                result.s3 = s3::check_s3_bucket(bucket, args.proxy.as_deref()).await;
        } else {
            // Step: try extracting bucket from target
            let bucket = target
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('.')
                .next()
                .unwrap_or("");
            if !bucket.is_empty() && bucket != "s3" {
            result.s3 = s3::check_s3_bucket(bucket, args.proxy.as_deref()).await;
            }
        }
        result.endpoints_scanned += 1;
        sp.stop("✓");
    }

    // Step: parameter fuzzing
    if !args.no_fuzz {
        stealth::jitter(args.jitter).await;
        let sp = Spinner::start("fuzzing hidden parameters");
        result.fuzz = fuzz::fuzz_params(&target, args.proxy.as_deref()).await;
        result.endpoints_scanned += 1;
        sp.stop("✓");
    }

    // Step: count vulnerabilities
    result.vulnerabilities = (result.cors.len() + result.idor.iter().filter(|i| i.potential_idor).count()
        + result.s3.iter().filter(|s| s.accessible).count()
        + result.fuzz.len()) as u32;

    // Branch: display human-readable or JSON output
    if !args.json {
        display::result(&result);
        let elapsed = start.elapsed().as_secs_f64();
        println!(
            "  {} {}",
            "▸".color(JADE).bold(),
            format!("done in {:.1}s", elapsed).color(GRAVEL)
        );
    }

    // Branch: JSON mode
    if args.json {
        if let Ok(json) = serde_json::to_string_pretty(&result) {
            println!("{}", json);
        }
    }

    // Step: write output file if requested
    if let Some(path) = &args.output {
        let out = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            eprintln!("Write failed: {}", e);
        }
    }
}
