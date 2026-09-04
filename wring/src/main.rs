/// WRING — SSL/TLS Security Testing Toolkit
///
/// Version: 2.2.6
/// Author: khaninkali · HyperSecurity Offensive Labs
mod display;
mod models;
mod parser;
mod tls;

use clap::Parser;
use colored::Colorize;
use display::{banner, divider, info, result, summary, LAVENDER, RED};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "wring")]
#[command(version = "2.2.6")]
#[command(about = "SSL/TLS Security Testing Toolkit")]
struct Cli {
    target: Option<String>,

    #[arg(short = 'f', long)]
    file: Option<PathBuf>,

    #[arg(short = 'p', long, default_value = "443")]
    port: u16,

    #[arg(short = 'j', long)]
    json: bool,

    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    #[arg(short = 'd', long)]
    download: bool,
}

/// Load targets from CLI argument and/or file.
fn load_targets(cli: &Cli) -> Vec<(String, u16)> {
    let mut targets = Vec::new();

    // Branch: add single target from positional argument
    if let Some(target) = &cli.target {
        targets.push((target.clone(), cli.port));
    }

    // Branch: load targets from file
    if let Some(path) = &cli.file {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cannot read {}: {}", path.display(), e);
                return targets;
            }
        };
        // Loop: parse each line (host:port or just host)
        for line in content.lines() {
            let line = line.trim();
            // Check: skip blanks and comments
            if !line.is_empty() && !line.starts_with('#') {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                let host = parts[0].trim().to_string();
                let port = parts
                    .get(1)
                    .and_then(|s| s.trim().parse::<u16>().ok())
                    .unwrap_or(443);
                let pair = (host, port);
                // Check: deduplicate
                if !targets.contains(&pair) {
                    targets.push(pair);
                }
            }
        }
    }

    targets
}

/// Save the certificate chain to a PEM file.
fn save_cert(result: &models::CertResult) -> String {
    use std::fmt::Write;

    // Step: sanitise hostname for filename
    let safe_host: String = result
        .target
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    let filename = format!("{}_{}.pem", safe_host, result.port);
    let mut pem = String::new();

    // Loop: encode each DER certificate to PEM
    for der in &result.chain_der {
        let _ = writeln!(pem, "-----BEGIN CERTIFICATE-----");
        let b64 = base64_encode(der);
        for chunk in b64.as_bytes().chunks(64) {
            let _ = writeln!(pem, "{}", std::str::from_utf8(chunk).unwrap_or(""));
        }
        let _ = writeln!(pem, "-----END CERTIFICATE-----");
    }

    let path = format!("certs/{}", filename);
    let _ = std::fs::create_dir_all("certs");
    let _ = std::fs::write(&path, &pem);
    path
}

/// Minimal base64 encoding (RFC 4648) without external dependencies.
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    // Loop: process 3 bytes at a time
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        // Branch: handle padding for incomplete triples
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    banner();

    // Step: load targets
    let targets = load_targets(&args);
    // Check: bail if no targets provided
    if targets.is_empty() {
        println!("  {} No targets provided", "✗".color(RED).bold());
        println!(
            "  {} knot example.com",
            "Usage:".color(RED)
        );
        println!(
            "  {} knot -f targets.txt -j -o results.json",
            "       ".color(RED)
        );
        println!(
            "  {} knot -d example.com",
            "       ".color(RED)
        );
        return;
    }

    // Step: print deployment summary
    println!(
        "  {} {} {}",
        "▸".color(LAVENDER).bold(),
        "Targets".color(LAVENDER),
        format!("{} hosts", targets.len()).color(RED)
    );
    println!(
        "  {} {} {}",
        "▸".color(LAVENDER).bold(),
        "Port".color(LAVENDER),
        format!("{}", args.port).color(RED)
    );
    println!(
        "  {} {} {}",
        "▸".color(LAVENDER).bold(),
        "Download".color(LAVENDER),
        if args.download { "certificates enabled".color(RED) } else { "off".color(RED) }
    );
    divider();

    let start = Instant::now();
    let mut results = Vec::new();

    // Loop: connect to each target and collect results
    for (host, port) in &targets {
        let r = tls::connect(host, *port).await;
        let mut saved = false;

        // Branch: save certificate if --download flag is set
        if args.download && !r.cert_der.is_empty() {
            let path = save_cert(&r);
            saved = true;
            info(&format!("Certificate saved: {}", path));
        }

        // Branch: print formatted result unless JSON mode
        if !args.json {
            result(&r, saved);
            println!();
        }

        results.push(r);
    }

    let elapsed = start.elapsed().as_secs_f64();

    // Branch: output JSON to stdout if --json flag is set
    if args.json {
        let mut json_results: Vec<models::CertResult> = results.clone();
        for r in &mut json_results {
            r.cert_der = Vec::new();
            r.chain_der = Vec::new();
        }
        if let Ok(json) = serde_json::to_string_pretty(&json_results) {
            println!("{}", json);
        }
    }

    // Branch: save JSON to file if --output is specified
    if let Some(path) = &args.output {
        let mut json_results: Vec<models::CertResult> = results.clone();
        for r in &mut json_results {
            r.cert_der = Vec::new();
            r.chain_der = Vec::new();
        }
        let out = serde_json::to_string_pretty(&json_results).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            println!("  {} {}", "✗".color(LAVENDER).bold(), format!("Write failed: {}", e).color(LAVENDER));
        } else {
            info(&format!("Saved to {}", path.display()));
        }
    }

    summary(results.len(), elapsed);
}
