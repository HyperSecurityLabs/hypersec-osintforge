/// LEAK — Secret Scanner
///
/// Version: 2.8.0
/// Author: khaninkali · HyperSecurity Offensive Labs
mod display;
mod models;
mod patterns;
mod scanner;
mod spinner;

use clap::Parser;
use colored::*;
use display::{banner, GB_AQUA, GB_BLUE, GB_BRIGHT_YELLOW};
use spinner::Spinner;
use std::path::PathBuf;
use std::time::Instant;

/// Command-line arguments for LEAK.
#[derive(Parser)]
#[command(name = "leak")]
#[command(version = "2.8.0")]
#[command(about = "LEAK — Secret scanner: API keys, tokens, credentials, and hardcoded secrets in files and git history")]
struct Cli {
    /// File or directory to scan.
    #[arg(help = "File or directory to scan")]
    target: Option<String>,

    /// Output results as JSON.
    #[arg(short = 'j', long, help = "JSON output (no banner, machine-readable)")]
    json: bool,

    /// Save results to file.
    #[arg(short = 'o', long, help = "Save results to file")]
    output: Option<PathBuf>,

    /// Scan git commit history.
    #[arg(long, help = "Scan git commit history (requires git binary)")]
    git: bool,

    /// Enable low-severity patterns (hashes, certs).
    #[arg(long, help = "Enable low-severity patterns (hashes, certs)")]
    entropy: bool,

    /// Additional ignore patterns (can repeat).
    #[arg(short = 'i', long, help = "Additional ignore pattern (can repeat)")]
    ignore: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();

    // Step: print banner unless JSON mode
    if !args.json {
        banner();
    }

    let start = Instant::now();

    // Step: validate and resolve the target path
    let target = match &args.target {
        Some(t) => t.trim().to_string(),
        None => {
            eprintln!("Usage: leak <file|directory>");
            return;
        }
    };

    let path = std::path::Path::new(&target);
    // Check: target must exist
    if !path.exists() {
        eprintln!("Error: {} not found", target);
        return;
    }

    // Step: print scanning info (non-JSON mode)
    if !args.json {
        println!(
            "  {} {} {}",
            "▸".color(GB_BRIGHT_YELLOW).bold(),
            ("Scanning ".to_string() + if path.is_dir() { "directory" } else { "file" }).color(GB_BLUE),
            target.bold().color(GB_AQUA),
        );
    }

    let spinner = Spinner::start("scanning for secrets");

    let max_size: u64 = 5 * 1024 * 1024;
    let enable_low = args.entropy;

    // Step: scan files (directory or single file)
    let (mut file_matches, files_scanned) = if path.is_dir() {
        scanner::scan_dir(path, max_size, enable_low, !enable_low)
    } else {
        scanner::scan_file(path, max_size, enable_low, !enable_low)
    };

    // Step: scan git history (optional)
    let git_matches = if args.git && path.is_dir() {
        spinner.stop("✓");
        let git_spinner = Spinner::start("scanning git history");
            let (gm, _) = scanner::scan_git(path, enable_low, !enable_low);
        git_spinner.stop("✓");
        gm
    } else {
        Vec::new()
    };

    // Step: combine file and git matches
    file_matches.extend(git_matches);

    // Step: deduplicate matches by file:line:pattern
    let mut seen = std::collections::HashSet::new();
    let unique_matches: Vec<_> = file_matches.into_iter().filter(|m| {
        let key = format!("{}:{}:{}", m.file, m.line, m.pattern);
        seen.insert(key)
    }).collect();

    // Handle: stop spinner with success/warning icon
    spinner.stop(
        if unique_matches.is_empty() { "✔" } else { "⚠" }
    );

    // Step: build the scan result
    let result = models::ScanResult {
        target: target.clone(),
        files_scanned,
        matches: unique_matches,
        error: None,
    };

    // Branch: display result unless JSON mode
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

    // Branch: write JSON output to file
    if let Some(path) = &args.output {
        let out = serde_json::to_string_pretty(&result).unwrap_or_default();
        if let Err(e) = std::fs::write(path, &out) {
            eprintln!("Write failed: {}", e);
        }
    }
}
