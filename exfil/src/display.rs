/// Terminal display utilities for EXFIL.
/// Defines color constants, the banner, severity-colour mapping,
/// and a structured results printer for CORS, IDOR, S3, and fuzz findings.
use colored::*;

pub const GRAVEL: Color = Color::TrueColor { r: 82, g: 79, b: 73 };
pub const JADE: Color = Color::TrueColor { r: 0, g: 170, b: 107 };
pub const LIGHT_BLUE: Color = Color::TrueColor { r: 137, g: 207, b: 240 };
pub const BRIGHT: Color = Color::BrightWhite;
pub const RED: Color = Color::TrueColor { r: 251, g: 73, b: 52 };
pub const ORANGE: Color = Color::TrueColor { r: 214, g: 93, b: 14 };
pub const YELLOW: Color = Color::TrueColor { r: 250, g: 189, b: 47 };

use crate::models::ExfilResult;

/// Print the EXFIL ASCII banner to stdout.
pub fn banner() {
    let inner = 50;
    let g = |s: &str| s.color(GRAVEL);
    let j = |s: &str| s.color(JADE);
    let b = |s: &str| s.color(LIGHT_BLUE);
    let w = |s: &str| s.color(BRIGHT);

    let art_pad = " ".repeat(inner - 2 - 27);

    println!("{}", g("+--------------------------------------------------+"));
    println!("{}", g("|                                                  |"));
    println!("|  {}{}|", j("░█▀▀▀ ░█─▄▀ ░█▀▀▀ ▀█▀ ░█───"), g(&art_pad));
    println!("|  {}{}|", j("░█▀▀▀ ░█▄▀─ ░█▀▀▀ ░█─ ░█───"), g(&art_pad));
    println!("|  {}{}|", j("░█▄▄▄ ░█─░█ ░█─── ▄█▄ ░█▄▄█"), g(&art_pad));
    println!("{}", g("|                                                  |"));
    println!("|  {}{}|", b("Data Bleed Scanner — CORS · IDOR · S3 · Fuzz"), g(&" ".repeat(inner - 2 - 44)));
    println!("|  {}{}|", w("Author: KhaninKali"), g(&" ".repeat(inner - 2 - 18)));
    println!("{}", g("|                                                  |"));
    println!("{}", g("+--------------------------------------------------+"));
}

/// Map a severity string to a terminal colour.
pub fn severity_color(level: &str) -> Color {
    match level {
        "CRITICAL" => RED,
        "HIGH" => ORANGE,
        "MEDIUM" => YELLOW,
        "LOW" => Color::TrueColor { r: 69, g: 133, b: 136 },
        "INFO" => Color::TrueColor { r: 92, g: 92, b: 92 },
        _ => BRIGHT,
    }
}

/// Print a structured human-readable summary of an `ExfilResult` to stdout.
pub fn result(r: &ExfilResult) {

    println!(
        "{} {} {} {}",
        "┌──".color(GRAVEL).bold(),
        "EXFIL".color(JADE),
        "─".color(GRAVEL).bold().repeat(3),
        r.target.bold().color(BRIGHT),
    );

    // Check: error present?
    if let Some(e) = &r.error {
        println!("  {} {}", "[ERROR]".color(RED).bold(), e.color(LIGHT_BLUE));
        return;
    }

    println!("  {} {} {} {}",
        "▸".color(JADE).bold(),
        format!("{}", r.endpoints_scanned).color(BRIGHT),
        "endpoints scanned,".color(LIGHT_BLUE),
        format!("{} vulnerabilities", r.vulnerabilities).color(if r.vulnerabilities > 0 { RED } else { JADE }).bold(),
    );

    // Step: print CORS results
    if !r.cors.is_empty() {
        println!("{} {}", "└ CORS Misconfigurations:".color(JADE).bold(), format!("[{}]", r.cors.len()).color(BRIGHT));
        for c in &r.cors {
            let sc = severity_color(&c.level);
            let mut parts = vec![
                format!("  ├ {}:{}", "Origin".color(GRAVEL), c.origin.color(LIGHT_BLUE)),
            ];
            if c.wildcard {
                parts.push(format!("  │   {} {}", "[WILDCARD *]".on_color(Color::TrueColor { r: 124, g: 0, b: 0 }).color(BRIGHT).bold(), "Access-Control-Allow-Origin: *".color(LIGHT_BLUE)));
            }
            if c.credentials {
                parts.push(format!("  │   {} {}", "[CREDENTIALS]".on_color(Color::TrueColor { r: 180, g: 60, b: 0 }).color(BRIGHT).bold(), "Access-Control-Allow-Credentials: true".color(LIGHT_BLUE)));
            }
            parts.push(format!("  └ {} [{}]", c.endpoint.color(GRAVEL), c.level.color(sc).bold()));
            for line in parts {
                println!("{}", line);
            }
        }
    }

    // Step: print IDOR results
    if !r.idor.is_empty() {
        println!("{} {}", "└ Potential IDORs:".color(JADE).bold(), format!("[{}]", r.idor.len()).color(BRIGHT));
        for id in &r.idor {
            let sc = severity_color(&id.level);
            let suspect = if id.potential_idor { "⚠" } else { "?" };
            println!("  {} {} {} → {} ({} vs {} bytes, {} vs {})",
                suspect.color(if id.potential_idor { RED } else { YELLOW }),
                id.parameter.color(GRAVEL),
                id.original_id.color(LIGHT_BLUE),
                id.test_id.color(LIGHT_BLUE),
                id.original_status, id.test_status,
                id.original_length, id.test_length,
            );
            println!("  └ {} [{}] {}", id.endpoint.color(GRAVEL), id.level.color(sc).bold(), "(different response)".color(LIGHT_BLUE));
        }
    }

    // Step: print S3 results
    if !r.s3.is_empty() {
        println!("{} {}", "└ S3 Bucket Access:".color(JADE).bold(), format!("[{}]", r.s3.len()).color(BRIGHT));
        for s in &r.s3 {
            let sc = severity_color(&s.level);
            let mut tags = vec![];
            if s.listable { tags.push("LISTABLE".color(RED).bold()); }
            if s.writable { tags.push("WRITABLE".on_color(Color::TrueColor { r: 124, g: 0, b: 0 }).color(BRIGHT).bold()); }
            if s.accessible { tags.push("PUBLIC".color(ORANGE).bold()); }
            let tag_str: Vec<String> = tags.iter().map(|t| format!("{}", t)).collect();
            println!("  {} {} [{}]",
                "▸".color(JADE),
                s.bucket_url.color(LIGHT_BLUE),
                tag_str.join(" ").color(sc),
            );
            println!("  └ {} [{}]", s.bucket_url.color(GRAVEL), s.level.color(sc).bold());
        }
    }

    // Step: print fuzz results
    if !r.fuzz.is_empty() {
        println!("{} {}", "└ Interesting Parameters:".color(JADE).bold(), format!("[{}]", r.fuzz.len()).color(BRIGHT));
        for f in &r.fuzz {
            let sc = severity_color(&f.level);
            let reflection = if f.reflection { " [REFLECTED]".color(ORANGE).to_string() } else { "".to_string() };
            println!("  {} {} = {} ({}b){}",
                "▸".color(JADE),
                f.parameter.color(GRAVEL),
                f.status.to_string().color(BRIGHT),
                f.body_length,
                reflection,
            );
            println!("  └ {} [{}]", f.endpoint.color(GRAVEL), f.level.color(sc).bold());
        }
    }

    println!(
        "  {} {}",
        "Source:".color(GRAVEL),
        "EXFIL v0.1.0".color(JADE)
    );
}
