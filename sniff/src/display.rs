/// Terminal display utilities for SNIFF output.
///
/// Implements a Rose Pine colour scheme and pretty-prints
/// [`SniffResult`] structs to the console with ANSI styling.
use crate::models::SniffResult;
use colored::*;

// Rose Pine color scheme
pub const ROSE_PINE_GOLD: Color = Color::TrueColor { r: 246, g: 193, b: 119 };
pub const ROSE_PINE_PINE: Color = Color::TrueColor { r: 49, g: 116, b: 143 };
pub const ROSE_PINE_ROSE: Color = Color::TrueColor { r: 235, g: 111, b: 146 };
pub const ROSE_PINE_FOAM: Color = Color::TrueColor { r: 156, g: 207, b: 216 };
pub const ROSE_PINE_LOVE: Color = Color::TrueColor { r: 235, g: 111, b: 146 };

/// Print the SNIFF ASCII banner to stdout.
pub fn banner() {
    let box_color = ROSE_PINE_GOLD;
    let top = "\
┌──────────────────────────────────────────────────────┐
│                                                      │
│  █▀▀ █▄░█ █ █▀▀ █▀▀                                  │
│  ▀▀█ █░▀█ █ █▀▀ █▀▀                                  │
│  ▀▀▀ ▀░░▀ ▀ ▀░░ ▀░░                                  │
│"
    .color(box_color);
    let name = "KhaninKali".italic().color(ROSE_PINE_FOAM);
    let pad = " ".repeat(40);
    let bot = "\
│                                                      │
└──────────────────────────────────────────────────────┘
"
    .color(box_color);

    println!("{top}  {name}{pad}│\n{bot}");
}

/// Pretty-print a single [`SniffResult`] to the terminal.
///
/// Displays the target, wildcard warning, subdomain table (with IP,
/// status code, title, source, takeover flag), and zone-transfer
/// details when available.
pub fn result(r: &SniffResult) {
    // Step: Print target header
    println!(
        "{} {} {}",
        "┌──".color(ROSE_PINE_ROSE).bold(),
        r.target.bold().color(ROSE_PINE_ROSE),
        "──".color(ROSE_PINE_ROSE).bold()
    );

    // Check: Wildcard DNS detected
    if r.wildcard {
        println!("  {} {}", "⚠".color(ROSE_PINE_LOVE).bold(), "Wildcard DNS".color(ROSE_PINE_LOVE));
    }

    // Branch: Subdomains found or empty state
    if r.subdomains.is_empty() {
        println!("  {} {}", "•".color(ROSE_PINE_FOAM), "No subdomains found".color(ROSE_PINE_PINE));
    } else {
        // Loop: Iterate over every discovered subdomain
        for sd in &r.subdomains {
            let ip_str = sd.ip.as_deref().unwrap_or("?");
            // Step: Build meta string from status-code colouring and title clipping
            let meta = {
                let s = if let Some(code) = sd.status_code {
                    let c = match code {
                        200..=299 => ROSE_PINE_PINE,
                        300..=399 => ROSE_PINE_GOLD,
                        400..=499 => ROSE_PINE_ROSE,
                        _ => ROSE_PINE_LOVE,
                    };
                    format!("[{}]", code).color(c).to_string()
                } else {
                    String::new()
                };
                let t = if let Some(t) = &sd.title {
                    let clipped = if t.len() > 40 { format!("{}...", &t[..40]) } else { t.clone() };
                    format!(" \"{}\"", clipped).color(ROSE_PINE_FOAM).dimmed().to_string()
                } else {
                    String::new()
                };
                format!("{}{}", s, t)
            };
            // Check: Takeover-flagged subdomain
            let takeover_flag = if sd.takeover.as_ref().is_some_and(|t| t.vulnerable) {
                format!(" {} {}", "⚠".color(ROSE_PINE_LOVE), "TAKEOVER".color(ROSE_PINE_LOVE).bold())
            } else {
                String::new()
            };
            // Branch: Print with or without meta context
            if meta.is_empty() {
                println!(
                    "    {:15} {} {} {}",
                    format!("{:15}", ip_str).color(ROSE_PINE_PINE),
                    sd.name.color(ROSE_PINE_GOLD),
                    format!("[{}]", sd.source).color(ROSE_PINE_FOAM).dimmed(),
                    takeover_flag,
                );
            } else {
                println!(
                    "    {} {:15} {} {} {}",
                    meta,
                    format!("{:15}", ip_str).color(ROSE_PINE_PINE),
                    sd.name.color(ROSE_PINE_GOLD),
                    format!("[{}]", sd.source).color(ROSE_PINE_FOAM).dimmed(),
                    takeover_flag,
                );
            }
        }
    }

    // Check: Zone transfer performed and succeeded
    if let Some(ref zt) = r.zone_transfer {
        if zt.success {
            println!(
                "  {} {}",
                "└ Zone Transfer: SUCCESS".color(ROSE_PINE_ROSE).bold(),
                zt.records.join(", ").color(ROSE_PINE_PINE)
            );
        }
    }

    // Step: Print source attribution footer
    println!(
        "  {} {}",
        "Source:".color(ROSE_PINE_GOLD),
        "SNIFF v0.1.0".color(ROSE_PINE_ROSE)
    );
}
