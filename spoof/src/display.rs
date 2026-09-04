/// SPOOF — Display & Output Formatting
///
/// Renders spoofability assessment results with color-coded severity
/// levels for MX, SPF, DMARC, DKIM, and SMTP relay findings.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::SpoofResult;
use colored::*;

pub const BANNER: Color = Color::BrightCyan;
pub const BORDER: Color = Color::White;
pub const TEXT: Color = Color::BrightWhite;

/// Renders the SPOOF ASCII banner.
pub fn banner() {
    let inner = 50;
    let b = |s: &str| s.color(BORDER);
    let art = |s: &str| s.color(BANNER);
    let txt = |s: &str| s.color(TEXT);

    let art_pad = " ".repeat(inner - 2 - 31);
    let title_pad = " ".repeat(inner - 2 - 34);
    let author_pad = " ".repeat(inner - 2 - 18);

    println!("{}", b("+--------------------------------------------------+"));
    println!("{}", b("|                                                  |"));
    println!("|  {}{}|", art("░█▀▀▀ ░█▀▀█ ░█▀▀▀█ ░█▀▀▀█ ░█▀▀▀"), b(&art_pad));
    println!("|  {}{}|", art("▀▀▀▄▄ ░█▄▄█ ░█──░█ ░█──░█ ░█▀▀▀"), b(&art_pad));
    println!("|  {}{}|", art("░█▄▄▄ ░█─── ░█▄▄▄█ ░█▄▄▄█ ░█───"), b(&art_pad));
    println!("{}", b("|                                                  |"));
    println!("|  {}{}|", txt("Identity & Network Testing Toolkit"), b(&title_pad));
    println!("|  {}{}|", txt("Author: KhaninKali"), b(&author_pad));
    println!("{}", b("|                                                  |"));
    println!("{}", b("+--------------------------------------------------+"));
}

/// Maps a severity level string to its corresponding color.
fn severity_color(level: &str) -> Color {
    match level {
        "CRITICAL" => Color::TrueColor { r: 251, g: 73, b: 52 },
        "HIGH" => Color::TrueColor { r: 214, g: 93, b: 14 },
        "MEDIUM" => Color::TrueColor { r: 250, g: 189, b: 47 },
        "LOW" => Color::TrueColor { r: 69, g: 133, b: 136 },
        "SAFE" => Color::TrueColor { r: 152, g: 151, b: 26 },
        _ => Color::White,
    }
}

/// Renders the full assessment result with all sections.
pub fn result(r: &SpoofResult) {
    // Spoofability header
    let sc = severity_color(&r.spoofable.level);
    println!(
        "{} {} {} {}",
        "┌──".color(BORDER).bold(),
        "SPOOF".color(BANNER),
        "─".color(BORDER).bold().repeat(3),
        r.target.bold().color(TEXT),
    );
    println!(
        "  {} {}",
        format!("[{}]", r.spoofable.level).color(sc).bold(),
        r.spoofable.reason.color(TEXT),
    );

    // MX records
    if !r.mx.is_empty() {
        println!("  {} ", "└ MX Records:".color(BANNER).bold());
        for mx in &r.mx {
            let ip = mx.ip.as_deref().unwrap_or("?");
            println!("    {} {} (prio {})", format!("{:30}", mx.host).color(BORDER), ip.color(TEXT).dimmed(), mx.priority);
        }
    }

    // SPF
    if let Some(spf) = &r.spf {
        println!("  {} {}", "└ SPF:".color(BANNER).bold(), spf.raw.color(TEXT));
        println!("    {} {}", "Policy:".color(BORDER), format!("[{}]", spf.all).color(severity_color(
            if spf.all == "-all" { "SAFE" } else if spf.all == "~all" { "MEDIUM" } else { "HIGH" }
        )));
    } else {
        println!("  {}  {}", "└ SPF:".color(BANNER).bold(), "No SPF record found".color(TEXT));
    }

    // DMARC
    if let Some(dmarc) = &r.dmarc {
        println!("  {} {}", "└ DMARC:".color(BANNER).bold(), dmarc.raw.color(TEXT));
        println!("    {} {} ({}%)", "Policy:".color(BORDER),
            format!("[{}]", dmarc.policy).color(severity_color(
                if dmarc.policy == "reject" { "SAFE" }
                else if dmarc.policy == "quarantine" { "MEDIUM" }
                else { "HIGH" }
            )),
            dmarc.pct,
        );
    } else {
        println!("  {}  {}", "└ DMARC:".color(BANNER).bold(), "No DMARC record found".color(TEXT));
    }

    // DKIM
    if !r.dkim.is_empty() {
        println!("  {} ", "└ DKIM:".color(BANNER).bold());
        for dk in &r.dkim {
            let status = if dk.valid { "✔" } else { "✘" };
            println!("    {} {}  {}", format!("{:20}", dk.selector).color(BORDER), status.color(
                if dk.valid { Color::TrueColor { r: 152, g: 151, b: 26 } } else { Color::TrueColor { r: 204, g: 36, b: 29 } }
            ), dk.raw.color(TEXT));
        }
    } else {
        println!("  {}  {}", "└ DKIM:".color(BANNER).bold(), "No DKIM records found".color(TEXT));
    }

    // SMTP relay test
    if let Some(relay) = &r.relay {
        if relay.open_relay {
            println!("  {} {} {} {}",
                "└ Relay:".color(BANNER).bold(),
                "[OPEN RELAY]".on_color(Color::TrueColor { r: 124, g: 0, b: 0 }).color(TEXT).bold(),
                relay.host.color(BORDER),
                relay.banner.color(TEXT),
            );
        } else {
            println!("  {} {} {}",
                "└ Relay:".color(BANNER).bold(),
                "Not open".color(Color::TrueColor { r: 152, g: 151, b: 26 }),
                relay.host.color(BORDER),
            );
        }
    }

    println!(
        "  {} {}",
        "Source:".color(BORDER),
        "SPOOF v0.1.0".color(BANNER)
    );
}
