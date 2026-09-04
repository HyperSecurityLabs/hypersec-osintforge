/// Terminal display and formatting for LEAK secret scan results.
///
/// Provides themed output functions using a gruvbox-style color palette
/// for banners, result printing, severity coloring, and field display.
use crate::models::ScanResult;
use colored::*;

/// Bright cyan color for banner text.
pub const BANNER: Color = Color::BrightCyan;
/// White color for borders.
pub const BORDER: Color = Color::White;
/// Bright white color for primary text.
pub const TEXT: Color = Color::BrightWhite;

/// Gruvbox red color.
pub const GB_RED: Color = Color::TrueColor { r: 204, g: 36, b: 29 };
/// Gruvbox green color.
pub const GB_GREEN: Color = Color::TrueColor { r: 152, g: 151, b: 26 };
/// Gruvbox blue color.
pub const GB_BLUE: Color = Color::TrueColor { r: 69, g: 133, b: 136 };
/// Gruvbox aqua color.
pub const GB_AQUA: Color = Color::TrueColor { r: 104, g: 157, b: 106 };
/// Gruvbox orange color.
pub const GB_ORANGE: Color = Color::TrueColor { r: 214, g: 93, b: 14 };
/// Gruvbox gray color.
pub const GB_GRAY: Color = Color::TrueColor { r: 146, g: 131, b: 116 };
/// Gruvbox bright yellow color.
pub const GB_BRIGHT_YELLOW: Color = Color::TrueColor { r: 250, g: 189, b: 47 };
/// Gruvbox bright green color.
pub const GB_BRIGHT_GREEN: Color = Color::TrueColor { r: 184, g: 187, b: 38 };
/// Gruvbox foreground / light cream color.
pub const GB_FG: Color = Color::TrueColor { r: 235, g: 219, b: 178 };

/// Print the LEAK ASCII banner to stdout.
pub fn banner() {
    let b = |s: &str| s.color(BORDER);
    let a = |s: &str| s.color(BANNER);
    let name = "KhaninKali".italic().color(TEXT);

    let pad = " ".repeat(21);
    let name_pad = " ".repeat(40);

    println!("{}", b("┌──────────────────────────────────────────────────────┐"));
    println!("{}", b("│                                                      │"));
    println!("│  {}{}│", a("░█─── ░█▀▀▀ ─█▀▀█ ░█─▄▀"), b(&pad));
    println!("│  {}{}│", a("░█─── ░█▀▀▀ ░█▄▄█ ░█▀▄─"), b(&pad));
    println!("│  {}{}│", a("░█▄▄█ ░█▄▄▄ ░█─░█ ░█─░█"), b(&pad));
    println!("│  {}{}│", name, name_pad);
    println!("{}", b("│                                                      │"));
    println!("{}", b("└──────────────────────────────────────────────────────┘"));
}

/// Return the foreground severity color for a given severity level.
fn severity_color(sev: &str) -> Color {
    match sev {
        "critical" => Color::TrueColor { r: 251, g: 73, b: 52 },
        "high" => GB_ORANGE,
        "medium" => GB_BRIGHT_YELLOW,
        "low" => GB_BLUE,
        _ => GB_GRAY,
    }
}

/// Return the background severity color for a given severity level.
fn severity_bg(sev: &str) -> Color {
    match sev {
        "critical" => Color::TrueColor { r: 124, g: 0, b: 0 },
        "high" => Color::TrueColor { r: 100, g: 40, b: 0 },
        "medium" => Color::TrueColor { r: 80, g: 70, b: 0 },
        "low" => Color::TrueColor { r: 0, g: 40, b: 60 },
        _ => Color::TrueColor { r: 40, g: 40, b: 40 },
    }
}

/// Print a formatted ScanResult to the terminal with severity grouping.
pub fn result(r: &ScanResult) {
    // Step: print the target header
    println!(
        "{} {} {} {}",
        "┌──".color(BORDER).bold(),
        "LEAK".color(BANNER),
        "─".color(BORDER).bold().repeat(3),
        r.target.bold().color(TEXT),
    );

    // Step: group matches by severity
    let by_sev: Vec<(&str, Vec<&crate::models::SecretMatch>)> = {
        let mut crit = Vec::new();
        let mut high = Vec::new();
        let mut med = Vec::new();
        let mut low = Vec::new();
        for m in &r.matches {
            match m.severity.as_str() {
                "critical" => crit.push(m),
                "high" => high.push(m),
                "medium" => med.push(m),
                _ => low.push(m),
            }
        }
        vec![("CRITICAL", crit), ("HIGH", high), ("MEDIUM", med), ("LOW", low)]
    };

    // Step: print scanned summary line
    println!("  {} {} {} {}",
        "Scanned".color(GB_GRAY),
        format!("{} files", r.files_scanned).color(GB_BRIGHT_GREEN),
        "·".color(GB_GRAY),
        format!("{} secrets found", r.matches.len()).color(if r.matches.is_empty() { GB_GREEN } else { GB_RED }),
    );

    // Branch: no matches found — print success and return
    if r.matches.is_empty() {
        println!("  {} {}", "✔".color(GB_GREEN).bold(), "No secrets detected".color(GB_GREEN));
        return;
    }

    // Loop: print each severity group
    for (label, group) in &by_sev {
        // Check: skip empty groups
        if group.is_empty() {
            continue;
        }
        println!(
            "  {} {}",
            format!("└ {}:", label).color(severity_color(label)).bold(),
            format!("{} matches", group.len()).color(severity_color(label)),
        );
        // Loop: print each match in the group
        for m in group {
            let _sev_color = severity_color(&m.severity);
            let tag = format!(" {} ", m.severity.to_uppercase()).on_color(severity_bg(&m.severity)).color(severity_color(&m.severity)).bold();
            println!(
                "    {} {} {} {}",
                tag,
                m.pattern.color(GB_AQUA).bold(),
                format!("{}:{}", m.file, m.line).color(GB_GRAY).dimmed(),
                m.context.trim().color(GB_FG).dimmed(),
            );
        }
    }

    // Handle: source attribution footer
    println!(
        "  {} {}",
        "Source:".color(GB_BRIGHT_YELLOW),
        "LEAK v0.1.0".color(GB_RED)
    );
}
