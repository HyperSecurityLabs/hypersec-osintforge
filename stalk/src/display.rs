/// Terminal display utilities for STALK output with a Gruvbox colour scheme.
use crate::models::StalkResult;
use colored::*;

// Gruvbox dark scheme
pub const GB_FG: Color = Color::TrueColor { r: 235, g: 219, b: 178 };
pub const GB_YELLOW: Color = Color::TrueColor { r: 215, g: 153, b: 33 };
pub const GB_RED: Color = Color::TrueColor { r: 204, g: 36, b: 29 };
pub const GB_GREEN: Color = Color::TrueColor { r: 152, g: 151, b: 26 };
pub const GB_BLUE: Color = Color::TrueColor { r: 69, g: 133, b: 136 };
pub const GB_PURPLE: Color = Color::TrueColor { r: 177, g: 98, b: 134 };
pub const GB_AQUA: Color = Color::TrueColor { r: 104, g: 157, b: 106 };
pub const GB_ORANGE: Color = Color::TrueColor { r: 214, g: 93, b: 14 };
pub const GB_GRAY: Color = Color::TrueColor { r: 146, g: 131, b: 116 };

// Bright variants
pub const GB_BRIGHT_YELLOW: Color = Color::TrueColor { r: 250, g: 189, b: 47 };
pub const GB_BRIGHT_GREEN: Color = Color::TrueColor { r: 184, g: 187, b: 38 };
pub const GB_BRIGHT_BLUE: Color = Color::TrueColor { r: 131, g: 165, b: 152 };

/// Print the STALK ASCII banner to stdout.
pub fn banner() {
    let top = "\
┌──────────────────────────────────────────────────────┐
│                                                      │
│  ░█▀▀▀ ▀▀█▀▀ ─█▀▀█ ░█─── ░█─▄▀                     │
│  ▀▀▀▄▄ ─░█── ░█▄▄█ ░█─── ░█▀▄─                     │
│  ░█▄▄▄ ─░█── ░█─░█ ░█▄▄█ ░█─░█                     │
│"
    .color(GB_YELLOW);
    let name = "KhaninKali".italic().color(GB_AQUA);
    let pad = " ".repeat(40);
    let bot = "\
│                                                      │
└──────────────────────────────────────────────────────┘
"
    .color(GB_YELLOW);

    println!("{top}  {name}{pad}│\n{bot}");
}

/// Pretty-print a [`StalkResult`] with all sections: platform sites,
/// GitHub profile, breach data, and Google dorks.
pub fn result(r: &StalkResult) {
    // Step: Print target header line
    println!(
        "{} {} {} {}",
        "┌──".color(GB_RED).bold(),
        r.target_type.color(GB_PURPLE),
        "─".color(GB_RED).bold().repeat(3),
        r.target.bold().color(GB_RED),
    );

    // Section: Platform account results
    if !r.sites.is_empty() {
        let found: Vec<_> = r.sites.iter().filter(|s| s.exists).collect();
        // Branch: No accounts found vs listing found accounts
        if found.is_empty() {
            println!("  {} {}", "•".color(GB_AQUA), "No accounts found on any platform".color(GB_BLUE));
        } else {
            println!("  {} {} {}",
                format!("{}", found.len()).color(GB_BRIGHT_YELLOW).bold(),
                "accounts found".color(GB_AQUA),
                format!("(scanned {})", r.sites.len()).color(GB_GRAY).dimmed(),
            );
            // Loop: Print each found account
            for s in &found {
                println!(
                    "    {} {}",
                    format!("{:20}", s.name).color(GB_BRIGHT_YELLOW),
                    s.url.color(GB_BRIGHT_BLUE).dimmed(),
                );
            }
        }
    }

    // Section: GitHub profile
    if let Some(gh) = &r.github {
        println!(
            "  {} {}",
            "└ GitHub:".color(GB_RED).bold(),
            format!("@{}", gh.login).color(GB_AQUA),
        );
        if let Some(n) = &gh.name {
            println!("    {} {}", "Name:".color(GB_BRIGHT_YELLOW), n.color(GB_FG));
        }
        if let Some(b) = &gh.bio {
            println!("    {} {}", "Bio:".color(GB_BRIGHT_YELLOW), b.color(GB_FG).italic());
        }
        if let Some(e) = &gh.email {
            println!("    {} {}", "Email:".color(GB_BRIGHT_YELLOW), e.color(GB_BLUE));
        }
        if let Some(l) = &gh.location {
            println!("    {} {}", "Loc:".color(GB_BRIGHT_YELLOW), l.color(GB_FG));
        }
        println!(
            "    {} {} {} {}",
            "Stats:".color(GB_BRIGHT_YELLOW),
            format!("{} repos", gh.public_repos).color(GB_AQUA),
            "·".color(GB_GRAY),
            format!("{} followers", gh.followers).color(GB_AQUA),
        );
        // Check: Has repositories to display
        if !gh.repos.is_empty() {
            println!("    {} ", "Repos:".color(GB_BRIGHT_YELLOW));
            // Loop: Print each repository
            for repo in &gh.repos {
                println!(
                    "      {} {} {}",
                    repo.name.color(GB_BRIGHT_GREEN),
                    repo.language.as_deref().map(|l| format!("[{}]", l)).unwrap_or_default().color(GB_BLUE),
                    format!("★{}", repo.stars).color(GB_ORANGE),
                );
            }
        }
    }

    // Section: Breach results
    if !r.breaches.is_empty() {
        println!("  {} {}", "└ Breaches:".color(GB_RED).bold(), format!("{} found", r.breaches.len()).color(GB_RED));
        // Loop: Print each breach entry
        for b in &r.breaches {
            println!(
                "    {} {} ({} — {} accounts)",
                b.name.color(GB_RED),
                b.domain.color(GB_GRAY).dimmed(),
                b.breach_date.color(GB_BRIGHT_YELLOW),
                format_count(b.pwn_count).color(GB_BRIGHT_YELLOW),
            );
            if !b.data_classes.is_empty() {
                println!("      Classes: {}", b.data_classes.join(", ").color(GB_AQUA).dimmed());
            }
        }
    }

    // Section: Google dorks
    if !r.dorks.is_empty() {
        println!("  {} ", "└ Google Dorks:".color(GB_PURPLE).bold());
        // Loop: Print each dork query
        for d in &r.dorks {
            println!("    {}", d.color(GB_BLUE));
        }
    }

    // Step: Source attribution footer
    println!(
        "  {} {}",
        "Source:".color(GB_BRIGHT_YELLOW),
        "STALK v0.1.0".color(GB_RED)
    );
}

/// Format a pwn-count number with human-readable suffixes (K, M).
fn format_count(n: u32) -> String {
    // Branch: Millions
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    // Branch: Thousands
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}
