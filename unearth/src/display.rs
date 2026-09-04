/// Terminal display utilities for UNEARTH with a light-blue / jade colour scheme.
use colored::*;

/// Pale light-blue accent colour.
pub const LIGHT_BLUE: Color = Color::TrueColor { r: 173, g: 216, b: 230 };
/// Jade-green accent colour.
pub const JADE: Color = Color::TrueColor { r: 0, g: 168, b: 107 };

/// Print the UNEARTH ASCII-art banner.
pub fn banner() {
    println!(
        "{}",
        r#"
    ⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣶⣶⣶⣶⣤⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⡀⠀⠀⠀
    ⠀⠀⠀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀
    ⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣷⡀
    ⠀⣾⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣷
    ⢰⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⣿⣿⣿⣿
    ⢸⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⢀⣀⣀⣀⡀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡿
    ⠸⣿⣿⣿⣿⣿⣿⣧⡀⠀⢰⣿⣿⣿⣿⣿⡆⠀⣸⣿⣿⣿⣿⣿⣿⠃
    ⠀⢻⣿⣿⣿⣿⣿⣿⣷⣄⠈⠻⣿⣿⣿⠟⢁⣼⣿⣿⣿⣿⣿⣿⡟⠀
    ⠀⠈⢿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣤⣤⣤⣴⣾⣿⣿⣿⣿⣿⣿⡿⠁⠀
    ⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠀⠀⠀
    ⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
"#
        .color(LIGHT_BLUE)
    );
    println!(
        "  {} v{} — {}",
        "U N E A R T H".bold().color(LIGHT_BLUE),
        "0.1.0".color(JADE),
        "Origin IP Discovery Framework".color(LIGHT_BLUE)
    );
    println!(
        "  {}",
        "4 Toolkit Suite: Recon | Scanner | Tracer | Matcher"
            .color(JADE)
    );
    println!();
}

/// Print a toolkit section header with numbering.
pub fn toolkit_header(name: &str, number: usize) {
    println!(
        "{} {} {}{}",
        "[".bold().color(LIGHT_BLUE),
        number.to_string().color(JADE).bold(),
        "/4]".bold().color(LIGHT_BLUE),
        format!(" Toolkit: {}", name).bold().color(LIGHT_BLUE)
    );
    println!("{}", "─".repeat(50).color(LIGHT_BLUE).dimmed());
}

/// Print a discovery line (positive finding).
pub fn found(text: &str, detail: &str) {
    println!(
        "  {} {} {}",
        "+".color(JADE).bold(),
        text.color(LIGHT_BLUE),
        detail.color(JADE)
    );
}

/// Print an informational line.
pub fn info(text: &str) {
    println!("  {} {}", "•".color(LIGHT_BLUE).dimmed(), text.dimmed());
}

/// Print a warning / high-confidence finding.
pub fn warning(text: &str) {
    println!("  {} {}", "!".color(JADE).bold(), text.color(LIGHT_BLUE));
}

/// Print a section separator with title.
pub fn section(title: &str) {
    println!("\n  {} {}", "▸".color(JADE).bold(), title.bold().color(LIGHT_BLUE));
}

/// Print a labelled result line.
pub fn result_line(label: &str, value: &str) {
    println!(
        "    {}: {}",
        label.color(JADE),
        value.color(LIGHT_BLUE)
    );
}
