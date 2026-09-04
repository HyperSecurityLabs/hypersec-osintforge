/// Auspex — Display & Output Formatting
///
/// Handles terminal rendering of WHOIS, RDAP, DNS, and other
/// intelligence results with color-coded sections and key-value pairs.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::AuspexResult;
use colored::{Color, Colorize};

/// Renders the Auspex ASCII banner with gradient coloring.
pub fn banner() {
    let b = r#"
▄▄▄       █    ██   ██████  ██▓███  ▓█████ ▒██   ██▒
▒████▄     ██  ▓██▒▒██    ▒ ▓██░  ██▒▓█   ▀ ▒▒ █ █ ▒░
▒██  ▀█▄  ▓██  ▒██░░ ▓██▄   ▓██░ ██▓▒▒███   ░░  █   ░
░██▄▄▄▄██ ▓▓█  ░██░  ▒   ██▒▒██▄█▓▒ ▒▒▓█  ▄  ░ █ █ ▒
▓█   ▓██▒▒▒█████▓ ▒██████▒▒▒██▒ ░  ░░▒████▒▒██▒ ▒██▒
▒▒   ▓▒█░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░░ ▒░ ░▒▒ ░ ░▓ ░
 ▒   ▒▒ ░░░▒░ ░ ░ ░ ░▒  ░ ░░▒ ░      ░ ░  ░░░   ░▒ ░
 ░   ▒    ░░░ ░ ░ ░  ░  ░  ░░          ░    ░    ░
     ░  ░   ░           ░              ░  ░ ░    ░

    Intelligence • Discovery • Correlation
    "#;
    let stops: [(u8, u8, u8); 4] = [
        (173, 216, 230), // light blue
        (0, 200, 255),   // cyan
        (200, 180, 255), // lavender
        (0, 180, 120),   // jade
    ];
    // Render with gradient interpolation
    let lines: Vec<&str> = b.lines().collect();
    let total = lines.len();
    for (i, line) in lines.iter().enumerate() {
        let t = i as f64 / (total - 1).max(1) as f64;
        let segs = (stops.len() - 1) as f64;
        let seg = (t * segs).min(segs - 0.0001) as usize;
        let local_t = (t * segs - seg as f64).min(1.0);
        let s = &stops[seg];
        let e = &stops[(seg + 1).min(stops.len() - 1)];
        let r = (s.0 as f64 + (e.0 as f64 - s.0 as f64) * local_t) as u8;
        let g = (s.1 as f64 + (e.1 as f64 - s.1 as f64) * local_t) as u8;
        let b = (s.2 as f64 + (e.2 as f64 - s.2 as f64) * local_t) as u8;
        println!("{}", line.truecolor(r, g, b));
    }
}

/// Prints a section header.
pub fn section(title: &str) {
    println!(
        "  {} {}",
        "◆".bright_magenta().bold(),
        title.bright_cyan().bold()
    );
}

/// Prints a key-value pair if the value is non-empty.
pub fn kv(key: &str, value: &str) {
    if value.is_empty() || value == "?" {
        return;
    }
    println!(
        "    {} {} {}",
        "▸".magenta().dimmed(),
        format!("{:25}", key).bright_cyan().dimmed(),
        value.white()
    );
}

/// Prints a blank line to end a section.
pub fn section_end() {
    println!();
}

/// Renders the full AuspexResult with all available intelligence sections.
pub fn result(r: &AuspexResult) {
    section("TARGET");
    kv("Domain", &r.target);
    section_end();

    // WHOIS section
    if let Some(w) = &r.whois {
        section("WHOIS");

        let status_text = if r.is_registered { "REGISTERED".green() } else { "AVAILABLE / UNREGISTERED".bright_red() };
        println!(
            "    {} {} {}",
            "◆".color(if r.is_registered { Color::Green } else { Color::BrightRed }).bold(),
            "Registration".color(if r.is_registered { Color::Green } else { Color::BrightRed }),
            status_text.bold()
        );

        if let Some(age) = r.domain_age_days {
            let years = age / 365;
            let days = age % 365;
            kv("Domain Age", &format!("{} years, {} days", years, days));
        }

        if let Some(exp) = r.days_until_expiry {
            let exp_str = format!("{} days", exp);
            if exp < 0 {
                kv("Expires In", &exp_str);
                kv("Expiry Status", "EXPIRED");
            } else if exp < 30 {
                kv("Expires In", &exp_str);
                kv("Expiry Status", "CRITICAL");
            } else if exp < 90 {
                kv("Expires In", &exp_str);
                kv("Expiry Status", "WARNING");
            } else {
                kv("Expires In", &exp_str);
                kv("Expiry Status", "OK");
            }
        }

        if let Some(ref s) = w.source_server { kv("WHOIS Server", s); }
        if let Some(ref s) = w.registrar { kv("Registrar", s); }
        if let Some(ref s) = w.registrar_iana_id { kv("Registrar IANA ID", s); }
        if let Some(ref s) = w.registrant_org { kv("Registrant Org", s); }
        if let Some(ref s) = w.registrant_name { kv("Registrant Name", s); }
        if let Some(ref s) = w.registrant_email { kv("Registrant Email", s); }
        if let Some(ref s) = w.registrant_phone { kv("Registrant Phone", s); }
        if let Some(ref s) = w.registrant_country { kv("Registrant Country", s); }
        if let Some(ref s) = w.admin_email { kv("Admin Email", s); }
        if let Some(ref s) = w.admin_name { kv("Admin Name", s); }
        if let Some(ref s) = w.tech_email { kv("Tech Email", s); }
        if let Some(ref s) = w.abuse_email { kv("Abuse Email", s); }
        if let Some(ref s) = w.creation_date { kv("Created", &s.format("%Y-%m-%d %H:%M:%S UTC").to_string()); }
        if let Some(ref s) = w.expiration_date { kv("Expires", &s.format("%Y-%m-%d %H:%M:%S UTC").to_string()); }
        if let Some(ref s) = w.updated_date { kv("Updated", &s.format("%Y-%m-%d %H:%M:%S UTC").to_string()); }
        if let Some(ref s) = w.dnssec { kv("DNSSEC", s); }
        if !w.status_codes.is_empty() {
            let codes = w.status_codes.join(", ");
            kv("Status", &codes);
        }

        section_end();
    }

    // Name Servers
    if let Some(w) = &r.whois {
        if !w.name_servers.is_empty() {
            section("NAME SERVERS");
            for ns in &w.name_servers {
                println!(
                    "    {} {}",
                    "↗".bright_cyan().dimmed(),
                    ns.white()
                );
            }
            section_end();
        }
    }

    // RDAP section
    if let Some(rd) = &r.rdap {
        section("RDAP");
        kv("Source", &rd.source);
        if !rd.events.is_empty() {
            for ev in &rd.events {
                if let Some(ref d) = ev.date {
                    kv(&format!("Event: {}", ev.action), &d.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                }
            }
        }
        for ent in &rd.entities {
            if let Some(ref n) = ent.name { kv(&format!("Entity ({})", ent.role), n); }
            if let Some(ref o) = ent.org { kv(&format!("Org ({})", ent.role), o); }
            if let Some(ref e) = ent.email { kv(&format!("Email ({})", ent.role), e); }
        }
        section_end();
    }

    // DNS correlation section
    if let Some(d) = &r.dns {
        section("DNS CORRELATION");
        if !d.ns.is_empty() { kv("Name Servers", &d.ns.join(", ")); }
        if !d.mx.is_empty() { kv("MX", &d.mx.join(", ")); }
        if !d.a_records.is_empty() { kv("A Records", &d.a_records.join(", ")); }
        if !d.aaaa_records.is_empty() { kv("AAAA Records", &d.aaaa_records.join(", ")); }
        if let Some(ref c) = d.cname { kv("CNAME", c); }
        if !d.txt.is_empty() {
            for t in &d.txt { kv("TXT", t); }
        }
        section_end();
    }

    // Error display
    if let Some(e) = &r.error {
        println!(
            "  {} {}",
            "⚠".bright_red().bold(),
            e.bright_yellow()
        );
    }
}
