/// Terminal display and formatting for PRY reconnaissance results.
///
/// Provides themed output functions using a crimson-and-gold color palette
/// for banners, result printing, and summary display.
use crate::models::LookupResult;
use colored::*;

/// Crimson red color for primary accents.
pub const CRIMSON: Color = Color::TrueColor { r: 220, g: 20, b: 60 };
/// Gold color for secondary accents.
pub const GOLD: Color = Color::TrueColor { r: 255, g: 215, b: 0 };

/// Print the PRY ASCII banner to stdout.
pub fn banner() {
    println!(
        "{}",
        r#"
+--------------------------------------------------+
|                                                  |
|  ░█▀-█ ░█▀▀█ ░█───█                              |
|  ░█▄▄█ ░█▄▄▀ ░█▄▄▄█                              |
|  ░█─░  ░█─░█ ──░█──                              |
|                                                  |
|  Precision Reconnaissance Yield                  |
|  KhaninKali                                      |
|                                                  |
+--------------------------------------------------+
"#
        .color(CRIMSON)
    );
    println!(
        "  {} v{} — {}",
        "P R Y".bold().color(CRIMSON),
        "0.2.0".color(GOLD),
        "Domain / IP Intelligence Framework".color(CRIMSON)
    );
    println!(
        "  {}",
        "RDAP + WHOIS + DNS Engine".color(GOLD)
    );
    println!();
}

/// Print a formatted LookupResult to the terminal.
///
/// When `raw` is true, dumps the raw WHOIS text instead of parsed fields.
pub fn result(result: &LookupResult, raw: bool) {
    // Step: print the target header
    println!(
        "{} {} {}",
        "┌──".color(CRIMSON).bold(),
        result.target.bold().color(CRIMSON),
        "──".color(CRIMSON).bold()
    );

    // Branch: if the result contains an error, print and return early
    if let Some(ref e) = result.error {
        println!("  {} {}", "✗".color(CRIMSON).bold(), e.color(CRIMSON));
        return;
    }

    // Branch: raw mode — print raw WHOIS text
    if raw {
        let all_raw = if !result.raw_referral.is_empty() {
            format!("{}\n\n══════════════════ REFERRAL ══════════════════\n\n{}", result.raw_whois, result.raw_referral)
        } else {
            result.raw_whois.clone()
        };
        if !all_raw.is_empty() {
            for line in all_raw.lines() {
                println!("  {}", line.color(CRIMSON).dimmed());
            }
            field("Source", &result.source);
            return;
        }
    }

    // Handle: registrar fields
    if let Some(ref v) = result.registrar {
        field("Registrar", v);
    }
    if let Some(ref v) = result.registrar_url {
        field("Registrar URL", v);
    }
    if let Some(ref v) = result.registrar_iana_id {
        field("Registrar IANA ID", v);
    }
    if let Some(ref v) = result.domain_registry_id {
        field("Registry Domain ID", v);
    } else if let Some(ref v) = result.domain_id {
        field("Domain", v);
    }
    if let Some(ref v) = result.creation_date {
        field("Created", v);
    }
    if let Some(ref v) = result.expiration_date {
        field("Expires", v);
    }
    if let Some(ref v) = result.updated_date {
        field("Updated", v);
    }

    // Handle: registrant contact fields
    if let Some(ref v) = result.registrant_name {
        field("Registrant Name", v);
    }
    if let Some(ref v) = result.registrant_org {
        field("Registrant Org", v);
    }
    if let Some(ref v) = result.registrant_email {
        field("Registrant Email", v);
    }
    if let Some(ref v) = result.registrant_phone {
        field("Registrant Phone", v);
    }
    if let Some(ref v) = result.registrant_street {
        field("Registrant Street", v);
    }
    if let Some(ref v) = result.registrant_city {
        field("Registrant City", v);
    }
    if let Some(ref v) = result.registrant_state {
        field("Registrant State", v);
    }
    if let Some(ref v) = result.registrant_country {
        field("Registrant Country", v);
    }
    if let Some(ref v) = result.registrant_zip {
        field("Registrant ZIP", v);
    }

    // Handle: admin contact fields
    if let Some(ref v) = result.admin_org {
        field("Admin Org", v);
    }
    if let Some(ref v) = result.admin_email {
        field("Admin Email", v);
    }
    if let Some(ref v) = result.admin_phone {
        field("Admin Phone", v);
    }

    // Handle: tech contact fields
    if let Some(ref v) = result.tech_org {
        field("Tech Org", v);
    }
    if let Some(ref v) = result.tech_name {
        field("Tech Name", v);
    }
    if let Some(ref v) = result.tech_street {
        field("Tech Street", v);
    }
    if let Some(ref v) = result.tech_city {
        field("Tech City", v);
    }
    if let Some(ref v) = result.tech_state {
        field("Tech State", v);
    }
    if let Some(ref v) = result.tech_zip {
        field("Tech ZIP", v);
    }
    if let Some(ref v) = result.tech_country {
        field("Tech Country", v);
    }
    if let Some(ref v) = result.tech_email {
        field("Tech Email", v);
    }
    if let Some(ref v) = result.tech_phone {
        field("Tech Phone", v);
    }

    // Handle: abuse, DNSSEC, status, DNS records
    if let Some(ref v) = result.abuse_email {
        field("Abuse", v);
    }
    if let Some(ref v) = result.dnssec {
        field("DNSSEC", v);
    }
    if !result.domain_status.is_empty() {
        field("Status", &result.domain_status.join(", "));
    }
    if !result.name_servers.is_empty() {
        field("NS", &result.name_servers.join(", "));
    }
    if !result.a_records.is_empty() {
        field("A", &result.a_records.join(", "));
    }
    if !result.aaaa_records.is_empty() {
        field("AAAA", &result.aaaa_records.join(", "));
    }

    // Check: warn if no data was returned
    if !result.has_data() && result.error.is_none() {
        warn("No data returned for this target");
    }

    // Handle: source attribution footer
    println!(
        "  {} {}",
        "Source:".color(GOLD),
        result.source.color(CRIMSON)
    );
}

/// Print a single label-value field with crimson and gold.
fn field(label: &str, value: &str) {
    println!(
        "    {}: {}",
        label.color(GOLD),
        value.color(CRIMSON)
    );
}

/// Print a warning message.
fn warn(text: &str) {
    println!("  {} {}", "⚠".color(GOLD).bold(), text.color(CRIMSON));
}

/// Print a horizontal divider.
pub fn divider() {
    println!("{}", "─".repeat(50).color(CRIMSON).dimmed());
}

/// Print an informational message.
pub fn info(text: &str) {
    println!("  {} {}", "•".color(CRIMSON).dimmed(), text.dimmed());
}

/// Print the final scan summary with total targets and elapsed time.
pub fn summary(total: usize, elapsed: f64) {
    println!();
    println!("{}", "═".repeat(55).color(CRIMSON).bold());
    println!(
        "  {} {}  {} results in {:.1}s",
        "PRY".bold().color(CRIMSON),
        "COMPLETE".color(GOLD).bold(),
        format!("{}", total).color(GOLD).bold(),
        elapsed
    );
    println!("{}", "═".repeat(55).color(CRIMSON).bold());
}
