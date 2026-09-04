/// Terminal display and formatting for IdentifyNet scan results.
///
/// Provides themed output functions using a Tokyo-night color palette
/// for banners, result printing, and field display.
use crate::models::IdentifyResult;
use colored::*;

/// Tokyo-night blue color constant.
pub const TOKYO_BLUE: Color = Color::TrueColor { r: 122, g: 162, b: 247 };
/// Tokyo-night pink color constant.
pub const TOKYO_PINK: Color = Color::TrueColor { r: 247, g: 118, b: 142 };

/// Print the IdentifyNet ASCII banner to stdout.
pub fn banner() {
    println!(
        "{}",
        r#"
┌──────────────────────────────────────────────────────┐
│                                                      │
│ ░█▀▀█ ░█▀▀▄ ░█▀▀▀ ░█▄─░█ ▀▀█▀▀ ▀█▀ ░█▀▀▀ ░█──░█      │
│ ──░█─ ░█──█ ░█▀▀▀ ░█░█░█ ─░█── ░█─ ░█▀▀▀ ─░█░█─      │
│ ░█▄▄█ ░█▄▄▀ ░█▄▄▄ ░█──▀█ ─░█── ▄█▄ ░█    ──▀▄▀──     │
│                                                      │
│  IP Intelligence & Geolocation Engine                │
│  KhaninKali                                          │
│                                                      │
└──────────────────────────────────────────────────────┘
"#
        .color(TOKYO_BLUE)
    );
}

/// Print a formatted IdentifyResult to the terminal.
pub fn result(r: &IdentifyResult) {
    // Dispatch: print target header line
    println!(
        "{} {} {}",
        "┌──".color(TOKYO_PINK).bold(),
        r.target.bold().color(TOKYO_PINK),
        "──".color(TOKYO_PINK).bold()
    );

    // Branch: if the result contains an error, print and return early
    if let Some(ref e) = r.error {
        println!("  {} {}", "✗".color(TOKYO_PINK).bold(), e.color(TOKYO_PINK));
        return;
    }

    // Handle: IP address field
    if let Some(ref v) = r.ip {
        field("IP", v);
    }

    // Handle: geolocation block
    if let Some(ref geo) = r.geo {
        divider("Geolocation");
        if let Some(ref v) = geo.city {
            field("City", v);
        }
        if let Some(ref v) = geo.state {
            field("State", v);
        }
        if let Some(ref v) = geo.country {
            let cc = geo.country_code.as_deref().unwrap_or("");
            let suffix = if cc.is_empty() { String::new() } else { format!(" ({})", cc) };
            field("Country", &format!("{}{}", v, suffix));
        }
        if let Some(ref v) = geo.postal {
            field("Postal", v);
        }
        if let (Some(lat), Some(lon)) = (geo.latitude, geo.longitude) {
            field("Coordinates", &format!("{:.4}, {:.4}", lat, lon));
        }
        if let Some(ref v) = geo.timezone {
            field("Timezone", v);
        }
    }

    // Handle: ASN block
    if let Some(ref asn) = r.asn {
        divider("ASN");
        if let Some(v) = asn.number {
            field("ASN", &format!("AS{}", v));
        }
        if let Some(ref v) = asn.organization {
            field("Organization", v);
        }
        if let Some(ref v) = asn.network {
            field("Network", v);
        }
    }

    // Handle: DNS block
    if let Some(ref dns) = r.dns {
        divider("DNS");
        if let Some(ref v) = dns.ptr {
            field("PTR", v);
        }
        if !dns.mx.is_empty() {
            field("MX", &dns.mx.join(", "));
        }
        if !dns.ns.is_empty() {
            field("NS", &dns.ns.join(", "));
        }
        if !dns.txt.is_empty() {
            field("TXT", &dns.txt.join(", "));
        }
    }

    // Handle: WHOIS block
    if let Some(ref whois) = r.whois {
        divider("WHOIS");
        if let Some(ref v) = whois.netrange {
            field("NetRange", v);
        }
        if let Some(ref v) = whois.orgname {
            field("OrgName", v);
        }
        if let Some(ref v) = whois.tech_email {
            field("Tech Email", v);
        }
        if let Some(ref v) = whois.abuse_email {
            field("Abuse Email", v);
        }
    }

    // Handle: port scan block
    if let Some(ref ports) = r.ports {
        divider("Ports");
        if ports.open.is_empty() {
            field("Open", "none (top 20)");
        } else {
            for p in &ports.open {
                field(&p.port.to_string(), &p.service);
            }
        }
    }

    // Handle: source attribution footer
    println!(
        "  {} {}",
        "Source:".color(TOKYO_BLUE),
        "IdentifyNet v0.1.0".color(TOKYO_PINK)
    );
}

/// Print a single label-value field with Tokyo colors.
fn field(label: &str, value: &str) {
    println!(
        "    {}: {}",
        label.color(TOKYO_BLUE),
        value.color(TOKYO_PINK)
    );
}

/// Print a section divider header.
fn divider(label: &str) {
    println!("  {} {} {}", "└".color(TOKYO_PINK), label.color(TOKYO_BLUE).bold(), "──".color(TOKYO_PINK));
}
