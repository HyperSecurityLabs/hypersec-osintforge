/// Terminal display helpers — banner, result formatting, and summary output for WRING.
use crate::models::CertResult;
use colored::*;

pub const LAVENDER: Color = Color::TrueColor { r: 230, g: 180, b: 210 };
pub const RED: Color = Color::TrueColor { r: 200, g: 30, b: 45 };

/// Print the WRING ASCII banner.
pub fn banner() {
    println!(
        "{}",
        r#"
+--------------------------------------------------+
|                                                  |
|  ░█──░█ ░█▀▀█ ▀█▀ ░█▄─░█ ░█▀▀█                   |
|  ░█░█░█ ░█▄▄▀ ░█─ ░█░█░█ ░█──▀                   |
|  ░█▄▀▄█ ░█─░█ ▄█▄ ░█──▀█ ░█▄▄█                   |
|                                                  |
|  SSL/TLS Security Testing Toolkit                |
|  Author: KhaninKali                              |
|                                                  |
+--------------------------------------------------+
"#
        .color(LAVENDER)
    );
    println!(
        "  {} v{} — {}",
        "WRING".bold().color(LAVENDER),
        "0.1.0".color(RED),
        "SSL/TLS Security Testing Toolkit".color(LAVENDER)
    );
    println!();
}

/// Print the leaf or chain certificate details.
pub fn result_ptr(r: &CertResult, leaf: bool) {
    let tag = if leaf { "" } else { " (chain)" };

    println!(
        "  {} {} {}{}",
        "─".repeat(45).color(LAVENDER).dimmed(),
        "Subject:".color(RED).bold(),
        r.subject_cn.as_deref().unwrap_or("?"),
        tag
    );

    // Branch: print optional subject fields
    if let Some(ref v) = r.subject_o {
        field("Org", v);
    }
    if let Some(ref v) = r.subject_ou {
        field("OU", v);
    }
    if let Some(ref v) = r.subject_l {
        field("Locality", v);
    }
    if let Some(ref v) = r.subject_st {
        field("State", v);
    }
    if let Some(ref v) = r.subject_c {
        field("Country", v);
    }

    // Branch: print optional issuer fields
    if let Some(ref v) = r.issuer_cn {
        field("Issuer CN", v);
    }
    if let Some(ref v) = r.issuer_o {
        field("Issuer Org", v);
    }
    if let Some(ref v) = r.issuer_c {
        field("Issuer Country", v);
    }

    if let Some(ref v) = r.serial {
        field("Serial", v);
    }

    if !r.san_dns.is_empty() {
        field("SANs", &r.san_dns.join(", "));
    }

    if let Some(ref v) = r.not_before {
        field("Not Before", v);
    }
    if let Some(ref v) = r.not_after {
        let days = r.days_remaining.map(|d| format!(" ({} days)", d)).unwrap_or_default();
        field("Not After", &format!("{}{}", v, days.dimmed()));
    }

    if let Some(ref v) = r.sha256_fingerprint {
        field("SHA-256", &v.to_lowercase());
    }

    if let Some(ref v) = r.pub_key_algo {
        let sz = r.pub_key_size.map(|s| format!(" {} bit", s)).unwrap_or_default();
        field("Pubkey", &format!("{}{}", v, sz));
    }

    if !r.key_usage.is_empty() {
        field("Key Usage", &r.key_usage.join(", "));
    }
    if !r.ext_key_usage.is_empty() {
        field("Ext Key Usage", &r.ext_key_usage.join(", "));
    }
    if r.is_ca {
        field("CA", "true");
    }

    if !r.crl_urls.is_empty() {
        field("CRL", &r.crl_urls.join(", "));
    }
    if let Some(ref v) = r.ocsp_url {
        field("OCSP", v);
    }
}

/// Print a full result block for a single target.
pub fn result(r: &CertResult, saved: bool) {
    println!(
        "{} {} {}",
        "┌──".color(LAVENDER).bold(),
        format!("{}:{}", r.target, r.port).bold().color(LAVENDER),
        "──".color(LAVENDER).bold()
    );

    // Branch: if error occurred, print and return early
    if let Some(ref e) = r.error {
        println!("  {} {}", "✗".color(RED).bold(), e.color(LAVENDER));
        return;
    }

    // Step: print TLS connection details
    if let Some(ref v) = r.tls_version {
        field("TLS", v);
    }
    if let Some(ref v) = r.cipher_suite {
        field("Cipher", v);
    }
    field("Chain", &format!("{} certificates", r.chain_length));

    result_ptr(r, true);

    println!(
        "  {} {}",
        "Source:".color(RED),
        "WRING v0.1.0".color(LAVENDER)
    );

    // Branch: show download status if certificate was saved
    if saved {
        println!(
            "  {} {}",
            "Download:".color(RED),
            format!("certificate saved → {}", r.target).color(LAVENDER)
        );
    }
}

/// Print a labelled field line.
fn field(label: &str, value: &str) {
    println!(
        "    {}: {}",
        label.color(RED),
        value.color(LAVENDER)
    );
}

/// Print a horizontal divider line.
pub fn divider() {
    println!("{}", "─".repeat(50).color(LAVENDER).dimmed());
}

/// Print an informational message.
pub fn info(text: &str) {
    println!("  {} {}", "•".color(LAVENDER).dimmed(), text.dimmed());
}

/// Print a final summary line with total targets and elapsed time.
pub fn summary(total: usize, elapsed: f64) {
    println!();
    println!("{}", "═".repeat(55).color(LAVENDER).bold());
    println!(
        "  {} {}  {} targets in {:.1}s",
        "WRING".bold().color(LAVENDER),
        "COMPLETE".color(RED).bold(),
        format!("{}", total).color(RED).bold(),
        elapsed
    );
    println!("{}", "═".repeat(55).color(LAVENDER).bold());
}
