/// Terminal display and formatting for REAP scan results.
///
/// Provides themed output functions using a Tokyo-night color palette
/// for banners, result printing, summaries, and field display.
use crate::models::ReapResult;
use colored::*;

/// Tokyo-night blue color constant.
pub const TOKYO_BLUE: Color = Color::TrueColor { r: 122, g: 162, b: 247 };
/// Tokyo-night pink color constant.
pub const TOKYO_PINK: Color = Color::TrueColor { r: 247, g: 118, b: 142 };

/// Print the REAP ASCII banner to stdout.
pub fn banner() {
    println!(
        "{}",
        r#"
+--------------------------------------------------+
|                                                  |
|  ░█▀▀█ ░█▀▀▀ ─█▀▀█ ░█▀▀█                         |
|  ░█▄▄▀ ░█▀▀▀ ░█▄▄█ ░█▄▄█                         |
|  ░█─░█ ░█▄▄▄ ░█─░█ ░█───                         |
|                                                  |
|  Web Intelligence Profiler    v4.0.0             |
|  Author: KhaninKali                              |
|                                                  |
+--------------------------------------------------+
"#
        .color(TOKYO_BLUE)
    );
    println!(
        "  {} v{} — {}",
        "REAP".bold().color(TOKYO_BLUE),
        "4.0.0".color(TOKYO_PINK),
        "Web Intelligence Profiler".color(TOKYO_BLUE)
    );
    println!();
}

/// Print a single scan result with optional headers and links.
pub fn result(r: &ReapResult, show_headers: bool, show_links: bool) {
    // Step: print the target header line
    println!(
        "{} {} {}",
        "┌──".color(TOKYO_BLUE).bold(),
        r.target.bold().color(TOKYO_BLUE),
        "──".color(TOKYO_BLUE).bold()
    );

    // Branch: if the result contains an error, print and return early
    if let Some(ref e) = r.error {
        println!("  {} {}", "✗".color(TOKYO_PINK).bold(), e.color(TOKYO_BLUE));
        return;
    }

    let http = match r.http.as_ref() {
        Some(h) => h,
        None => {
            println!("  {} {}", "✗".color(TOKYO_PINK).bold(), "No HTTP data".color(TOKYO_BLUE));
            return;
        }
    };

    // Handle: display basic HTTP response fields
    if let Some(ref v) = http.final_url {
        field("URL", v);
    }
    if let Some(ref v) = http.status {
        field("Status", &v.to_string());
    }
    if let Some(ref v) = http.content_type {
        field("Type", v);
    }
    if let Some(ref v) = http.content_length {
        field("Size", &format!("{} bytes", v));
    }
    if let Some(ref v) = http.server {
        field("Server", v);
    }
    if let Some(ref v) = http.powered_by {
        field("Powered By", v);
    }
    if let Some(ref v) = http.title {
        field("Title", v);
    }
    if let Some(ref v) = http.description {
        field("Description", &v.chars().take(120).collect::<String>());
    }

    // Handle: timing breakdown
    if r.timing.fetch_ms > 0 {
        field("Fetch Time", &format!("{}ms", r.timing.fetch_ms));
    }
    if r.timing.scan_ms > 0 {
        field("Scan Time", &format!("{}ms", r.timing.scan_ms));
    }
    if r.timing.total_ms > 0 {
        field("Total Time", &format!("{}ms", r.timing.total_ms));
    }

    // Handle: HTTP redirect chain
    if !http.redirects.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Redirects".color(TOKYO_PINK).bold());
        for (i, redir) in http.redirects.iter().enumerate() {
            println!("    {} {} → {}", i + 1, redir.status, redir.url.color(TOKYO_BLUE));
        }
    }

    // Handle: cookie dump with security flags
    if !http.cookies.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Cookies".color(TOKYO_PINK).bold());
        for c in &http.cookies {
            let flags = vec![
                if c.secure { "Secure" } else { "" },
                if c.http_only { "HttpOnly" } else { "" },
            ]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
            let extra = if flags.is_empty() { String::new() } else { format!(" [{}]", flags) };
            println!(
                "    {}={}{}",
                c.name.color(TOKYO_BLUE),
                c.value.chars().take(40).collect::<String>(),
                extra.color(TOKYO_PINK)
            );
        }
    }

    // Branch: security headers audit section
    if show_headers && !http.security_headers.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Security Headers".color(TOKYO_PINK).bold());
        for sh in &http.security_headers {
            let icon = if sh.present { "✓" } else { "✗" };
            let val = sh.value.as_deref().unwrap_or("");
            let note = if sh.note.is_empty() { String::new() } else { format!(" ({})", sh.note) };
            println!(
                "    {} {}:{}{}",
                if sh.present { icon.color(TOKYO_BLUE) } else { icon.color(TOKYO_PINK) },
                sh.header.color(TOKYO_BLUE),
                val,
                note.color(TOKYO_PINK)
            );
        }
    }

    // Handle: detected technologies
    if !http.technologies.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Technologies".color(TOKYO_PINK).bold());
        for t in &http.technologies {
            println!("    {} {} ({})", t.name.color(TOKYO_BLUE), t.category.color(TOKYO_PINK), t.confidence);
        }
    }

    // Handle: HTML forms detected on page
    if !http.forms.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Forms".color(TOKYO_PINK).bold());
        for f in &http.forms {
            println!(
                "    {} {} action={}",
                f.method.color(TOKYO_PINK),
                "→".color(TOKYO_BLUE),
                if f.action.is_empty() { "(self)".color(TOKYO_BLUE) } else { f.action.color(TOKYO_BLUE) }
            );
            for field in &f.fields {
                let req = if field.required { "*".color(TOKYO_PINK) } else { "".color(TOKYO_BLUE) };
                println!(
                    "      {} {} {}",
                    field.field_type.color(TOKYO_BLUE),
                    field.name,
                    req
                );
            }
        }
    }

    // Branch: links found on page
    if show_links && !http.links.is_empty() {
        println!();
        println!("  {} {} ({} total)","└".color(TOKYO_BLUE),"Links".color(TOKYO_PINK).bold(), http.links.len());
        for link in http.links.iter().take(15) {
            let disp = if link.href.len() > 80 {
                let truncated: String = link.href.chars().take(77).collect();
                format!("{}...", truncated)
            } else {
                link.href.clone()
            };
            println!("    {}", disp.color(TOKYO_BLUE));
        }
        if http.links.len() > 15 {
            println!("    ... and {} more", http.links.len() - 15);
        }
    }

    // Handle: email addresses extracted
    if !http.emails.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Emails".color(TOKYO_PINK).bold());
        for e in &http.emails {
            println!("    {}", e.color(TOKYO_BLUE));
        }
    }

    // Handle: phone numbers extracted
    if !http.phones.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Phones".color(TOKYO_PINK).bold());
        for p in &http.phones {
            println!("    {}", p.color(TOKYO_BLUE));
        }
    }

    // Handle: social media links
    if !http.social_links.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Social".color(TOKYO_PINK).bold());
        for s in &http.social_links {
            println!("    {}", s.color(TOKYO_BLUE));
        }
    }

    // Handle: HTML meta tags
    if !http.meta_tags.is_empty() {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Meta Tags".color(TOKYO_PINK).bold());
        for m in &http.meta_tags {
            println!("    {}", m.color(TOKYO_BLUE));
        }
    }

    // Handle: WAF detection results
    if let Some(ref w) = r.waf {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"WAF".color(TOKYO_PINK).bold());
        println!("    {} {} ({})", w.name.color(TOKYO_BLUE), w.manufacturer.color(TOKYO_PINK), w.signals.first().map(|s| s.as_str()).unwrap_or("?"));
        if w.signals.len() > 1 {
            for s in &w.signals[1..] {
                println!("      → {}", s.color(TOKYO_BLUE));
            }
        }
    }

    // Handle: DNS records
    if let Some(ref d) = r.dns {
        if !d.records.is_empty() {
            println!();
            println!("  {} {}","└".color(TOKYO_BLUE),"DNS Records".color(TOKYO_PINK).bold());
            for rec in &d.records {
                println!("    {} {}", rec.rtype.color(TOKYO_PINK), rec.value.color(TOKYO_BLUE));
            }
        }
    }

    // Handle: JavaScript analysis
    if let Some(ref js) = r.js {
        if !js.files.is_empty() || !js.api_hints.is_empty() || !js.spa_routes.is_empty() {
            println!();
            println!("  {} {}","└".color(TOKYO_BLUE),"JavaScript".color(TOKYO_PINK).bold());
            if !js.files.is_empty() {
                for f in js.files.iter().take(10) {
                    let hint = if f.hints.is_empty() { String::new() } else { format!(" ({})", f.hints.join(", ")) };
                    println!("    {}{}", f.src.color(TOKYO_BLUE), hint.color(TOKYO_PINK));
                }
                if js.files.len() > 10 {
                    println!("    ... and {} more", js.files.len() - 10);
                }
            }
            if !js.api_hints.is_empty() {
                for a in &js.api_hints {
                    println!("    API: {}", a.color(TOKYO_BLUE));
                }
            }
            if !js.spa_routes.is_empty() {
                for r in js.spa_routes.iter().take(8) {
                    println!("    Route: {}", r.color(TOKYO_BLUE));
                }
            }
        }
    }

    // Handle: page classification and analysis
    if let Some(ref p) = r.page {
        println!();
        println!("  {} {}","└".color(TOKYO_BLUE),"Page Analysis".color(TOKYO_PINK).bold());
        println!("    Type: {}", p.classification.color(TOKYO_BLUE));
        if p.has_login_form {
            println!("    {} Login form detected", "⚠".color(TOKYO_PINK));
        }
        if p.has_upload {
            println!("    {} File upload detected", "⚠".color(TOKYO_PINK));
        }
        if !p.error_disclosure.is_empty() {
            for e in &p.error_disclosure {
                let disp = if e.len() > 100 { format!("{}...", &e[..97]) } else { e.clone() };
                println!("    {} {}", "✗".color(TOKYO_PINK), disp.color(TOKYO_BLUE));
            }
        }
        if !p.tech_hints.is_empty() {
            println!("    Hints: {}", p.tech_hints.join(", ").color(TOKYO_BLUE));
        }
    }

    // Handle: endpoint scan results
    if let Some(ref scan) = r.scan {
        if !scan.endpoints.is_empty() {
            println!();
            println!("  {} {}","└".color(TOKYO_BLUE),"Endpoints".color(TOKYO_PINK).bold());
            for e in &scan.endpoints {
                println!(
                    "    {} [{}] {}",
                    e.status,
                    e.content_type.as_deref().unwrap_or("?"),
                    e.path.color(TOKYO_BLUE)
                );
            }
        }
        // Handle: discovered subdomains
        if !scan.subdomains.is_empty() {
            println!();
            println!("  {} {}","└".color(TOKYO_BLUE),"Subdomains".color(TOKYO_PINK).bold());
            for s in &scan.subdomains {
                println!("    {}", s.color(TOKYO_BLUE));
            }
        }
    }

    // Handle: source attribution footer
    println!(
        "  {} {}",
        "Source:".color(TOKYO_PINK),
        "REAP v4.0.0".color(TOKYO_BLUE)
    );
}

/// Print a formatted label-value field line.
fn field(label: &str, value: &str) {
    println!(
        "    {}: {}",
        label.color(TOKYO_PINK),
        value.color(TOKYO_BLUE)
    );
}

/// Print a horizontal divider line.
pub fn divider() {
    println!("{}", "─".repeat(50).color(TOKYO_BLUE).dimmed());
}

/// Print an informational message with dimmed styling.
pub fn info(text: &str) {
    println!("  {} {}", "•".color(TOKYO_BLUE).dimmed(), text.dimmed());
}

/// Print a final summary line with total targets and elapsed time.
pub fn summary(total: usize, elapsed: f64, _quiet: bool) {
    println!();
    println!("{}", "═".repeat(55).color(TOKYO_BLUE).bold());
    println!(
        "  {} {}  {} target{} in {:.1}s",
        "REAP".bold().color(TOKYO_BLUE),
        "COMPLETE".color(TOKYO_PINK).bold(),
        format!("{}", total).color(TOKYO_PINK).bold(),
        if total == 1 { "" } else { "s" },
        elapsed
    );
    println!("{}", "═".repeat(55).color(TOKYO_BLUE).bold());
}
