/// HTTP fetch engine — drives the full web intelligence pipeline.
///
/// Orchestrates the HTTP request, redirect following, header/cookie parsing,
/// WAF detection, DNS resolution, HTML parsing, JS analysis, and endpoint scanning.
use crate::models::{CookieInfo, Form, FormField, HttpInfo, Link, Redirect, ReapResult};
use crate::stealth;
use crate::{content, dns, endpoints, fingerprint, js, secheaders, waf};
use regex::Regex;
use reqwest::header::{HeaderMap, SET_COOKIE};
use scraper::{Html, Selector};
use std::time::Instant;

/// Perform a full intelligence fetch against a target URL.
///
/// Builds a configurable HTTP client, follows redirects, extracts metadata,
/// and runs all analysis modules (WAF, DNS, fingerprinting, JS, endpoints).
pub async fn fetch(target: &str, proxy: Option<&str>) -> ReapResult {
    let mut r = ReapResult::default();
    r.target = target.to_string();

    // Step: configure the HTTP client with timeout, no redirects, and random UA
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(stealth::random_ua());

    // Branch: apply proxy if provided
    if let Some(proxy_url) = proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => {
            r.error = Some(format!("Client build failed: {}", e));
            return r;
        }
    };

    // Step: normalize URL — add https:// if no scheme present
    let url = if !target.starts_with("http://") && !target.starts_with("https://") {
        format!("https://{}", target)
    } else {
        target.to_string()
    };

    // Step: execute initial request with HTTPS fallback
    let mut final_url = url.clone();
    let fetch_start = Instant::now();
    let mut response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            // Branch: fallback to HTTP if HTTPS fails
            let fallback = if url.starts_with("https://") {
                url.replacen("https://", "http://", 1)
            } else {
                url.clone()
            };
            match client.get(&fallback).send().await {
                Ok(r) => {
                    final_url = fallback;
                    r
                }
                Err(e2) => {
                    r.error = Some(format!("Request failed: {} (also tried http: {})", e, e2));
                    return r;
                }
            }
        }
    };

    let fetch_ms = fetch_start.elapsed().as_millis() as u64;

    // Step: populate initial HTTP info
    let mut http = HttpInfo::default();
    http.final_url = Some(final_url.clone());
    http.status = Some(response.status().as_u16());

    // Loop: follow redirect chain (max 10 hops)
    let mut redirects = Vec::new();
    for _ in 0..10 {
        if response.status().is_redirection() {
            let loc = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            if let Some(loc) = loc {
                let next = resolve_url(&final_url, &loc);
                redirects.push(Redirect {
                    status: response.status().as_u16(),
                    url: final_url.clone(),
                });

                match client.get(&next).send().await {
                    Ok(resp) => {
                        final_url = next;
                        response = resp;
                    }
                    Err(_) => break,
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    // Handle: record final redirect target
    if !redirects.is_empty() {
        redirects.push(Redirect {
            status: response.status().as_u16(),
            url: final_url.clone(),
        });
    }
    http.redirects = redirects;
    http.final_url = Some(final_url.clone());

    // Step: extract all response headers
    let headers = response.headers().clone();
    for (k, v) in headers.iter() {
        if let Ok(val) = v.to_str() {
            http.headers.push((k.as_str().to_string(), val.to_string()));
        }
    }

    // Step: parse key headers
    if let Some(v) = header_val(&headers, "content-type") {
        http.content_type = Some(v);
    }
    if let Some(v) = header_val(&headers, "content-length") {
        http.content_length = v.parse::<u64>().ok();
    }
    if let Some(v) = header_val(&headers, "server") {
        http.server = Some(v);
    }
    if let Some(v) = header_val(&headers, "x-powered-by") {
        http.powered_by = Some(v);
    }

    // Step: parse Set-Cookie headers
    for cv in response.headers().get_all(SET_COOKIE) {
        if let Ok(s) = cv.to_str() {
            http.cookies.push(parse_cookie(s));
        }
    }

    // Step: audit security headers
    http.security_headers = secheaders::audit(&headers);

    // Step: read response body
    let body = match response.text().await {
        Ok(b) => b,
        Err(_) => {
            r.http = Some(http);
            r.timing.fetch_ms = fetch_ms;
            return r;
        }
    };

    // Step: run WAF detection
    r.waf = waf::detect(&headers, &body, &http.cookies);

    // Step: resolve DNS records
    let dns_start = Instant::now();
    r.dns = Some(dns::resolve(&target).await);
    r.timing.dns_ms = dns_start.elapsed().as_millis() as u64;

    // Step: parse HTML and extract metadata
    {
        let doc = Html::parse_document(&body);

        // Handle: extract page title
        if let Ok(sel) = Selector::parse("title") {
            if let Some(el) = doc.select(&sel).next() {
                http.title = Some(el.text().collect::<String>().trim().to_string());
            }
        }

        // Handle: extract meta description
        if let Ok(sel) = Selector::parse("meta[name=description]") {
            if let Some(el) = doc.select(&sel).next() {
                if let Some(content) = el.value().attr("content") {
                    http.description = Some(content.to_string());
                }
            }
        }

        // Handle: extract all meta tags
        if let Ok(sel) = Selector::parse("meta") {
            for el in doc.select(&sel) {
                if let Some(n) = el.value().attr("name") {
                    let c = el.value().attr("content").unwrap_or("");
                    http.meta_tags.push(format!("{}={}", n, c));
                }
            }
        }

        // Handle: extract form fields
        if let Ok(sel) = Selector::parse("form") {
            for el in doc.select(&sel) {
                let action = el.value().attr("action").unwrap_or("").to_string();
                let method = el
                    .value()
                    .attr("method")
                    .unwrap_or("get")
                    .to_uppercase();
                let mut fields = Vec::new();

                if let Ok(field_sel) = Selector::parse("input, textarea, select") {
                    for field in el.select(&field_sel) {
                        let name = field.value().attr("name").unwrap_or("").to_string();
                        if name.is_empty() {
                            continue;
                        }
                        let ft = field
                            .value()
                            .attr("type")
                            .unwrap_or("text")
                            .to_string();
                        let required = field.value().attr("required").is_some();
                        let placeholder = field.value().attr("placeholder").map(|s| s.to_string());
                        fields.push(FormField {
                            name,
                            field_type: ft,
                            required,
                            placeholder,
                        });
                    }
                }

                if !action.is_empty() || !fields.is_empty() {
                    http.forms.push(Form {
                        action,
                        method,
                        fields,
                    });
                }
            }
        }

        // Step: run technology fingerprinting
        fingerprint::detect(&mut http, &headers, &body);

        // Step: classify the page content
        r.page = Some(content::classify(&body, http.title.as_deref(), &http.meta_tags));

        // Step: extract links and contact info
        extract_links(&doc, &mut http);
        extract_contacts(&body, &mut http);
    }

    // Step: analyze JavaScript for API hints and SPA routes
    let js_start = Instant::now();
    r.js = Some(js::analyze(&body));
    r.timing.js_ms = js_start.elapsed().as_millis() as u64;

    // Step: scan common endpoints
    let scan_start = Instant::now();
    let scan_info = endpoints::scan(&target, client.clone(), &final_url).await;
    r.timing.scan_ms = scan_start.elapsed().as_millis() as u64;
    r.scan = Some(scan_info);

    r.http = Some(http);
    r.timing.fetch_ms = fetch_ms;
    r.timing.total_ms = r.timing.fetch_ms + r.timing.dns_ms + r.timing.js_ms + r.timing.scan_ms;
    r
}

/// Extract all `<a href>` links from the parsed HTML document.
fn extract_links(doc: &Html, http: &mut HttpInfo) {
    if let Ok(sel) = Selector::parse("a[href]") {
        for el in doc.select(&sel) {
            let href = el.value().attr("href").unwrap_or("").to_string();
            // Check: skip empty, anchors, and javascript links
            if href.is_empty() || href.starts_with('#') || href.starts_with("javascript:") {
                continue;
            }
            // Check: skip mailto and tel links
            if href.starts_with("mailto:") || href.starts_with("tel:") {
                continue;
            }
            let text = el.text().collect::<String>().trim().to_string();
            // Check: skip excessively long URLs
            if href.len() > 500 {
                continue;
            }
            http.links.push(Link { href, text });
        }
    }
}

/// Extract email addresses, phone numbers, and social media links from body text.
fn extract_contacts(body: &str, http: &mut HttpInfo) {
    // Step: extract email addresses via regex
    if let Ok(re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        for m in re.find_iter(body) {
            let email = m.as_str().to_lowercase();
            if !http.emails.contains(&email) {
                http.emails.push(email);
            }
        }
    }

    // Step: extract phone numbers with context validation
    if let Ok(re) = Regex::new(r"\+?1?\d{10,15}") {
        let phone_context = Regex::new(r"(?i)(tel|phone|call|contact|whatsapp|mobile|cell|fax)").ok();
        for m in re.find_iter(body) {
            let phone = m.as_str().to_string();
            let start = m.start().saturating_sub(80);
            let end = std::cmp::min(m.end() + 80, body.len());
            let context = &body[start..end];
            let has_context = phone_context.as_ref()
                .map(|re| re.is_match(context))
                .unwrap_or(true);
            // Check: skip if no phone-related context
            if !has_context {
                continue;
            }
            if !http.phones.contains(&phone) {
                http.phones.push(phone);
            }
        }
    }

    // Step: scan for known social media domain references
    let social_domains: &[&str] = &[
        "facebook.com", "twitter.com", "x.com", "instagram.com",
        "linkedin.com", "youtube.com", "tiktok.com", "pinterest.com",
        "github.com", "discord.com", "reddit.com", "medium.com",
        "t.me", "telegram.me", "whatsapp.com", "snapchat.com",
    ];
    let body_lower = body.to_lowercase();
    for domain in social_domains {
        let pattern = format!("{}", domain.replace('.', "\\."));
        if let Ok(re) = Regex::new(&pattern) {
            for m in re.find_iter(&body_lower) {
                let found = m.as_str().to_string();
                if !http.social_links.contains(&found) {
                    http.social_links.push(found);
                }
            }
        }
    }
}

/// Safely extract a header value as a String.
fn header_val(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Resolve a potentially relative redirect URL against a base URL.
fn resolve_url(base: &str, loc: &str) -> String {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        loc.to_string()
    } else if loc.starts_with('/') {
        let parsed = url::Url::parse(base).ok();
        match parsed {
            Some(u) => {
                format!("{}://{}{}", u.scheme(), u.host_str().unwrap_or(""), loc)
            }
            None => format!("{}{}", base.trim_end_matches('/'), loc),
        }
    } else {
        format!(
            "{}/{}",
            base.trim_end_matches('/'),
            loc.trim_start_matches('/')
        )
    }
}

/// Parse a raw Set-Cookie string into a structured CookieInfo.
fn parse_cookie(raw: &str) -> CookieInfo {
    let parts: Vec<&str> = raw.split(';').map(|s| s.trim()).collect();
    let kv = parts.first().unwrap_or(&"");
    let (name, value) = match kv.split_once('=') {
        Some((n, v)) => (n.trim().to_string(), v.trim().to_string()),
        None => (kv.to_string(), String::new()),
    };

    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    let mut domain = None;
    let mut path = None;

    // Loop: parse cookie attributes (Secure, HttpOnly, SameSite, Domain, Path)
    for p in &parts[1..] {
        match p.to_lowercase().as_str() {
            "secure" => secure = true,
            "httponly" => http_only = true,
            s if s.starts_with("samesite=") => {
                same_site = Some(s.trim_start_matches("samesite=").to_string());
            }
            s if s.starts_with("domain=") => {
                domain = Some(s.trim_start_matches("domain=").to_string());
            }
            s if s.starts_with("path=") => {
                path = Some(s.trim_start_matches("path=").to_string());
            }
            _ => {}
        }
    }

    CookieInfo {
        name,
        value,
        secure,
        http_only,
        same_site,
        domain,
        path,
    }
}
