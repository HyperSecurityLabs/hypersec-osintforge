/// HTML page content classification and analysis.
///
/// Provides functions to classify web pages by type (login, admin, blog, etc.),
/// detect error disclosures, identify technology stacks from HTML patterns,
/// and detect login/upload forms.
use crate::models::PageInfo;
use scraper::{Html, Selector};

/// Classification patterns mapping page categories to keyword indicators.
const CLASSIFICATION_PATTERNS: &[(&str, &[&str])] = &[
    ("login", &["login", "signin", "sign-in", "log in", "sign in", "username", "password"]),
    ("admin", &["admin", "dashboard", "cpanel", "control panel", "administration"]),
    ("blog", &["blog", "article", "post", "published", "read more"]),
    ("error", &["error", "404", "not found", "page not found", "internal server error"]),
    ("landing", &["landing", "hero", "get started", "learn more", "sign up free"]),
    ("ecommerce", &["cart", "checkout", "add to cart", "buy now", "shop", "products"]),
    ("documentation", &["docs", "documentation", "manual", "api reference", "quickstart"]),
    ("portal", &["portal", "my account", "my profile", "settings", "welcome back"]),
    ("forum", &["forum", "topic", "thread", "reply", "discussion"]),
    ("support", &["support", "help", "faq", "knowledgebase", "ticket"]),
];

/// Patterns indicating error message disclosure in HTML body.
const ERROR_PATTERNS: &[&str] = &[
    "warning:", "notice:", "deprecated",
    "mysql_fetch", "sqlsrv", "sqlite",
    "stack trace", "debug_backtrace",
    "division by zero", "undefined index", "undefined variable",
    "cannot modify header", "failed to open stream",
    "php error", "mysql error", "sql error",
    "fatal error", "parse error", "syntax error",
    "exception:", "uncaught exception",
    "file_get_contents", "include_once",
    "runtimeerror", "typeerror",
    "path: /", "line ", "on line",
    "var_dump(", "print_r(",
];

/// Technology fingerprint hints — maps tech names to HTML/URL patterns.
const TECH_HINTS: &[(&str, &[&str])] = &[
    ("WordPress", &["/wp-content/", "/wp-includes/", "wp-json", "wordpress"]),
    ("Laravel", &["laravel", "csrf-token", "laravel_session"]),
    ("Django", &["django", "csrfmiddlewaretoken", "sessionid"]),
    ("Ruby on Rails", &["rails", "csrf-token", "_session"]),
    ("ASP.NET", &["__viewstate", "__eventvalidation", "asp.net"]),
    ("PHP", &[".php", "phpsessid"]),
    ("Node.js", &["express", "node_modules", "/next.js"]),
    ("Java", &["jsessionid", ".jsp", "java servlet", "java.lang", "java.io"]),
    ("React", &["react.js", "reactdom", "createroot", "react.production"]),
    ("Vue.js", &["vue", "vuejs", "v-bind", "v-model"]),
    ("Angular", &["angular", "ng-app", "ng-controller"]),
    ("jQuery", &["jquery", "$("]),
    ("Bootstrap", &["bootstrap", "col-md", "col-xs"]),
    ("Font Awesome", &["fontawesome", "fa-"]),
    ("Google Analytics", &["google-analytics", "ga(", "gtag"]),
    ("Cloudflare", &["cloudflare", "cf-ray"]),
    ("Shopify", &["shopify", "myshopify"]),
    ("Wix", &["wix.com", "wixstatic"]),
    ("Squarespace", &["squarespace", "static.squarespace"]),
    ("Stripe", &["stripe.com", "stripe-"]),
    ("PayPal", &["paypal.com", "paypalobjects"]),
    ("Algolia", &["algolia"]),
    ("Disqus", &["disqus"]),
    ("reCAPTCHA", &["recaptcha"]),
    ("Facebook SDK", &["connect.facebook.net"]),
];

/// Classify a web page by analyzing its body, title, and meta tags.
///
/// Returns a `PageInfo` struct with classification, form detection,
/// error disclosures, and technology hints.
pub fn classify(body: &str, title: Option<&str>, meta_tags: &[String]) -> PageInfo {
    let body_lower = body.to_lowercase();
    let doc = Html::parse_document(body);

    let mut info = PageInfo {
        classification: "unknown".to_string(),
        has_login_form: false,
        has_upload: false,
        error_disclosure: Vec::new(),
        tech_hints: Vec::new(),
    };

    // Step: score each classification category against body keywords
    let mut scores: Vec<(&str, usize)> = CLASSIFICATION_PATTERNS
        .iter()
        .map(|(name, pats)| {
            let score = pats.iter().filter(|p| body_lower.contains(&p.to_lowercase())).count();
            (*name, score)
        })
        .collect();
    scores.sort_by(|a, b| b.1.cmp(&a.1));
    if let Some(top) = scores.first() {
        if top.1 > 0 {
            info.classification = top.0.to_string();
        }
    }

    // Step: override classification based on page title keywords
    if let Some(t) = title {
        let t_lower = t.to_lowercase();
        if t_lower.contains("login") || t_lower.contains("sign in") {
            info.classification = "login".to_string();
        }
        if t_lower.contains("admin") || t_lower.contains("dashboard") {
            info.classification = "admin".to_string();
        }
        if t_lower.contains("error") || t_lower.contains("not found") {
            info.classification = "error".to_string();
        }
    }

    // Step: detect login forms by checking for password input fields
    if let Ok(sel) = Selector::parse("input[type=password]") {
        if doc.select(&sel).next().is_some() {
            info.has_login_form = true;
        }
    }
    // Step: detect file upload forms
    if let Ok(sel) = Selector::parse("input[type=file]") {
        if doc.select(&sel).next().is_some() {
            info.has_upload = true;
        }
    }

    // Step: scan body for error disclosure patterns with context snippets
    for pat in ERROR_PATTERNS {
        if let Some(pos) = body_lower.find(pat) {
            let start = pos.saturating_sub(40);
            let end = (pos + pat.len() + 80).min(body_lower.len());
            let start = (0..=start)
                .rev()
                .find(|&i| body_lower.is_char_boundary(i))
                .unwrap_or(0);
            let end = (end..body_lower.len())
                .find(|&i| body_lower.is_char_boundary(i))
                .unwrap_or(body_lower.len());
            let snippet = &body_lower[start..end];
            let lines: Vec<&str> = snippet.lines().collect();
            let context = if lines.len() > 3 {
                format!("{} ...", lines[..3].join(" | "))
            } else {
                snippet.to_string()
            };
            if !info.error_disclosure.iter().any(|e| e.contains(pat)) {
                info.error_disclosure.push(format!("'{}' in: {}", pat, context));
            }
        }
    }

    // Step: match tech stack hints from HTML body patterns
    let mut seen_tech = std::collections::HashSet::new();
    for (name, pats) in TECH_HINTS {
        if pats.iter().any(|p| body_lower.contains(p)) && seen_tech.insert(name.to_string()) {
            info.tech_hints.push(name.to_string());
        }
    }

    // Step: extract technology info from meta generator tags
    for meta in meta_tags {
        let meta_lower = meta.to_lowercase();
        if meta_lower.contains("generator") {
            if let Some(val) = meta.split('=').nth(1) {
                info.tech_hints.push(format!("Meta generator: {}", val));
            }
        }
    }

    info
}
