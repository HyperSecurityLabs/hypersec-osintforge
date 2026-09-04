/// JavaScript analysis — extracts external JS files, API hints, and SPA route patterns.
///
/// Scans both external script sources and inline scripts for sensitive API patterns
/// and single-page application routing clues.
use crate::models::{JsFile, JsInfo};
use scraper::{Html, Selector};
use std::collections::HashSet;

/// Patterns that suggest API endpoints, tokens, or secrets in JavaScript.
const API_PATTERNS: &[&str] = &[
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
    "api.", "api_key", "api.secret", "api.token",
    "firebase", "stripe", "sk_live", "pk_live",
    "aws_access_key", "aws_secret_key",
    "token:", "secret:", "password:",
    "bearer", "jwt", "oauth",
    ".firebaseio.com", "cloudfunctions.net",
    "lambda", "execute-api",
];

/// Patterns that indicate SPA routing frameworks.
const SPA_PATTERNS: &[&str] = &[
    "react-router", "vue-router", "angular/router",
    "next/router", "nuxt-link", "gatsby-link",
    "path:", "pathname", "history.push",
    "navigate(", "route.path", "routes =",
];

/// Analyze HTML body for JavaScript files, API hints, and SPA routes.
pub fn analyze(body: &str) -> JsInfo {
    let doc = Html::parse_document(body);
    let mut js_info = JsInfo {
        files: Vec::new(),
        api_hints: Vec::new(),
        spa_routes: Vec::new(),
    };
    let mut seen_apis = HashSet::new();
    let mut seen_routes = HashSet::new();

    // Step: extract external JS files with src attributes
    if let Ok(sel) = Selector::parse("script[src]") {
        for el in doc.select(&sel) {
            if let Some(src) = el.value().attr("src") {
                let mut hints = Vec::new();
                let src_lower = src.to_lowercase();

                for pat in API_PATTERNS {
                    if src_lower.contains(pat) {
                        hints.push(pat.to_string());
                    }
                }

                js_info.files.push(JsFile {
                    src: src.to_string(),
                    is_inline: false,
                    hints,
                });
            }
        }
    }

    // Step: check inline scripts for API patterns and SPA routes
    if let Ok(sel) = Selector::parse("script:not([src])") {
        for el in doc.select(&sel) {
            let text = el.text().collect::<String>();
            // Check: skip very large inline scripts
            if text.len() > 5000 {
                continue;
            }
            let text_lower = text.to_lowercase();

            for pat in API_PATTERNS {
                if text_lower.contains(pat) && seen_apis.insert(pat.to_string()) {
                    js_info.api_hints.push(format!("{} (inline script)", pat));
                }
            }

            for pat in SPA_PATTERNS {
                if text_lower.contains(pat) && seen_routes.insert(pat.to_string()) {
                    js_info.spa_routes.push(pat.to_string());
                }
            }

            // Step: attempt to extract route paths from router-related code
            if text_lower.contains("routes") || text_lower.contains("router") {
                for word in text.split(|c: char| c.is_whitespace() || c == ',' || c == '"' || c == '\'') {
                    if word.starts_with('/') && word.len() > 1 && word.len() < 100 && !word.contains(' ') {
                        js_info.spa_routes.push(word.to_string());
                    }
                }
            }
        }
    }

    // Step: scan full body for API-related hints
    let body_lower = body.to_lowercase();
    for pat in API_PATTERNS {
        if body_lower.contains(pat) && seen_apis.insert(pat.to_string()) {
            js_info.api_hints.push(pat.to_string());
        }
    }

    js_info
}
