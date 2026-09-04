/// Web technology fingerprinting via headers, HTML, cookies, scripts, and meta tags.
///
/// Matches known signatures for web servers, CMS platforms, JavaScript frameworks,
/// analytics services, CDNs, and other technologies.
use crate::models::{HttpInfo, Tech};
use regex::Regex;
use reqwest::header::HeaderMap;
use scraper::{Html, Selector};

/// A technology signature with match patterns across multiple sources.
struct Sig {
    name: &'static str,
    category: &'static str,
    headers: &'static [(&'static str, &'static str)],
    html: &'static [&'static str],
    cookies: &'static [&'static str],
    meta: &'static [(&'static str, &'static str)],
    scripts: &'static [&'static str],
}

/// Comprehensive technology signature database.
const SIGNATURES: &[Sig] = &[
    // Web Servers
    Sig { name: "nginx", category: "Web Server", headers: &[("server", "nginx")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Apache", category: "Web Server", headers: &[("server", "apache")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "IIS", category: "Web Server", headers: &[("server", "iis"), ("x-powered-by", "asp\\.net")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Cloudflare", category: "CDN", headers: &[("server", "cloudflare"), ("cf-ray", ""), ("cf-cache-status", "")], html: &[], cookies: &["__cfduid"], meta: &[], scripts: &[] },
    Sig { name: "Caddy", category: "Web Server", headers: &[("server", "caddy")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    // CMS
    Sig { name: "WordPress", category: "CMS", headers: &[], html: &["/wp-content/", "/wp-includes/"], cookies: &["wp-", "wordpress_"], meta: &[("generator", "wordpress")], scripts: &["wp-includes"] },
    Sig { name: "Drupal", category: "CMS", headers: &[], html: &["drupal"], cookies: &["Drupal.", "SESS"], meta: &[("generator", "drupal")], scripts: &[] },
    Sig { name: "Joomla", category: "CMS", headers: &[], html: &[], cookies: &[], meta: &[("generator", "joomla")], scripts: &[] },
    Sig { name: "Shopify", category: "E-commerce", headers: &[("x-shopid", ""), ("x-shopify-stage", "")], html: &["shopify"], cookies: &["_shopify_"], meta: &[], scripts: &["shopify"] },
    Sig { name: "Squarespace", category: "CMS", headers: &[], html: &["squarespace"], cookies: &["ss_sd"], meta: &[("generator", "squarespace")], scripts: &["static1.squarespace"] },
    Sig { name: "Wix", category: "CMS", headers: &[], html: &["wix.com"], cookies: &[], meta: &[("generator", "wix")], scripts: &["static.wixstatic"] },
    Sig { name: "Magento", category: "E-commerce", headers: &[], html: &[], cookies: &["mage-", "mage-cache-", "mage-messages"], meta: &[("generator", "magento")], scripts: &[] },
    Sig { name: "WooCommerce", category: "E-commerce", headers: &[], html: &["woocommerce"], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Ghost", category: "CMS", headers: &[], html: &[], cookies: &[], meta: &[("generator", "ghost")], scripts: &[] },
    Sig { name: "Jekyll", category: "CMS", headers: &[], html: &[], cookies: &[], meta: &[("generator", "jekyll")], scripts: &[] },
    // Frameworks
    Sig { name: "React", category: "JavaScript Framework", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &["react.js", "react.min.js", "/static/js/react"] },
    Sig { name: "Next.js", category: "JavaScript Framework", headers: &[("x-powered-by", "next.js"), ("x-nextjs-page", "")], html: &["__next"], cookies: &[], meta: &[], scripts: &["/_next/"] },
    Sig { name: "Vue.js", category: "JavaScript Framework", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &["vue.js", "vue.min.js"] },
    Sig { name: "Nuxt.js", category: "JavaScript Framework", headers: &[], html: &["__nuxt"], cookies: &[], meta: &[], scripts: &["/_nuxt/"] },
    Sig { name: "Angular", category: "JavaScript Framework", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &["angular.js", "angular.min.js", "angular-core"] },
    Sig { name: "jQuery", category: "JavaScript Library", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &["jquery"] },
    Sig { name: "Bootstrap", category: "CSS Framework", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &["bootstrap"] },
    Sig { name: "Tailwind CSS", category: "CSS Framework", headers: &[], html: &["tailwind"], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Font Awesome", category: "Icon Library", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &["font-awesome", "fontawesome"] },
    Sig { name: "Laravel", category: "PHP Framework", headers: &[], html: &[], cookies: &["laravel_session", "XSRF-TOKEN"], meta: &[], scripts: &[] },
    Sig { name: "Django", category: "Python Framework", headers: &[("server", "wsgiref")], html: &[], cookies: &["csrftoken", "sessionid"], meta: &[], scripts: &[] },
    Sig { name: "Rails", category: "Ruby Framework", headers: &[("x-powered-by", "rails"), ("x-request-id", "")], html: &[], cookies: &["_session"], meta: &[], scripts: &[] },
    Sig { name: "Express", category: "Node.js Framework", headers: &[("x-powered-by", "express")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Flask", category: "Python Framework", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Spring Boot", category: "Java Framework", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "ASP.NET", category: ".NET Framework", headers: &[("x-powered-by", "asp.net"), ("x-aspnet-version", "")], html: &[], cookies: &[".asp", "__requestverificationtoken"], meta: &[], scripts: &[] },
    // Analytics
    Sig { name: "Google Analytics", category: "Analytics", headers: &[], html: &[], cookies: &["_ga", "_gid", "_gat"], meta: &[], scripts: &["google-analytics.com/analytics.js", "googletagmanager.com/gtag/js"] },
    Sig { name: "Meta Pixel", category: "Analytics", headers: &[], html: &[], cookies: &["_fbp"], meta: &[], scripts: &["connect.facebook.net"] },
    Sig { name: "Hotjar", category: "Analytics", headers: &[], html: &[], cookies: &["_hj"], meta: &[], scripts: &["hotjar"] },
    Sig { name: "Matomo", category: "Analytics", headers: &[], html: &[], cookies: &["_pk_"], meta: &[], scripts: &["matomo"] },
    // Security
    Sig { name: "Sucuri", category: "Security", headers: &[("x-sucuri-id", ""), ("x-sucuri-cache", "")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "ModSecurity", category: "Security", headers: &[], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Akamai", category: "CDN", headers: &[("server", "akamai"), ("x-akamai-", "")], html: &[], cookies: &["ak_bmsc"], meta: &[], scripts: &[] },
    Sig { name: "Fastly", category: "CDN", headers: &[("x-fastly-request-id", ""), ("x-served-by", "")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Amazon CloudFront", category: "CDN", headers: &[("x-amz-cf-id", ""), ("x-amz-cf-pop", "")], html: &[], cookies: &[], meta: &[], scripts: &[] },
    Sig { name: "Varnish", category: "Cache", headers: &[("x-varnish", ""), ("via", "varnish")], html: &[], cookies: &[], meta: &[], scripts: &[] },
];

/// Detect technologies present in the HTTP response and populate `result.technologies`.
///
/// Checks headers, HTML body, cookies, meta tags, and script sources against known signatures.
pub fn detect(result: &mut HttpInfo, headers: &HeaderMap, body: &str) {
    // Step: strip HTML comments before matching to avoid false positives
    let comment_re = Regex::new(r"(?s)<!--.*?-->").unwrap();
    let cleaned = comment_re.replace_all(body, "");
    let body_lower = cleaned.to_lowercase();
    let doc = Html::parse_document(body);
    let mut techs = Vec::new();

    // Loop: check each signature against the response
    for sig in SIGNATURES {
        let mut matched = false;
        let mut method = "";

        // Step: match against response headers
        for (hdr, pattern) in sig.headers {
            if let Some(val) = headers.get(*hdr) {
                if let Ok(v) = val.to_str() {
                    let v_lower = v.to_lowercase();
                    if pattern.is_empty() || v_lower.contains(&pattern.to_lowercase()) {
                        matched = true;
                        method = "header";
                        break;
                    }
                }
            }
        }
        if matched {
            techs.push(Tech {
                name: sig.name.to_string(),
                category: sig.category.to_string(),
                confidence: format!("{} match", method),
            });
            continue;
        }

        // Step: match against HTML body content
        for pattern in sig.html {
            if body_lower.contains(pattern) {
                matched = true;
                method = "html";
                break;
            }
        }
        if matched {
            techs.push(Tech {
                name: sig.name.to_string(),
                category: sig.category.to_string(),
                confidence: format!("{} match", method),
            });
            continue;
        }

        // Step: match against cookie names
        for pattern in sig.cookies {
            for c in &result.cookies {
                if c.name.to_lowercase().contains(pattern) {
                    matched = true;
                    method = "cookie";
                    break;
                }
            }
            if matched {
                break;
            }
        }
        if matched {
            techs.push(Tech {
                name: sig.name.to_string(),
                category: sig.category.to_string(),
                confidence: format!("{} match", method),
            });
            continue;
        }

        // Step: match against meta tags
        for (name, pattern) in sig.meta {
            if let Ok(sel) = Selector::parse(&format!("meta[name='{}']", name)) {
                if let Some(el) = doc.select(&sel).next() {
                    let content = el.value().attr("content").unwrap_or("").to_lowercase();
                    if pattern.is_empty() || content.contains(pattern) {
                        matched = true;
                        method = "meta";
                        break;
                    }
                }
            }
        }
        if matched {
            techs.push(Tech {
                name: sig.name.to_string(),
                category: sig.category.to_string(),
                confidence: format!("{} match", method),
            });
            continue;
        }

        // Step: match against script src attributes
        for pattern in sig.scripts {
            if let Ok(sel) = Selector::parse("script[src]") {
                for el in doc.select(&sel) {
                    if let Some(src) = el.value().attr("src") {
                        if src.to_lowercase().contains(pattern) {
                            matched = true;
                            method = "script";
                            break;
                        }
                    }
                }
                if matched {
                    break;
                }
            }
        }
        if matched {
            techs.push(Tech {
                name: sig.name.to_string(),
                category: sig.category.to_string(),
                confidence: format!("{} match", method),
            });
        }
    }

    result.technologies = techs;
}
