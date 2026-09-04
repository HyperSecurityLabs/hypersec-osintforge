/// Common web endpoint scanner.
///
/// Probes a list of sensitive or interesting paths on the target
/// to discover accessible endpoints, configuration files, and admin panels.
use crate::models::{Endpoint, ScanInfo};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Common paths to check during endpoint scanning.
const COMMON_PATHS: &[&str] = &[
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/",
    "/.well-known/security.txt",
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/admin/",
    "/admin",
    "/wp-admin/",
    "/wp-content/",
    "/wp-includes/",
    "/wp-json/",
    "/backup/",
    "/backup",
    "/api/",
    "/api",
    "/v1/",
    "/v2/",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/config/",
    "/config.json",
    "/config.php",
    "/configuration.php",
    "/db/",
    "/database/",
    "/install/",
    "/install.php",
    "/login",
    "/login/",
    "/register",
    "/register/",
    "/.htaccess",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/README.md",
    "/CHANGELOG.md",
    "/composer.json",
    "/package.json",
    "/Cargo.toml",
    "/Dockerfile",
    "/docker-compose.yml",
    "/nginx.conf",
    "/web.config",
    "/.travis.yml",
    "/Jenkinsfile",
    "/public/",
    "/private/",
    "/temp/",
    "/tmp/",
    "/logs/",
    "/error.log",
    "/debug/",
    "/test/",
    "/status",
    "/health",
    "/healthz",
    "/metrics",
    "/version",
    "/info.php",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
];

/// Scan common web paths on the target and return discovered endpoints.
///
/// Uses a semaphore-limited concurrent worker pool (max 20) for efficiency.
pub async fn scan(_target: &str, client: Client, base_url: &str) -> ScanInfo {
    let mut info = ScanInfo::default();
    let sem = Arc::new(Semaphore::new(20));
    let mut handles = Vec::new();

    // Loop: spawn a concurrent request for each path
    for path in COMMON_PATHS {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let sem = sem.clone();
        let client = client.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            match client.get(&url).timeout(Duration::from_secs(4)).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Check: only collect interesting status codes
                    if status == 200 || status == 401 || status == 403 || status == 301 || status == 302 || status == 307 || status == 308 {
                        let size = resp
                            .headers()
                            .get("content-length")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok());
                        let ct = resp
                            .headers()
                            .get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string());
                        Some(Endpoint {
                            path: path.to_string(),
                            status,
                            size,
                            content_type: ct,
                        })
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }));
    }

    // Step: collect all results
    for handle in handles {
        if let Ok(Some(ep)) = handle.await {
            info.endpoints.push(ep);
        }
    }

    info
}
