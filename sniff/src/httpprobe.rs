/// HTTP(S) subdomain probing for status code and HTML title extraction.
use crate::models::Subdomain;
use crate::stealth;

/// Probe a batch of subdomains with HTTP requests.
///
/// For each subdomain an HTTP GET is sent (optionally via a proxy).
/// The response status code is recorded and, when the content type
/// indicates text/html or application/json, the `<title>` is parsed
/// from the response body.
pub async fn probe(subdomains: &[Subdomain], proxy: Option<&str>) -> Vec<Subdomain> {
    // Step: Build the reqwest client with stealth UA and redirect limit
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .user_agent(stealth::random_ua())
        .redirect(reqwest::redirect::Policy::limited(3));
    // Check: Apply optional proxy
    if let Some(proxy_url) = proxy {
        if let Ok(p) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(p);
        }
    }
    let client = match builder.build()
    {
        Ok(c) => c,
        Err(_) => return subdomains.to_vec(),
    };

    let mut results = Vec::new();
    // Loop: Probe each subdomain individually
    for sd in subdomains {
        let url = format!("http://{}", sd.name);
        let mut enriched = sd.clone();
        // Handle: Attempt GET request
        if let Ok(resp) = client.get(&url).send().await {
            enriched.status_code = Some(resp.status().as_u16());
            // Check: Content-type allows title extraction
            if let Some(ct) = resp.headers().get("content-type") {
                if let Ok(val) = ct.to_str() {
                    // Branch: HTML or JSON bodies may contain a title
                    if val.contains("text/html") || val.contains("application/json") {
                        if let Ok(body) = resp.text().await {
                            enriched.title = extract_title(&body);
                        }
                    }
                }
            }
        }
        results.push(enriched);
    }

    results
}

/// Extract the text content of the first `<title>` tag from raw HTML.
///
/// Returns `None` when no title tag is found or the tag is empty.
fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let open = "<title>";
    let close = "</title>";

    // Step: Locate opening tag
    let start = lower.find(open)?;
    let content_start = start + open.len();
    // Step: Locate closing tag after content start
    let end = lower[content_start..].find(close)?;

    let title = html[content_start..content_start + end].trim().to_string();
    // Check: Return None for empty titles
    if title.is_empty() { None } else { Some(title) }
}
