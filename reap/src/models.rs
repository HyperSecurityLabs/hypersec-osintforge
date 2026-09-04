/// Data models for the REAP web intelligence profiler.
use serde::Serialize;

/// A detected technology with its category and confidence.
#[derive(Debug, Serialize, Clone)]
pub struct Tech {
    pub name: String,
    pub category: String,
    pub confidence: String,
}

/// A security header audit result.
#[derive(Debug, Serialize, Clone)]
pub struct SecurityHeader {
    pub header: String,
    pub present: bool,
    pub value: Option<String>,
    pub note: String,
}

/// Parsed cookie information.
#[derive(Debug, Serialize, Clone)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub domain: Option<String>,
    pub path: Option<String>,
}

/// A discovered web endpoint with status code and metadata.
#[derive(Debug, Serialize, Clone)]
pub struct Endpoint {
    pub path: String,
    pub status: u16,
    pub size: Option<u64>,
    pub content_type: Option<String>,
}

/// A form field with type and attributes.
#[derive(Debug, Serialize, Clone)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub placeholder: Option<String>,
}

/// An HTML form with action, method, and fields.
#[derive(Debug, Serialize, Clone)]
pub struct Form {
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
}

/// A single HTTP redirect entry.
#[derive(Debug, Serialize, Clone)]
pub struct Redirect {
    pub status: u16,
    pub url: String,
}

/// A hyperlink with href and anchor text.
#[derive(Debug, Serialize, Clone)]
pub struct Link {
    pub href: String,
    pub text: String,
}

/// Web Application Firewall detection result.
#[derive(Debug, Serialize, Clone)]
pub struct WafInfo {
    pub detected: bool,
    pub name: String,
    pub manufacturer: String,
    pub signals: Vec<String>,
}

/// A single DNS record (type + value).
#[derive(Debug, Serialize, Clone)]
pub struct DnsRecord {
    pub rtype: String,
    pub value: String,
}

/// DNS information — collection of resolved records.
#[derive(Debug, Serialize, Clone)]
pub struct DnsInfo {
    pub records: Vec<DnsRecord>,
}

/// A detected JavaScript file reference with hints.
#[derive(Debug, Serialize, Clone)]
pub struct JsFile {
    pub src: String,
    pub is_inline: bool,
    pub hints: Vec<String>,
}

/// JavaScript analysis result (files, API hints, SPA routes).
#[derive(Debug, Serialize, Clone)]
pub struct JsInfo {
    pub files: Vec<JsFile>,
    pub api_hints: Vec<String>,
    pub spa_routes: Vec<String>,
}

/// Page content classification result.
#[derive(Debug, Serialize, Clone)]
pub struct PageInfo {
    pub classification: String,
    pub has_login_form: bool,
    pub has_upload: bool,
    pub error_disclosure: Vec<String>,
    pub tech_hints: Vec<String>,
}

/// HTTP response metadata and analysis data.
#[derive(Debug, Default, Serialize, Clone)]
pub struct HttpInfo {
    pub final_url: Option<String>,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub headers: Vec<(String, String)>,
    pub meta_tags: Vec<String>,
    pub redirects: Vec<Redirect>,
    pub cookies: Vec<CookieInfo>,
    pub forms: Vec<Form>,
    pub technologies: Vec<Tech>,
    pub security_headers: Vec<SecurityHeader>,
    pub links: Vec<Link>,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub social_links: Vec<String>,
}

/// Discovered endpoints and subdomains during scanning.
#[derive(Debug, Default, Serialize, Clone)]
pub struct ScanInfo {
    pub endpoints: Vec<Endpoint>,
    pub subdomains: Vec<String>,
}

/// Timing breakdown in milliseconds for each scan phase.
#[derive(Debug, Default, Serialize, Clone)]
pub struct Timing {
    pub fetch_ms: u64,
    pub dns_ms: u64,
    pub scan_ms: u64,
    pub js_ms: u64,
    pub total_ms: u64,
}

/// Top-level result of a full REAP scan.
#[derive(Debug, Default, Serialize, Clone)]
pub struct ReapResult {
    pub target: String,
    pub http: Option<HttpInfo>,
    pub scan: Option<ScanInfo>,
    pub waf: Option<WafInfo>,
    pub dns: Option<DnsInfo>,
    pub js: Option<JsInfo>,
    pub page: Option<PageInfo>,
    pub timing: Timing,
    pub error: Option<String>,
}
