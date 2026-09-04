/// Data models for the UNEARTH origin-IP discovery framework.
use serde::Serialize;
use std::net::IpAddr;

/// A candidate origin IP address with metadata and confidence score.
#[derive(Debug, Clone, Serialize)]
pub struct OriginCandidate {
    pub ip: IpAddr,
    pub port: u16,
    pub confidence: u8,
    pub source: String,
    pub hostname: Option<String>,
    pub server_header: Option<String>,
    pub status_code: Option<u16>,
    pub body_hash: Option<String>,
    pub response_time_ms: Option<f64>,
}

/// A single DNS record discovered during reconnaissance.
#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub source: String,
}

/// A subdomain found via passive recon (e.g. crt.sh).
#[derive(Debug, Clone, Serialize)]
pub struct Subdomain {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub source: String,
}

/// A historical IP address associated with the target.
#[derive(Debug, Clone, Serialize)]
pub struct HistoricalIp {
    pub ip: IpAddr,
    pub date_seen: String,
    pub source: String,
}

/// An open port / service discovered during scanning.
#[derive(Debug, Clone, Serialize)]
pub struct ScanTarget {
    pub ip: IpAddr,
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
}

/// Results produced by one of the four toolkits.
#[derive(Debug, Clone, Serialize)]
pub struct ToolkitResult {
    pub name: String,
    pub origins: Vec<OriginCandidate>,
    pub subdomains: Vec<Subdomain>,
    pub dns_records: Vec<DnsRecord>,
    pub historical_ips: Vec<HistoricalIp>,
    pub open_targets: Vec<ScanTarget>,
}

/// Top-level result aggregating all four toolkit stages.
#[derive(Debug, Clone, Serialize)]
pub struct UnearthResult {
    pub target: String,
    pub timestamp: String,
    pub duration_secs: f64,
    pub results: Vec<ToolkitResult>,
    pub all_origins: Vec<OriginCandidate>,
    pub cidr_ranges: Vec<String>,
}
