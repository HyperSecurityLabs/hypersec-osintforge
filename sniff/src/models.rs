/// Data models for the SNIFF subdomain-hunter and takeover detector.
use serde::Serialize;

/// Top-level result of a SNIFF scan against a single target.
///
/// Holds the canonical target name, every discovered subdomain,
/// optional zone-transfer result, wildcard flag, and any fatal error.
#[derive(Debug, Default, Serialize, Clone)]
pub struct SniffResult {
    pub target: String,
    pub subdomains: Vec<Subdomain>,
    pub zone_transfer: Option<ZoneTransferResult>,
    pub wildcard: bool,
    pub error: Option<String>,
}

/// A single subdomain with its resolution and HTTP-probe metadata.
///
/// Fields are progressively populated by passive recon, DNS
/// resolution, HTTP probing, and takeover detection stages.
#[derive(Debug, Serialize, Clone)]
pub struct Subdomain {
    pub name: String,
    pub ip: Option<String>,
    pub source: String,
    pub status_code: Option<u16>,
    pub title: Option<String>,
    pub takeover: Option<TakeoverInfo>,
}

/// Describes a potential subdomain takeover vulnerability.
#[derive(Debug, Serialize, Clone)]
pub struct TakeoverInfo {
    pub service: String,
    pub cname: String,
    pub vulnerable: bool,
}

/// Result of a DNS zone-transfer (AXFR) attempt.
#[derive(Debug, Serialize, Clone)]
pub struct ZoneTransferResult {
    pub success: bool,
    pub records: Vec<String>,
}
