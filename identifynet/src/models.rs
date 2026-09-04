/// Data models for the IdentifyNet IP intelligence engine.
use serde::Serialize;

/// Top-level result of an IP/domain intelligence scan.
#[derive(Debug, Default, Serialize, Clone)]
pub struct IdentifyResult {
    /// The original target string (IP or domain).
    pub target: String,
    /// Resolved IP address, if available.
    pub ip: Option<String>,
    /// Geographic location data from MaxMind GeoLite2-City.
    pub geo: Option<GeoInfo>,
    /// Autonomous System number and organization from GeoLite2-ASN.
    pub asn: Option<AsnInfo>,
    /// DNS records (PTR, MX, NS, TXT).
    pub dns: Option<DnsInfo>,
    /// WHOIS registration data.
    pub whois: Option<WhoisInfo>,
    /// Top-20 TCP port scan results.
    pub ports: Option<PortScanInfo>,
    /// Error message if the scan failed.
    pub error: Option<String>,
    /// Timing breakdown for each scan phase.
    pub timing: Timing,
}

/// Geographic location data.
#[derive(Debug, Default, Serialize, Clone)]
pub struct GeoInfo {
    pub city: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub postal: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

/// Autonomous System Number information.
#[derive(Debug, Default, Serialize, Clone)]
pub struct AsnInfo {
    pub number: Option<u32>,
    pub organization: Option<String>,
    pub network: Option<String>,
}

/// DNS record data (PTR, MX, NS, TXT).
#[derive(Debug, Default, Serialize, Clone)]
pub struct DnsInfo {
    pub ptr: Option<String>,
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
}

/// WHOIS registration data.
#[derive(Debug, Default, Serialize, Clone)]
pub struct WhoisInfo {
    pub raw: String,
    pub netrange: Option<String>,
    pub orgname: Option<String>,
    pub tech_email: Option<String>,
    pub abuse_email: Option<String>,
}

/// Top-N TCP port scan result.
#[derive(Debug, Default, Serialize, Clone)]
pub struct PortScanInfo {
    pub open: Vec<OpenPort>,
    pub total_scanned: usize,
}

/// A single open TCP port with its service name.
#[derive(Debug, Serialize, Clone)]
pub struct OpenPort {
    pub port: u16,
    pub service: String,
}

/// Timing breakdown in milliseconds for each scan phase.
#[derive(Debug, Default, Serialize, Clone)]
pub struct Timing {
    pub geo_ms: u64,
    pub asn_ms: u64,
    pub dns_ms: u64,
    pub whois_ms: u64,
    pub portscan_ms: u64,
    pub total_ms: u64,
}
