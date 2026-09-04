/// Shroud — Data Models
///
/// Defines the structured data types for network topology nodes,
/// geolocation info, service fingerprints, and scan results.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use serde::Serialize;
use std::net::IpAddr;
use std::collections::HashMap;

/// Geographic and ASN information for a network node.
#[derive(Debug, Clone, Serialize)]
pub struct GeoInfo {
    pub city: String,
    pub region: String,
    pub country: String,
    pub org: String,
    pub asn: String,
    pub as_org: String,
    pub isp: String,
}

/// A discovered network node with associated metadata.
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub ip: IpAddr,
    pub hostname: String,
    pub layer: String,
    pub source: String,
    pub latency_ms: f64,
    pub geo: Option<GeoInfo>,
    pub reverse_dns: Option<String>,
    pub open_ports: Vec<u16>,
    pub asn_cidr: Option<String>,
}

/// A fingerprinted service running on an open port.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceFingerprint {
    pub ip: IpAddr,
    pub port: u16,
    pub service: Option<String>,
    pub banner: Option<String>,
}

/// Top-level scan result aggregating all reconnaissance findings.
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub target: String,
    pub timestamp: String,
    pub duration_secs: f64,
    pub resolver_chain: Vec<String>,
    pub nodes: Vec<Node>,
    pub cidr_ranges: Vec<String>,
    pub cname_chain: Vec<String>,
    pub nameservers: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub subdomains: Vec<String>,
    pub ssl_cert_issuer: Option<String>,
    pub server_header: Option<String>,
    pub waf: Option<String>,
    pub services: Vec<ServiceFingerprint>,
    pub asn_map: HashMap<String, Vec<IpAddr>>,
}
