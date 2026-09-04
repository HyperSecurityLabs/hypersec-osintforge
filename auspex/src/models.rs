/// Auspex — Data Models
///
/// Defines the structured data types for WHOIS info, RDAP info,
/// DNS correlation results, and the top-level investigation result.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

/// Structured WHOIS domain information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WhoisInfo {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrar_iana_id: Option<String>,
    pub registrant_org: Option<String>,
    pub registrant_name: Option<String>,
    pub registrant_email: Option<String>,
    pub registrant_phone: Option<String>,
    pub registrant_country: Option<String>,
    pub admin_email: Option<String>,
    pub admin_name: Option<String>,
    pub admin_org: Option<String>,
    pub tech_email: Option<String>,
    pub tech_name: Option<String>,
    pub abuse_email: Option<String>,
    pub name_servers: Vec<String>,
    pub creation_date: Option<NaiveDateTime>,
    pub expiration_date: Option<NaiveDateTime>,
    pub updated_date: Option<NaiveDateTime>,
    pub dnssec: Option<String>,
    pub status_codes: Vec<String>,
    pub raw: Option<String>,
    pub source_server: Option<String>,
}

/// RDAP (Registration Data Access Protocol) domain information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RdapInfo {
    pub domain: String,
    pub events: Vec<RdapEvent>,
    pub entities: Vec<RdapEntity>,
    pub status_codes: Vec<String>,
    pub name_servers: Vec<String>,
    pub dnssec: Option<String>,
    pub source: String,
}

/// A single RDAP lifecycle event (registration, expiration, update).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapEvent {
    pub action: String,
    pub date: Option<NaiveDateTime>,
}

/// An RDAP entity (registrar, registrant, admin, tech, abuse).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapEntity {
    pub role: String,
    pub name: Option<String>,
    pub org: Option<String>,
    pub email: Option<String>,
    pub country: Option<String>,
}

/// Correlated DNS records for a domain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsCorrelation {
    pub mx: Vec<String>,
    pub ns: Vec<String>,
    pub txt: Vec<String>,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub cname: Option<String>,
}

/// Top-level result aggregating all intelligence sources.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuspexResult {
    pub target: String,
    pub whois: Option<WhoisInfo>,
    pub rdap: Option<RdapInfo>,
    pub dns: Option<DnsCorrelation>,
    pub registrar_abuse_email: Option<String>,
    pub is_registered: bool,
    pub domain_age_days: Option<i64>,
    pub days_until_expiry: Option<i64>,
    pub error: Option<String>,
    pub timing_ms: u64,
}
