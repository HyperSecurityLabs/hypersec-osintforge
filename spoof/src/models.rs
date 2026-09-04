/// SPOOF — Data Models
///
/// Defines the structured data types for MX, SPF, DMARC, DKIM,
/// SMTP relay results, and the top-level spoofability assessment.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use serde::Serialize;

/// Top-level result aggregating all email security checks.
#[derive(Debug, Default, Serialize, Clone)]
pub struct SpoofResult {
    pub target: String,
    pub mx: Vec<MxRecord>,
    pub spf: Option<SpfResult>,
    pub dmarc: Option<DmarcResult>,
    pub dkim: Vec<DkimResult>,
    pub relay: Option<RelayResult>,
    pub spoofable: SpoofStatus,
    pub error: Option<String>,
}

/// An MX record with optional resolved IP address.
#[derive(Debug, Serialize, Clone)]
pub struct MxRecord {
    pub host: String,
    pub ip: Option<String>,
    pub priority: u16,
}

/// SPF record result with policy and includes.
#[derive(Debug, Serialize, Clone)]
pub struct SpfResult {
    pub raw: String,
    pub all: String,
    pub includes: Vec<String>,
    pub valid: bool,
}

/// DMARC record result with policy, percentage, and report URIs.
#[derive(Debug, Serialize, Clone)]
pub struct DmarcResult {
    pub raw: String,
    pub policy: String,
    pub pct: u32,
    pub rua: Vec<String>,
    pub valid: bool,
}

/// DKIM record result for a specific selector.
#[derive(Debug, Serialize, Clone)]
pub struct DkimResult {
    pub selector: String,
    pub raw: String,
    pub valid: bool,
}

/// SMTP relay test result.
#[derive(Debug, Serialize, Clone)]
pub struct RelayResult {
    pub host: String,
    pub banner: String,
    pub open_relay: bool,
}

/// Spoofability assessment level and reasoning.
#[derive(Debug, Default, Serialize, Clone)]
pub struct SpoofStatus {
    pub level: String,
    pub reason: String,
}
