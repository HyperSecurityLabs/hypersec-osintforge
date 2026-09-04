/// Data models for the EXFIL scanner results.
/// Defines the serialisable result types for CORS, IDOR, S3, and fuzz scans.
use serde::Serialize;

/// Top-level result produced by an EXFIL scan.
#[derive(Debug, Default, Serialize, Clone)]
pub struct ExfilResult {
    pub target: String,
    pub cors: Vec<CorsResult>,
    pub idor: Vec<IdorResult>,
    pub s3: Vec<S3Result>,
    pub fuzz: Vec<FuzzResult>,
    pub endpoints_scanned: u32,
    pub vulnerabilities: u32,
    pub error: Option<String>,
}

/// Result of testing a single CORS origin.
#[derive(Debug, Serialize, Clone)]
pub struct CorsResult {
    pub endpoint: String,
    pub origin: String,
    pub allowed: bool,
    pub credentials: bool,
    pub wildcard: bool,
    pub level: String,
}

/// Result of testing a single IDOR mutation.
#[derive(Debug, Serialize, Clone)]
pub struct IdorResult {
    pub endpoint: String,
    pub parameter: String,
    pub original_id: String,
    pub test_id: String,
    pub original_status: u16,
    pub test_status: u16,
    pub original_length: usize,
    pub test_length: usize,
    pub potential_idor: bool,
    pub level: String,
}

/// Result of testing a single S3 bucket endpoint.
#[derive(Debug, Serialize, Clone)]
pub struct S3Result {
    pub bucket_url: String,
    pub accessible: bool,
    pub listable: bool,
    pub writable: bool,
    pub level: String,
}

/// Result of testing a single fuzz parameter.
#[derive(Debug, Serialize, Clone)]
pub struct FuzzResult {
    pub endpoint: String,
    pub parameter: String,
    pub status: u16,
    pub body_length: usize,
    pub reflection: bool,
    pub level: String,
}
