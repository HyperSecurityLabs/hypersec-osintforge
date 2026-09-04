/// Data model for TLS certificate scan results.
use serde::Serialize;

/// Represents the parsed result of an SSL/TLS certificate connection.
#[derive(Debug, Default, Serialize, Clone)]
pub struct CertResult {
    pub target: String,
    pub port: u16,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub chain_length: usize,
    pub subject_cn: Option<String>,
    pub subject_o: Option<String>,
    pub subject_ou: Option<String>,
    pub subject_l: Option<String>,
    pub subject_st: Option<String>,
    pub subject_c: Option<String>,
    pub issuer_cn: Option<String>,
    pub issuer_o: Option<String>,
    pub issuer_ou: Option<String>,
    pub issuer_c: Option<String>,
    pub san_dns: Vec<String>,
    pub san_ip: Vec<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub days_remaining: Option<i64>,
    pub serial: Option<String>,
    pub sha256_fingerprint: Option<String>,
    pub pub_key_algo: Option<String>,
    pub pub_key_size: Option<u32>,
    pub is_ca: bool,
    pub key_usage: Vec<String>,
    pub ext_key_usage: Vec<String>,
    pub crl_urls: Vec<String>,
    pub ocsp_url: Option<String>,
    pub error: Option<String>,
    #[serde(skip)]
    pub cert_der: Vec<u8>,
    #[serde(skip)]
    pub chain_der: Vec<Vec<u8>>,
}
