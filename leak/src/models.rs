/// Data models for the LEAK secret scanner.
use serde::Serialize;

/// Top-level result of a secret scan.
#[derive(Debug, Default, Serialize, Clone)]
pub struct ScanResult {
    /// The original target path or domain.
    pub target: String,
    /// Number of files scanned.
    pub files_scanned: u32,
    /// List of secret matches found.
    pub matches: Vec<SecretMatch>,
    /// Error message if the scan failed.
    pub error: Option<String>,
}

/// A single secret match within a file.
#[derive(Debug, Serialize, Clone)]
pub struct SecretMatch {
    /// Path to the file containing the match.
    pub file: String,
    /// Line number of the match.
    pub line: u32,
    /// Name of the pattern that matched.
    pub pattern: String,
    /// Severity level (critical, high, medium, low).
    pub severity: String,
    /// Surrounding context snippet from the line.
    pub context: String,
}
