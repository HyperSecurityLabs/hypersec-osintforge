/// Secret detection patterns and utility functions.
///
/// Defines regex-based patterns for cloud credentials, API tokens, database URLs,
/// private keys, and other sensitive data. Also provides entropy analysis,
/// false-positive filtering, and JWT validation.
use once_cell::sync::Lazy;
use regex::Regex;

/// A single secret detection pattern with name, severity, and compiled regex.
pub struct SecretPattern {
    /// Human-readable name for the pattern.
    pub name: &'static str,
    /// Severity level (critical, high, medium, low).
    pub severity: &'static str,
    /// Lazily compiled regex for matching.
    pub regex: Lazy<Regex>,
}

/// Macro for concise pattern definition.
macro_rules! pat {
    ($name:expr, $sev:expr, $re:expr) => {
        SecretPattern {
            name: $name,
            severity: $sev,
            regex: Lazy::new(|| Regex::new($re).expect("bad regex")),
        }
    };
}

/// All registered secret detection patterns.
pub static PATTERNS: Lazy<Vec<SecretPattern>> = Lazy::new(|| vec![
    // Cloud credentials
    pat!("AWS Access Key ID", "high", r"(?i)A[SK]IA[0-9A-Z]{16}"),
    pat!("AWS Secret Access Key", "critical", r#"(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]"#),
    pat!("AWS Secret Key", "critical", r"(?i)secret_access_key.{0,30}[0-9a-zA-Z/+]{40}"),
    pat!("AWS Session Token", "high", r"(?i)aws_session_token.{0,30}[0-9a-zA-Z/+]{40,}"),
    pat!("Google API Key", "high", r"AIza[0-9A-Za-z\-_]{35}"),
    pat!("Google OAuth", "high", r#"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"#),
    pat!("Heroku API Key", "high", r"(?i)heroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    pat!("Azure Connection String", "high", r"(?i)(AccountName|AccountKey|DefaultEndpointsProtocol)=.{10,80}"),

    // Tokens
    pat!("GitHub PAT", "critical", r"(?i)ghp_[0-9a-zA-Z]{36}"),
    pat!("GitHub OAuth", "critical", r"(?i)gho_[0-9a-zA-Z]{36}"),
    pat!("GitLab PAT", "critical", r"(?i)glpat-[0-9a-zA-Z\-_]{20,40}"),
    pat!("Slack Token", "critical", r"(?i)xox[baprs]-[0-9a-zA-Z\-]{20,80}"),
    pat!("Discord Bot Token", "critical", r"[MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6}\.[A-Za-z\d\-_]{27,38}"),
    pat!("Telegram Bot Token", "high", r"[0-9]{8,10}:[a-zA-Z0-9\-_]{35}"),
    pat!("JWT Token", "high", r"(?i)eyJ[a-zA-Z0-9\-_]{10,}\.eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}"),
    pat!("npm auth token", "high", r"(?i)_auth.{0,10}[a-zA-Z0-9/+]{20,}={0,2}"),
    pat!("Docker config auth", "high", r"(?i)auths[\s\S]{0,200}auth.{0,50}[a-zA-Z0-9/+]{20,}={0,2}"),

    // Database connection strings
    pat!("MySQL DB URL", "high", r"(?i)mysql://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\._/-]+:[0-9]+"),
    pat!("PostgreSQL DB URL", "high", r"(?i)postgres(ql)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\._/-]+:[0-9]+"),
    pat!("MongoDB DB URL", "high", r"(?i)mongo(db)?://[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9\._/-]+:[0-9]+"),
    pat!("Redis DB URL", "high", r"(?i)redis://[^@\s]+@[a-zA-Z0-9\._/-]+:[0-9]+"),
    pat!("JDBC Connection", "high", r"jdbc:[a-z]+://[a-zA-Z0-9\._/-]+:[0-9]+/[a-zA-Z0-9_]+"),

    // Auth strings
    pat!("Authorization: Basic", "high", r"(?i)authorization.{0,10}basic\s[a-zA-Z0-9/+]{20,}={0,2}"),
    pat!("Authorization: Bearer", "critical", r"(?i)authorization.{0,10}bearer\s[a-zA-Z0-9\-_\.]{20,100}"),
    pat!("Generic API Key", "medium", r#"(?i)(api[_-]?key|apikey|api_secret).{0,10}['"][a-zA-Z0-9_\-]{16,}['"]"#),
    pat!("Generic Password", "medium", r#"(?i)(password|passwd|pwd).{0,10}['"][^'"\s]{6,}['"]"#),
    pat!("Generic Secret", "medium", r#"(?i)(secret|token|credential).{0,10}['"][a-zA-Z0-9_\-]{16,}['"]"#),

    // Crypto keys
    pat!("SSH Private Key", "critical", r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"),
    pat!("PGP Private Key Block", "critical", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    pat!("PEM Certificate", "medium", r"-----BEGIN CERTIFICATE-----"),

    // Cloud URLs
    pat!("S3 Bucket URL", "medium", r"(?i)s3\.amazonaws\.com/[a-zA-Z0-9\-\._]{3,}"),
    pat!("S3 Bucket (explicit)", "medium", r"(?i)s3://[a-zA-Z0-9\-\._]{3,}"),

    // Hashes (low severity, entropy-gated when --no-low-entropy is set)
    pat!("SHA256 Hash", "low", r"[a-fA-F0-9]{64}"),
    pat!("SHA1 Hash", "low", r"[a-fA-F0-9]{40}"),
    pat!("MD5 Hash", "low", r"[a-fA-F0-9]{32}"),
]);

/// Compute the Shannon entropy of a string.
///
/// Higher values indicate more randomness, which correlates with
/// the likelihood of a secret or token.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f64;
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    -counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / len;
        acc + p * p.log2()
    })
}

/// Check if a match looks like a false positive (test data, placeholder, etc.).
pub fn is_low_quality_match(matched: &str, line: &str) -> bool {
    let combined = format!("{} {}", matched, line).to_lowercase();
    let keywords = [
        "example", "test", "your-", "xxxx", "changeme",
        "placeholder", "todo",
    ];
    keywords.iter().any(|&kw| combined.contains(kw))
}

/// Validate that a JWT token has exactly 3 dot-separated segments.
pub fn validate_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}
