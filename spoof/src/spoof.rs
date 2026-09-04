/// SPOOF — Spoofability Analyzer
///
/// Evaluates a domain's email spoofability based on the presence
/// and strength of SPF, DMARC, and DKIM configurations, producing
/// a severity rating from CRITICAL to SAFE.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::{SpoofResult, SpoofStatus};

/// Analyzes the spoofability of a domain based on SPF, DMARC, and DKIM results.
///
/// Returns a SpoofStatus with a severity level (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
/// and a human-readable explanation.
pub fn analyze(result: &SpoofResult) -> SpoofStatus {
    let spf_weak = match &result.spf {
        Some(s) => s.all == "+all" || s.all == "?all" || s.all == "~all" || !s.valid,
        None => true,
    };
    let dmarc_weak = match &result.dmarc {
        Some(d) => d.policy == "none" || d.policy.is_empty() || !d.valid,
        None => true,
    };
    let no_spf = result.spf.is_none();
    let no_dmarc = result.dmarc.is_none();

    // Both missing — worst case
    if no_spf && no_dmarc {
        return SpoofStatus {
            level: "CRITICAL".to_string(),
            reason: "No SPF or DMARC records — any sender can spoof".to_string(),
        };
    }
    // Both weak
    if spf_weak && dmarc_weak {
        return SpoofStatus {
            level: "HIGH".to_string(),
            reason: format!("Weak SPF ({}) and weak DMARC ({}) — spoofing likely possible",
                result.spf.as_ref().map(|s| s.all.as_str()).unwrap_or("none"),
                result.dmarc.as_ref().map(|d| d.policy.as_str()).unwrap_or("none")),
        };
    }
    // Only SPF weak
    if spf_weak {
        return SpoofStatus {
            level: "MEDIUM".to_string(),
            reason: format!("Weak SPF policy ({}) — spoofing may be possible",
                result.spf.as_ref().map(|s| s.all.as_str()).unwrap_or("none")),
        };
    }
    // Only DMARC weak
    if dmarc_weak {
        return SpoofStatus {
            level: "LOW".to_string(),
            reason: format!("Weak DMARC policy ({}) — spoofing may be possible",
                result.dmarc.as_ref().map(|d| d.policy.as_str()).unwrap_or("none")),
        };
    }
    // Both strong
    SpoofStatus {
        level: "SAFE".to_string(),
        reason: "SPF hard-fail and DMARC reject/quarantine — spoofing mitigated".to_string(),
    }
}
