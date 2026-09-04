/// Auspex — DNS Correlation
///
/// Performs multi-record DNS lookups (A, AAAA, MX, NS, TXT, CNAME)
/// for domain intelligence gathering using the Hickory DNS resolver.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::DnsCorrelation;
use std::time::Duration;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// Creates a DNS resolver configured with Cloudflare and a 5-second timeout.
fn create_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 1;
    TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
}

/// Performs DNS record correlation against the given domain.
///
/// Returns a DnsCorrelation containing A, AAAA, MX, NS, TXT, and CNAME records.
pub async fn correlate(domain: &str) -> DnsCorrelation {
    let resolver = create_resolver();
    let mut dns = DnsCorrelation::default();

    // A records
    if let Ok(response) = resolver.ipv4_lookup(domain).await {
        dns.a_records = response.iter().map(|r| r.to_string()).collect();
    }

    // AAAA records
    if let Ok(response) = resolver.ipv6_lookup(domain).await {
        dns.aaaa_records = response.iter().map(|r| r.to_string()).collect();
    }

    // MX records
    if let Ok(response) = resolver.mx_lookup(domain).await {
        let mut mx: Vec<String> = response
            .iter()
            .map(|r| format!("{} preference={}", r.exchange().to_string().trim_end_matches('.'), r.preference()))
            .collect();
        mx.sort();
        dns.mx = mx;
    }

    // NS records
    if let Ok(response) = resolver.ns_lookup(domain).await {
        dns.ns = response
            .iter()
            .map(|r| r.to_string().trim_end_matches('.').to_string())
            .collect();
    }

    // TXT records
    if let Ok(response) = resolver.txt_lookup(domain).await {
        dns.txt = response
            .iter()
            .flat_map(|r| {
                r.iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
    }

    // CNAME record
    if let Ok(response) = resolver.lookup(domain, hickory_resolver::proto::rr::RecordType::CNAME).await {
        if let Some(r) = response.iter().next() {
            dns.cname = Some(r.to_string().trim_end_matches('.').to_string());
        }
    }

    dns
}
