/// Shroud — DNS Reconnaissance
///
/// Multi-resolver DNS lookup engine for A, AAAA, CNAME, NS, MX, TXT,
/// and PTR records. Supports CNAME chain resolution, cross-resolver
/// queries (Cloudflare, Google, Quad9), and node aggregation.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use std::net::IpAddr;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use crate::stealth::jitter;

/// Creates a default DNS resolver using Cloudflare with a 10-second timeout.
pub fn create_resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(10);
    opts.attempts = 2;
    TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
}

/// Creates a DNS resolver with a custom configuration and 8-second timeout.
pub fn create_resolver_with(config: &ResolverConfig) -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(8);
    opts.attempts = 1;
    TokioAsyncResolver::tokio(config.clone(), opts)
}

/// Resolves A records for a domain.
pub async fn resolve_a(
    resolver: &TokioAsyncResolver,
    domain: &str,
    jitter_ms: u64,
) -> Vec<IpAddr> {
    jitter(jitter_ms).await;
    match resolver.ipv4_lookup(domain).await {
        Ok(response) => response.iter().map(|r| IpAddr::V4(**r)).collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolves AAAA records for a domain.
pub async fn resolve_aaaa(
    resolver: &TokioAsyncResolver,
    domain: &str,
    jitter_ms: u64,
) -> Vec<IpAddr> {
    jitter(jitter_ms).await;
    match resolver.ipv6_lookup(domain).await {
        Ok(response) => response.iter().map(|r| IpAddr::V6(**r)).collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolves a PTR record for an IP address.
pub async fn resolve_ptr(ip: IpAddr, jitter_ms: u64) -> Option<String> {
    jitter(jitter_ms).await;
    let resolver = create_resolver();
    match resolver.reverse_lookup(ip).await {
        Ok(response) => {
            response.iter().next().map(|r| r.to_string().trim_end_matches('.').to_string())
        }
        Err(_) => None,
    }
}

/// Resolves a CNAME chain for a domain up to a maximum depth.
pub async fn resolve_cname(
    resolver: &TokioAsyncResolver,
    domain: &str,
    jitter_ms: u64,
) -> Vec<String> {
    jitter(jitter_ms).await;
    let mut chain = Vec::new();
    let mut current = domain.to_string();
    let max_depth = 10;
    for _ in 0..max_depth {
        match resolver.lookup(&current, RecordType::CNAME).await {
            Ok(response) => {
                let cname = match response.iter().next() {
                    Some(r) => r.to_string(),
                    None => break,
                };
                let cname = cname.trim_end_matches('.').to_string();
                if chain.contains(&cname) {
                    break;
                }
                chain.push(cname.clone());
                current = cname;
            }
            Err(_) => break,
        }
    }
    chain
}

/// Resolves NS records for a domain.
pub async fn resolve_ns(
    resolver: &TokioAsyncResolver,
    domain: &str,
    jitter_ms: u64,
) -> Vec<String> {
    jitter(jitter_ms).await;
    match resolver.ns_lookup(domain).await {
        Ok(response) => response
            .iter()
            .map(|r| r.to_string().trim_end_matches('.').to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolves MX records for a domain, sorted by preference.
pub async fn resolve_mx(
    resolver: &TokioAsyncResolver,
    domain: &str,
    jitter_ms: u64,
) -> Vec<String> {
    jitter(jitter_ms).await;
    match resolver.mx_lookup(domain).await {
        Ok(response) => {
            let mut records: Vec<String> = response
                .iter()
                .map(|r| {
                    format!(
                        "{} {}",
                        r.preference(),
                        r.exchange().to_string().trim_end_matches('.')
                    )
                })
                .collect();
            records.sort();
            records
        }
        Err(_) => Vec::new(),
    }
}

/// Resolves TXT records for a domain.
pub async fn resolve_txt(
    resolver: &TokioAsyncResolver,
    domain: &str,
    jitter_ms: u64,
) -> Vec<String> {
    jitter(jitter_ms).await;
    match resolver.txt_lookup(domain).await {
        Ok(response) => response
            .iter()
            .flat_map(|r| {
                let txt: Vec<String> = r
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect();
                txt
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Queries a domain across multiple public resolvers and aggregates results.
pub async fn query_multiple_resolvers(domain: &str) -> Vec<IpAddr> {
    let mut all_ips = Vec::new();
    let resolvers = [
        (ResolverConfig::cloudflare(), "Cloudflare"),
        (ResolverConfig::google(), "Google"),
        (ResolverConfig::quad9(), "Quad9"),
    ];
    for (config, _name) in &resolvers {
        let resolver = create_resolver_with(config);
        if let Ok(response) = resolver.ipv4_lookup(domain).await {
            let ips: Vec<IpAddr> = response.iter().map(|r| IpAddr::V4(**r)).collect();
            all_ips.extend(ips);
        }
    }
    all_ips.sort();
    all_ips.dedup();
    all_ips
}

/// Gathers all DNS nodes (A, AAAA, CNAME, NS, MX, TXT) for a domain.
///
/// Also resolves IPs for name servers and CNAME targets to build a
/// complete node list. Deduplicates and sorts the final result.
pub async fn gather_nodes(
    domain: &str,
    jitter_ms: u64,
) -> (Vec<IpAddr>, Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let resolver = create_resolver();

    let a_records = resolve_a(&resolver, domain, jitter_ms).await;
    let aaaa_records = resolve_aaaa(&resolver, domain, jitter_ms).await;
    let cnames = resolve_cname(&resolver, domain, jitter_ms).await;
    let ns = resolve_ns(&resolver, domain, jitter_ms).await;
    let mx = resolve_mx(&resolver, domain, jitter_ms).await;
    let txt = resolve_txt(&resolver, domain, jitter_ms).await;

    // Aggregate all IPs from direct resolution
    let mut nodes = a_records;
    nodes.extend(aaaa_records);

    // Resolve NS hosts to IPs
    for ns_host in &ns {
        let ns_resolver = create_resolver();
        let ips = resolve_a(&ns_resolver, ns_host, 0).await;
        nodes.extend(ips);
    }

    // Resolve CNAME targets to IPs
    for cname in &cnames {
        let cname_resolver = create_resolver();
        let ips = resolve_a(&cname_resolver, cname, 0).await;
        nodes.extend(ips);
    }

    nodes.sort();
    nodes.dedup();

    // Cross-reference with other resolvers
    let multi_ips = query_multiple_resolvers(domain).await;
    nodes.extend(multi_ips);
    nodes.sort();
    nodes.dedup();

    (nodes, cnames, ns, mx, txt)
}
