/// Toolkit 3: Tracer — MX and NS origin tracing with PTR scanning.
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, TcpStream as StdTcpStream};
use std::io::Read;
use std::time::Duration;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use tokio::time::timeout;
use crate::models::{OriginCandidate, ScanTarget, DnsRecord};
use crate::stealth::jitter;

/// Tracer toolkit that discovers mail-server and nameserver origin IPs
/// and performs reverse-DNS (PTR) scans on adjacent addresses.
pub struct TracerToolkit {
    pub domain: String,
    pub jitter_ms: u64,
    pub port_timeout: u64,
}

impl TracerToolkit {
    /// Create a new `TracerToolkit` for the given domain.
    pub fn new(domain: &str, jitter_ms: u64, port_timeout: u64) -> Self {
        Self {
            domain: domain.to_string(),
            jitter_ms,
            port_timeout,
        }
    }

    /// Build a Cloudflare-based async DNS resolver.
    fn resolver() -> TokioAsyncResolver {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(10);
        opts.attempts = 2;
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
    }

    /// Trace MX mail-server origins — resolve MX hosts to IPs and
    /// collect SMTP banners.
    pub async fn trace_mx(&self) -> Vec<OriginCandidate> {
        let mut origins = Vec::new();
        let mut seen = HashSet::new();
        let resolver = Self::resolver();

        jitter(self.jitter_ms).await;
        // Step: Look up MX records
        let mx_records = if let Ok(response) = resolver.mx_lookup(&self.domain).await {
            response.iter().map(|r| {
                let exchange = r.exchange().to_string().trim_end_matches('.').to_string();
                let preference = r.preference();
                (exchange, preference)
            }).collect::<Vec<_>>()
        } else {
            return origins;
        };

        // Loop: Process each MX exchange
        for (exchange, _pref) in &mx_records {
            jitter(self.jitter_ms / 2).await;
            // Step: Resolve MX hostname to IPv4 addresses
            let mx_ips = if let Ok(response) = resolver.ipv4_lookup(exchange).await {
                response.iter().map(|r| IpAddr::V4(**r)).collect::<Vec<_>>()
            } else {
                continue;
            };

            // Loop: Process each MX IP
            for mx_ip in mx_ips {
                // Check: Deduplicate IPs
                if !seen.insert(mx_ip) {
                    continue;
                }

                // Step: Connect to port 25 (SMTP) and read banner
                let addr = SocketAddr::new(mx_ip, 25);
                let dur = Duration::from_millis(self.port_timeout);
                let banner = if let Ok(Ok(mut stream)) = timeout(dur, async {
                    StdTcpStream::connect_timeout(&addr, Duration::from_secs(5))
                }).await {
                    let mut buf = [0u8; 512];
                    let mut banner = String::new();
                    if stream.read(&mut buf).is_ok() {
                        banner = String::from_utf8_lossy(&buf).to_string();
                    }
                    stream.shutdown(std::net::Shutdown::Both).ok();
                    Some(banner)
                } else {
                    None
                };

                origins.push(OriginCandidate {
                    ip: mx_ip,
                    port: 25,
                    confidence: 60,
                    source: format!("MX: {}", exchange),
                    hostname: Some(exchange.clone()),
                    server_header: banner,
                    status_code: None,
                    body_hash: None,
                    response_time_ms: None,
                });
            }
        }

        origins
    }

    /// Trace nameserver origins — resolve NS hosts to IPs.
    pub async fn trace_ns(&self) -> Vec<OriginCandidate> {
        let mut origins = Vec::new();
        let mut seen = HashSet::new();
        let resolver = Self::resolver();

        jitter(self.jitter_ms).await;
        // Step: Look up NS records
        let ns_records = if let Ok(response) = resolver.ns_lookup(&self.domain).await {
            response.iter()
                .map(|r| r.to_string().trim_end_matches('.').to_string())
                .collect::<Vec<_>>()
        } else {
            return origins;
        };

        // Loop: Process each nameserver
        for ns_host in &ns_records {
            jitter(self.jitter_ms / 2).await;
            // Step: Resolve NS hostname to IPv4 addresses
            if let Ok(response) = resolver.ipv4_lookup(ns_host).await {
                for ip in response.iter() {
                    let ip = IpAddr::V4(**ip);
                    // Check: Deduplicate IPs
                    if seen.insert(ip) {
                        origins.push(OriginCandidate {
                            ip,
                            port: 53,
                            confidence: 50,
                            source: format!("NS: {}", ns_host),
                            hostname: Some(ns_host.clone()),
                            server_header: None,
                            status_code: None,
                            body_hash: None,
                            response_time_ms: None,
                        });
                    }
                }
            }
        }

        origins
    }

    /// Scan adjacent IPs in the given CIDRs for PTR records (reverse DNS).
    pub async fn ptr_scan(&self, cidrs: &[String]) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        let resolver = Self::resolver();

        // Loop: Process each CIDR range
        for cidr in cidrs {
            if let Some((base, _bits)) = cidr.split_once('/') {
                let base_ip: std::net::Ipv4Addr = match base.trim().parse() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                let prefix: u32 = u32::from(base_ip);
                // Loop: Check first 4 adjacent IPs for PTR records
                for offset in 1..5 {
                    let octets = (prefix + offset).to_be_bytes();
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
                    jitter(self.jitter_ms).await;
                    if let Ok(response) = resolver.reverse_lookup(ip).await {
                        for name in response.iter() {
                            records.push(DnsRecord {
                                record_type: "PTR".to_string(),
                                value: format!("{} -> {}", ip, name.to_string().trim_end_matches('.')),
                                source: "Reverse DNS".to_string(),
                            });
                        }
                    }
                }
            }
        }

        records
    }

    /// Run all tracer stages, returning origins, scan targets, and PTR records.
    pub async fn run(&self, cidrs: &[String]) -> (Vec<OriginCandidate>, Vec<ScanTarget>, Vec<DnsRecord>) {
        // Stage: Trace MX origins
        let mx_origins = self.trace_mx().await;
        // Stage: Trace NS origins
        let ns_origins = self.trace_ns().await;
        // Stage: PTR records
        let ptr_records = self.ptr_scan(cidrs).await;

        // Step: Combine all discovered origins
        let mut origins = mx_origins;
        origins.extend(ns_origins);

        // Step: Map origins to scan targets
        let targets: Vec<ScanTarget> = origins
            .iter()
            .map(|o| ScanTarget {
                ip: o.ip,
                port: o.port,
                service: if o.port == 25 { "SMTP".to_string() } else { "DNS".to_string() },
                banner: o.server_header.clone(),
            })
            .collect();

        (origins, targets, ptr_records)
    }
}
