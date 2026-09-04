/// Toolkit 1: Reconnaissance — DNS record harvesting, crt.sh
/// subdomain enumeration, historical IP lookup, and zone-transfer check.
use std::net::IpAddr;
use std::time::Duration;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use crate::models::{DnsRecord, HistoricalIp, Subdomain, OriginCandidate};
use crate::stealth::{jitter, random_ua};

/// Reconnaissance toolkit that collects DNS records, subdomains,
/// historical IPs, and zone-transfer results for a target domain.
pub struct ReconToolkit {
    pub domain: String,
    pub jitter_ms: u64,
    pub client: reqwest::Client,
}

impl ReconToolkit {
    /// Create a new `ReconToolkit` with the given domain and jitter setting.
    pub fn new(domain: &str, jitter_ms: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(random_ua())
            .build()
            .unwrap_or_default();
        Self {
            domain: domain.to_string(),
            jitter_ms,
            client,
        }
    }

    /// Build a Cloudflare-based async DNS resolver with custom timeouts.
    fn resolver() -> TokioAsyncResolver {
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(10);
        opts.attempts = 2;
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts)
    }

    /// Fetch A, AAAA, NS, MX, TXT, and CNAME records for the domain.
    pub async fn dns_records(&self) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        let resolver = Self::resolver();

        // Step: A record lookup
        if let Ok(response) = resolver.ipv4_lookup(&self.domain).await {
            for ip in response.iter() {
                records.push(DnsRecord {
                    record_type: "A".to_string(),
                    value: IpAddr::V4(**ip).to_string(),
                    source: "DNS".to_string(),
                });
            }
        }

        jitter(self.jitter_ms).await;
        // Step: AAAA record lookup
        if let Ok(response) = resolver.ipv6_lookup(&self.domain).await {
            for ip in response.iter() {
                records.push(DnsRecord {
                    record_type: "AAAA".to_string(),
                    value: IpAddr::V6(**ip).to_string(),
                    source: "DNS".to_string(),
                });
            }
        }

        jitter(self.jitter_ms).await;
        // Step: NS record lookup
        if let Ok(response) = resolver.ns_lookup(&self.domain).await {
            for ns in response.iter() {
                records.push(DnsRecord {
                    record_type: "NS".to_string(),
                    value: ns.to_string().trim_end_matches('.').to_string(),
                    source: "DNS".to_string(),
                });
            }
        }

        jitter(self.jitter_ms).await;
        // Step: MX record lookup
        if let Ok(response) = resolver.mx_lookup(&self.domain).await {
            for mx in response.iter() {
                records.push(DnsRecord {
                    record_type: "MX".to_string(),
                    value: format!("{} {}", mx.preference(), mx.exchange().to_string().trim_end_matches('.')),
                    source: "DNS".to_string(),
                });
            }
        }

        jitter(self.jitter_ms).await;
        // Step: TXT record lookup
        if let Ok(response) = resolver.txt_lookup(&self.domain).await {
            for txt_set in response.iter() {
                for txt in txt_set.iter() {
                    records.push(DnsRecord {
                        record_type: "TXT".to_string(),
                        value: String::from_utf8_lossy(txt).to_string(),
                        source: "DNS".to_string(),
                    });
                }
            }
        }

        jitter(self.jitter_ms).await;
        // Step: CNAME record lookup
        if let Ok(response) = resolver.lookup(&self.domain, RecordType::CNAME).await {
            for cname in response.iter() {
                records.push(DnsRecord {
                    record_type: "CNAME".to_string(),
                    value: cname.to_string().trim_end_matches('.').to_string(),
                    source: "DNS".to_string(),
                });
            }
        }

        records
    }

    /// Query crt.sh for subdomains via certificate transparency logs.
    pub async fn crt_subdomains(&self) -> Vec<Subdomain> {
        let url = format!("https://crt.sh/?q=%25.{}&output=json", self.domain);
        jitter(self.jitter_ms).await;

        let response = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let data: Vec<serde_json::Value> = response.json().await.unwrap_or_default();
        let mut seen = std::collections::HashSet::new();
        let mut subs = Vec::new();

        // Loop: Iterate through each CT log entry
        for entry in &data {
            let name = match entry.get("name_value").and_then(|v| v.as_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Loop: Split on newline for multi-domain certificates
            for sub in name.split('\n') {
                let sub = sub.trim().to_string();
                // Check: Belongs to target domain and not yet collected
                if (sub.ends_with(&format!(".{}", self.domain)) || sub == self.domain)
                    && seen.insert(sub.clone())
                {
                    subs.push(Subdomain {
                        name: sub.clone(),
                        ips: Vec::new(),
                        source: "crt.sh".to_string(),
                    });
                }
            }
        }

        subs.sort_by(|a, b| a.name.cmp(&b.name));
        subs
    }

    /// Fetch historical IPs from SecurityTrails (free tier).
    pub async fn historical_ips(&self) -> Vec<HistoricalIp> {
        let mut history = Vec::new();

        // Step: Query SecurityTrails API
        let url = format!("https://api.securitytrails.com/v1/domain/{}?apikey=", self.domain);
        jitter(self.jitter_ms * 2).await;

        let response = self.client.get(&url).send().await;
        if let Ok(resp) = response {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                // Check: current_dns -> a -> values array present
                if let Some(current) = data.get("current_dns").and_then(|d| d.get("a")) {
                    if let Some(values) = current.get("values").and_then(|v| v.as_array()) {
                        // Loop: Extract each IP from the values array
                        for val in values {
                            if let Some(ip) = val.get("ip").and_then(|x| x.as_str()) {
                                if let Ok(parsed) = ip.parse::<IpAddr>() {
                                    history.push(HistoricalIp {
                                        ip: parsed,
                                        date_seen: "current".to_string(),
                                        source: "SecurityTrails".to_string(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        history
    }

    /// Check for DNS zone-transfer (AXFR) vulnerability on all NS.
    pub async fn check_zone_transfer(&self) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        let resolver = Self::resolver();

        jitter(self.jitter_ms).await;
        // Step: Enumerate nameservers
        if let Ok(response) = resolver.ns_lookup(&self.domain).await {
            // Loop: Attempt AXFR against each nameserver
            for ns in response.iter() {
                let ns_host = ns.to_string().trim_end_matches('.').to_string();
                let zone_resolver = TokioAsyncResolver::tokio(
                    ResolverConfig::new(),
                    ResolverOpts::default(),
                );
                let result = zone_resolver.lookup(&self.domain, RecordType::AXFR).await;
                // Check: AXFR succeeded — zone is leaky
                if result.is_ok() {
                    records.push(DnsRecord {
                        record_type: "ZONE-TRANSFER".to_string(),
                        value: format!("VULNERABLE via {}", ns_host),
                        source: "DNS".to_string(),
                    });
                }
            }
        }

        records
    }

    /// Run all recon stages and return collected data.
    pub async fn run(&self) -> (Vec<DnsRecord>, Vec<Subdomain>, Vec<HistoricalIp>, Vec<OriginCandidate>) {
        // Stage: DNS records
        let records = self.dns_records().await;
        // Stage: crt.sh subdomains
        let subdomains = self.crt_subdomains().await;
        // Stage: Historical IPs
        let history = self.historical_ips().await;
        // Stage: Zone-transfer check
        let zone = self.check_zone_transfer().await;

        let mut all_records = records;
        all_records.extend(zone);

        // Step: Convert historical IPs to origin candidates
        let mut origins = Vec::new();
        for ip in &history {
            origins.push(OriginCandidate {
                ip: ip.ip,
                port: 443,
                confidence: 40,
                source: "Historical DNS".to_string(),
                hostname: None,
                server_header: None,
                status_code: None,
                body_hash: None,
                response_time_ms: None,
            });
        }

        (all_records, subdomains, history, origins)
    }
}
