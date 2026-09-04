/// Toolkit 2: Scanner — IP-range TCP port scanning and origin probing.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use sha2::{Sha256, Digest};
use crate::models::{OriginCandidate, ScanTarget};
use crate::stealth::random_ua;

/// Scanner toolkit that probes CIDR ranges for open ports and HTTP
/// responses with a Host header set to the target domain.
pub struct ScannerToolkit {
    pub domain: String,
    pub target_cidrs: Vec<String>,
    pub port_timeout: u64,
}

impl ScannerToolkit {
    /// Create a new `ScannerToolkit` for the given domain and CIDRs.
    pub fn new(domain: &str, cidrs: Vec<String>, port_timeout: u64, _concurrency: usize) -> Self {
        Self {
            domain: domain.to_string(),
            target_cidrs: cidrs,
            port_timeout,
        }
    }

    /// Return the default set of ports to scan.
    fn common_ports() -> Vec<u16> {
        vec![80, 443, 8080, 8443, 3000, 5000, 9000, 9090]
    }

    /// TCP-connect scan of a single IP against a port list.
    pub async fn scan_single_ip(ip: IpAddr, ports: &[u16], timeout_ms: u64) -> Vec<u16> {
        let mut open = Vec::new();
        // Loop: Test each port with a TCP timeout
        for &port in ports {
            let addr = SocketAddr::new(ip, port);
            let dur = Duration::from_millis(timeout_ms);
            if let Ok(Ok(_)) = timeout(dur, TcpStream::connect(addr)).await {
                open.push(port);
            }
        }
        open
    }

    /// Expand a CIDR notation into a list of individual IP addresses.
    fn ips_from_cidr(cidr: &str) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        if let Some((base, bits)) = cidr.split_once('/') {
            let base_ip: Ipv4Addr = match base.trim().parse() {
                Ok(ip) => ip,
                Err(_) => return ips,
            };
            let prefix: u32 = u32::from(base_ip);
            let bits: u8 = match bits.parse() {
                Ok(b) => b,
                Err(_) => return ips,
            };
            let shift = 32 - bits;
            let network = prefix & (0xFFFFFFFF << shift);
            let count = 1 << shift;
            // Loop: Generate up to 256 addresses from the CIDR
            for i in 0..count.min(256) {
                let ip_int = network | i;
                let octets = ip_int.to_be_bytes();
                ips.push(IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])));
            }
        }
        ips
    }

    /// Probe an IP:port with an HTTP GET, sending the target domain as Host.
    pub async fn probe_ip(ip: IpAddr, port: u16, domain: &str) -> Option<OriginCandidate> {
        // Step: Determine URL scheme from port
        let scheme = if port == 443 || port == 8443 { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, ip, port);
        let host_header = domain;

        // Step: Build client and send request
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent(random_ua())
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .ok()?;

        let start = std::time::Instant::now();
        let response = client
            .get(&url)
            .header("Host", host_header)
            .send()
            .await
            .ok()?;

        // Step: Record response metadata
        let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        let status_code = response.status().as_u16();
        let server = response
            .headers()
            .get("server")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Step: Hash the response body
        let body = response.bytes().await.ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let hash = hex::encode(hasher.finalize());

        let confidence = if status_code == 200 { 70 } else { 40 };

        Some(OriginCandidate {
            ip,
            port,
            confidence,
            source: "Scanner".to_string(),
            hostname: Some(domain.to_string()),
            server_header: server,
            status_code: Some(status_code),
            body_hash: Some(hash),
            response_time_ms: Some(response_time_ms),
        })
    }

    /// Scan all CIDR ranges for open ports and probe them.
    pub async fn scan_range(&self) -> Vec<OriginCandidate> {
        let mut candidates = Vec::new();
        let ports = Self::common_ports();

        // Loop: Iterate through each target CIDR
        for cidr in &self.target_cidrs {
            let ips = Self::ips_from_cidr(cidr);
            // Loop: Scan up to 50 IPs from the range
            for ip in ips.iter().take(50) {
                let open_ports = Self::scan_single_ip(*ip, &ports, self.port_timeout).await;
                // Loop: Probe each open port
                for port in open_ports {
                    if let Some(candidate) = Self::probe_ip(*ip, port, &self.domain).await {
                        candidates.push(candidate);
                    }
                }
            }
        }

        candidates
    }

    /// Run the full scanner toolkit, returning origin candidates and scan targets.
    pub async fn run(&self) -> (Vec<OriginCandidate>, Vec<ScanTarget>) {
        let candidates = self.scan_range().await;

        // Step: Map candidates to scan targets
        let targets: Vec<ScanTarget> = candidates
            .iter()
            .map(|c| ScanTarget {
                ip: c.ip,
                port: c.port,
                service: "HTTP".to_string(),
                banner: c.server_header.clone(),
            })
            .collect();

        (candidates, targets)
    }
}
