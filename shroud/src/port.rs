/// Shroud — Port Scanner
///
/// Concurrent TCP port scanner targeting common service ports
/// for rapid network node service discovery.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

const COMMON_PORTS: &[u16] = &[
    80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143,
    993, 995, 3306, 5432, 6379, 9090, 27017,
];

/// Scans a set of ports concurrently on the given IP address.
///
/// Returns the list of open ports, sorted numerically.
pub async fn scan_ports_concurrent(ip: IpAddr, ports: Option<&[u16]>, timeout_ms: u64) -> Vec<u16> {
    let ports_to_scan = ports.unwrap_or(COMMON_PORTS);
    let mut handles = Vec::new();

    for &port in ports_to_scan {
        let handle = tokio::spawn(async move {
            let addr = SocketAddr::new(ip, port);
            let dur = Duration::from_millis(timeout_ms);
            match timeout(dur, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Some(port),
                _ => None,
            }
        });
        handles.push(handle);
    }

    let mut open = Vec::new();
    for handle in handles {
        if let Ok(Some(port)) = handle.await {
            open.push(port);
        }
    }
    open.sort();
    open
}
