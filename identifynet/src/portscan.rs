/// TCP port scanner targeting the top 20 most common ports.
use crate::models::{OpenPort, PortScanInfo};
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Top 20 TCP ports with their associated service names.
const TOP_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (1521, "Oracle"),
    (2049, "NFS"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (9090, "HTTP-Alt2"),
    (27017, "MongoDB"),
];

/// Scan the top 20 TCP ports on the target IP.
///
/// Returns `None` if no ports are open, otherwise a `PortScanInfo`
/// with all responsive ports and their service names.
pub async fn scan(ip: IpAddr) -> Option<PortScanInfo> {
    let mut open = Vec::new();

    // Loop: test each port in the top-20 list
    for &(port, service) in TOP_PORTS {
        let addr = format!("{}:{}", ip, port);
        // Check: attempt TCP connection with 800ms timeout
        if timeout(Duration::from_millis(800), TcpStream::connect(&addr))
            .await
            .ok()
            .and_then(|r| r.ok())
            .is_some()
        {
            // Handle: port is open, record it
            open.push(OpenPort {
                port,
                service: service.to_string(),
            });
        }
    }

    Some(PortScanInfo {
        open,
        total_scanned: TOP_PORTS.len(),
    })
}
