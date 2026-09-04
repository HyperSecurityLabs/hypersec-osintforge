/// SPOOF — SMTP Relay Test
///
/// Connects to an SMTP server on port 25 and attempts to send
/// an email through it to determine if it is an open relay.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use crate::models::RelayResult;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};

/// Tests whether an SMTP server at the given host:port is an open relay.
///
/// Performs EHLO, MAIL FROM, and RCPT TO commands. If RCPT TO
/// returns a 2xx/250 response, the server is considered an open relay.
pub async fn check_relay(host: &str, port: u16, from: &str, to: &str) -> Option<RelayResult> {
    let addr = format!("{}:{}", host, port);
    let stream = match timeout(Duration::from_secs(8), TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Read server banner
    let mut banner = String::new();
    let _ = timeout(Duration::from_secs(3), buf_reader.read_line(&mut banner)).await;

    // EHLO
    let ehlo = "EHLO spoof-check.local\r\n".to_string();
    let _ = writer.write_all(ehlo.as_bytes()).await;
    let _ = writer.flush().await;
    let mut ehlo_resp = String::new();
    let _ = timeout(Duration::from_secs(3), buf_reader.read_line(&mut ehlo_resp)).await;

    // MAIL FROM
    let mail = format!("MAIL FROM:<{}>\r\n", from);
    let _ = writer.write_all(mail.as_bytes()).await;
    let _ = writer.flush().await;
    let mut mail_resp = String::new();
    let _ = timeout(Duration::from_secs(3), buf_reader.read_line(&mut mail_resp)).await;

    // RCPT TO
    let rcpt = format!("RCPT TO:<{}>\r\n", to);
    let _ = writer.write_all(rcpt.as_bytes()).await;
    let _ = writer.flush().await;
    let mut rcpt_resp = String::new();
    let _ = timeout(Duration::from_secs(3), buf_reader.read_line(&mut rcpt_resp)).await;

    // QUIT
    let _ = writer.write_all(b"QUIT\r\n").await;
    let _ = writer.flush().await;

    let open_relay = rcpt_resp.starts_with("250") || rcpt_resp.starts_with("2");

    Some(RelayResult {
        host: format!("{}:{}", host, port),
        banner: banner.trim().to_string(),
        open_relay,
    })
}
