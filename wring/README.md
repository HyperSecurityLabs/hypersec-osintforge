# WRING — SSL/TLS Security Testing Toolkit

**Version:** 0.1.0  
**Author:** KhaninKali / HyperSecurity Offensive Labs  
**Repository:** [Rust-DDos-FrameworkSRC]

---

## Technical Definition

Wring is an async TLS/SSL assessment toolkit that performs certificate chain analysis, cipher suite interrogation, and certificate extraction for one or multiple targets. Built on `rustls` and `tokio-rustls`, it operates entirely in userspace with no OpenSSL dependency.

### Capabilities

- **TLS handshake & certificate retrieval** — Connects to any TLS-enabled service and retrieves the full certificate chain
- **Certificate parsing & validation** — Parses X.509 certificates, extracts validity, issuer, subject, SANs, and fingerprint (SHA-256)
- **Mass scanning** — Accepts a file of targets (hostname:port) for batch assessment
- **Certificate download** — Saves PEM-encoded certificates to disk for offline analysis
- **Multiple output formats** — Human-readable terminal output + JSON for pipeline ingestion

### Technical Architecture

```
┌─────────────────────────────────────────────┐
│               WRING ENGINE                    │
├─────────────────────────────────────────────┤
│  Socket: tokio::net::TcpStream              │
│  TLS:    tokio-rustls (rustls ClientConfig) │
│  Certs:  x509-parser (RustlsPkiTypes)       │
│  Hash:   SHA-256 certificate fingerprint    │
│  Output: colored terminal + JSON export     │
└─────────────────────────────────────────────┘
```

### Analysis Performed per Target

| Check | Description |
|-------|-------------|
| Certificate validity period | notBefore / notAfter dates |
| Issuer | Certificate Authority who signed it |
| Subject | Common Name (CN) |
| Subject Alternative Names (SANs) | All valid domains for this cert |
| SHA-256 fingerprint | Unique hash for cert identification |
| Certificate chain length | Number of intermediates |
| Self-signed detection | Issuer == Subject |
| Wildcard detection | *.example.com patterns |
| Expiration status | Valid / Expiring / Expired |

---

## Offensive Use Cases

- **Certificate transparency monitoring** — Identify all domains a target organization certifies
- **Subdomain enumeration via SANs** — Extract all SAN entries for a target's cert (passive subdomain discovery)
- **Expired certificate hunting** — Find expired certs → potential domain takeover or stale infrastructure
- **Self-signed certificate detection** — Identify internal services exposing self-signed certs
- **Infrastructure fingerprinting** — Match certificate patterns to identify shared hosting / CDN relationships
- **Mass TLS auditing** — Scan entire IP ranges for TLS-enabled services
- **Certificate pinning assessment** — Identify certs that would break pinning if expired

---

## CLI Usage

```
wring [TARGET] [OPTIONS]

Positional:
  TARGET                        Target domain or IP address

Options:
  -f, --file <FILE>             File with targets (one per line, optionally port: host:port)
  -p, --port <PORT>             Port number [default: 443]
  -j, --json                    JSON output
  -o, --output <FILE>           Save results to JSON file
  -d, --download                Download certificates to ./certs/ as PEM files
```

### Examples

```bash
# Single target scan
wring example.com

# Scan specific port
wring example.com -p 8443

# Batch scan from file
wring -f targets.txt -o results.json

# Scan + download certificates
wring example.com -d

# JSON output piped to jq
wring example.com -j | jq '.[] | {target, issuer, fingerprint}'

# Full batch with JSON export
wring -f targets.txt -j -o scan_results.json

# Multi-port scan (run separately per port)
wring example.com -p 443 -j -o port443.json
wring example.com -p 8443 -j -o port8443.json
```

### Target File Format

```
# targets.txt
example.com
example.com:443
example.org:8443
api.example.com:9090
192.168.1.1:443
```

---

## Targets

| Target Type | Use Case | Notes |
|-------------|----------|-------|
| Web servers (HTTPS) | Certificate validation, expiration | Primary use case |
| API endpoints | TLS assessment, cert pinning check | Common on non-443 ports |
| Mail servers (SMTPS, IMAPS) | Certificate audit | Ports 465, 587, 993 |
| VPN endpoints | TLS fingerprinting | Ports 443, 8443 |
| Cloud load balancers | Mass cert extraction | TLS termination inspection |
| IoT devices | Self-signed cert detection | Often forgotten in audits |
