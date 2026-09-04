# SHROUD — Stealth Network Topology Discovery & Forensics Framework

**Version:** 0.2.0  
**Author:** khaninkali · HyperSecurity Offensive Labs  
**Description:** Multi-stage reconnaissance framework that maps target infrastructure from the outside in — DNS resolution chain, certificate transparency subdomain harvesting, HTTP fingerprinting, WAF detection, geolocation, reverse DNS, port scanning, CIDR analysis, and ASN mapping.

---

## Technical Definition

Shroud performs a 5-stage reconnaissance pipeline against a target domain. It resolves A/AAAA/CNAME/NS/MX/TXT records across multiple resolver backends (Cloudflare, Google, Quad9), cross-references Certificate Transparency logs (crt.sh), sends HTTP probes for server banner + WAF fingerprinting, performs per-IP reverse DNS + geolocation + port scanning, and outputs a structured topology graph with CIDR clustering and ASN grouping.

**Key capabilities:**
- Multi-resolver DNS redirection detection (split-horizon DNS)
- CNAME chain tracing
- HTTP WAF fingerprinting (Cloudflare, Akamai, Vercel, Sucuri, CloudFront)
- Certificate Transparency passive subdomain discovery
- IP geolocation via ip-api.com
- Concurrent TCP port scanning (17 common ports)
- Stealth timing with configurable jitter + random user-agent rotation
- Proxy support (SOCKS/HTTP)
- JSON output with full ScanResult schema

---

## Offensive Use Cases

- **Pre-attack surface mapping:** Enumerate every IP, CNAME, and subdomain before engagement  
- **WAF/CDN bypass planning:** Identify origin IPs behind Cloudflare/Akamai/Vercel  
- **Infrastructure layer classification:** Separate CDN, WAF, origin, and DNS into distinct layers  
- **Supply chain mapping:** Discover third-party dependencies via CNAME chains  
- **Geographic targeting:** Locate infrastructure for jurisdiction-aware attacks  
- **Red team network diagrams:** Auto-generate CIDR ranges and ASN groupings for reporting

---

## CLI Usage

```
shroud --target <URL> [OPTIONS]
```

### Required

| Flag | Description |
|------|-------------|
| `-u`, `--target` | Target URL (e.g. `https://example.com`) |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-j`, `--jitter` | `150` | Max jitter ms between requests (stealth) |
| `--json` | `false` | Output full ScanResult as JSON |
| `-o`, `--output` | None | Save JSON output to file |
| `-p`, `--proxy` | None | Proxy URL (SOCKS/HTTP) |
| `--port-scan` | `false` | Enable TCP port scanning |
| `--crt` | `false` | Enable crt.sh passive recon stage |
| `--no-geo` | `false` | Disable geolocation lookups |
| `--port-timeout` | `3000` | Per-port timeout in ms |

### Examples

```bash
# Basic reconnaissance
shroud --target https://example.com

# Full stealth scan with proxy, crt.sh, port scan
shroud --target https://target.com --jitter 300 --proxy socks5://127.0.0.1:9050 --crt --port-scan

# Machine-readable output for tool chaining
shroud --target https://internal-app.corp.com --json --output scan.json --port-scan

# Fast skim (no geo, no crt, no port scan)
shroud --target https://cdn.target.com --no-geo --jitter 10

# Deep infrastructure mapping
shroud --target https://bank.example --crt --port-scan --port-timeout 5000 --jitter 500
```

---

## Targets

- **Websites:** Full application-layer infrastructure mapping  
- **Networks:** Discover perimeter IP ranges and AS boundaries  
- **Applications:** Identify reverse proxy, CDN, and origin architecture  
- **Cloud tenants:** Map S3, CloudFront, and Vercel presence  
- **Enterprise:** Enumerate mail, DNS, and edge infrastructure
