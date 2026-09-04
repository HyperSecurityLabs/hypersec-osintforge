# REAP v4.0.0

**Author:** KhaninKali · HyperSecurity Offensive Labs  
**Version:** 4.0.0  
**Description:** Web Intelligence Profiler — reap every detail from the web surface  

---

## Technical Definition

REAP is a comprehensive web reconnaissance and intelligence profiling engine. It performs deep HTTP analysis including header auditing, cookie inspection, technology fingerprinting, WAF detection, DNS resolution, form extraction, JavaScript analysis, content classification, endpoint scanning, and social media link discovery. Operates as a single-pass intelligence gatherer with concurrent bulk target processing.

## Capabilities

- **HTTP Profiling**: Status codes, redirect chains, headers, cookies, server banners
- **Security Header Audit**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, CORS, etc.
- **Technology Fingerprinting**: 50+ web technologies (frameworks, CMS, analytics, CDNs)
- **WAF Detection**: Signature-based WAF identification from headers and response patterns
- **DNS Resolution**: A/AAAA record discovery
- **Form Extraction**: Login forms, upload forms, field types, CSRF tokens
- **JavaScript Analysis**: API endpoint hints, SPA route discovery, external script enumeration
- **Content Classification**: Error disclosure detection, login portals, upload functionality
- **Endpoint Scanning**: Common path brute-force for hidden resources
- **Social Discovery**: Facebook, Twitter/X, Instagram, LinkedIn, Telegram, Discord, GitHub links
- **Contact Extraction**: Email addresses and phone numbers
- **Bulk Processing**: File-based target list with concurrent workers

## Offensive Use Cases

- Pre-engagement reconnaissance for penetration testing
- Attack surface mapping for red team operations
- Target technology inventory for exploit selection
- Phishing campaign infrastructure identification
- Security misconfiguration discovery (missing headers, exposed endpoints, info disclosure)
- Social media presence mapping for OSINT correlation
- WAF identification for bypass strategy development

## Usage

```
reap <target>
reap -f <file> [options]
```

### Single Target Intelligence
```
reap example.com
```

### Bulk Recon with JSON Export
```
reap -f targets.txt -c 50 -j -o results.json
```

### Minimal Output (No Headers/Links)
```
reap example.com --no-headers --no-links
```

## Flags

| Flag | Description |
|------|-------------|
| `-f, --file` | Target file (hosts/IPs, one per line) |
| `-c, --concurrency` | Concurrent workers (default: 10) |
| `-j, --json` | JSON output to stdout |
| `-o, --output` | Save results to JSON file |
| `--no-headers` | Skip HTTP header output |
| `--no-links` | Skip link enumeration output |

## Targets

- Any web-facing host or application
- Bulk target lists from subdomain enumeration or Shodan exports
- Phishing target infrastructure assessment
- Enterprise web application portfolios
- E-commerce and banking platforms for security posture evaluation
