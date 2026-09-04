# UNEARTH — Origin IP Discovery Framework

**Version:** 0.1.0  
**Author:** KhaninKali / HyperSecurity Offensive Labs  
**Repository:** [Rust-DDos-FrameworkSRC]

---

## Technical Definition

Unearth is a 4-toolkit reconnaissance suite designed to defeat reverse proxies (Cloudflare, Akamai, CloudFront, Fastly, Arbor) by discovering the real origin IP of a target web property. It operates in four sequential phases:

1. **Reconnaissance** – DNS record enumeration, subdomain discovery via crt.sh certificate transparency logs, historical IP lookup, MX/NS/SPF record analysis
2. **Scanner** – CIDR-range port scanning of discovered origin ranges, HTTP response fingerprinting, confidence scoring
3. **Tracer** – MX/NS mail exchanger and nameserver origin tracing, PTR record resolution
4. **Matcher** – Body hash comparison & Server header matching against the direct-connect origin to confirm true origin IPs

### Capabilities

- Bypasses CDN reverse proxies (Cloudflare, Akamai, Fastly, CloudFront, Arbor, Incapsula)
- SHA-256 body fingerprinting for origin matching
- Historical IP lookups across multiple passive databases
- CIDR range expansion from discrete IP candidates
- Confidence scoring (0–100%) for each origin candidate
- JSON output for pipeline integration
- SOCKS5 proxy support for operational security
- Jitter-based rate limiting to avoid WAF triggers

---

## Offensive Use Cases

- **CDN bypass** — Identify the real server behind Cloudflare/Akamai for direct-target DDoS or exploitation
- **Infrastructure mapping** — Map all IP origins (web servers, mail exchangers, nameservers) for a given domain
- **Watering hole recon** — Discover all subdomains and their associated IPs before engagement
- **Phishing infrastructure profiling** — Identify shared hosting origins and adjacent targets
- **Red team external recon** — Full passive→active discovery without triggering alerts on the primary domain

---

## CLI Usage

```
unearth -u https://target.com

Toolkit flags:
  -u, --target <URL>         Target domain or URL
  -j, --jitter <MS>          Jitter between requests (default: 100)
  -t, --threads <NUM>        Scanner threads (default: 4)
  -o, --output <FILE>        JSON output file
  -p, --proxy <PROXY>        SOCKS5 proxy (e.g. socks5://127.0.0.1:9050)
      --port-timeout <MS>    Port scan timeout (default: 3000)
      --json                 Output results as JSON to stdout
      --skip-recon           Skip Toolkit 1 (DNS recon)
      --skip-scanner         Skip Toolkit 2 (CIDR scanner)
      --skip-tracer          Skip Toolkit 3 (origin tracer)
      --skip-matcher         Skip Toolkit 4 (fingerprint matcher)
```

### Examples

```bash
# Full 4-toolkit discovery
unearth -u https://example.com -o results.json

# Quick recon + matcher only (skip scanner + tracer)
unearth -u https://example.com --skip-scanner --skip-tracer

# Tor-proxied recon
unearth -u https://example.com -p socks5://127.0.0.1:9050

# High-stealth with jitter
unearth -u https://example.com -j 500 --skip-scanner --skip-tracer

# JSON pipeline output
unearth -u https://target.com --json | jq '.all_origins[] | select(.confidence >= 80)'
```

---

## Targets

| Target Type | Applicable Modules | Notes |
|-------------|-------------------|-------|
| Websites (behind CDN) | Recon, Matcher | Primary use case — origin bypass |
| Corporate networks | Scanner, Tracer | MX/NS origin mapping |
| Cloud-hosted apps | All 4 toolkits | AWS/GCP/Azure origin discovery |
| Mail servers | Tracer | PTR + MX origin extraction |
| API endpoints | Recon, Matcher | Subdomain discovery → API origin |
