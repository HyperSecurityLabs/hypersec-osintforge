# SNIFF — Subdomain Hunter: Passive Recon, DNS Brute-Force & Takeover Detection

**Version:** 0.1.0  
**Author:** khaninkali · HyperSecurity Offensive Labs  
**Description:** Multi-source subdomain enumeration engine that aggregates findings from crt.sh, AlienVault OTX, DNS brute-force, wildcard detection, zone transfer checks, HTTP probing with title extraction, and automated subdomain takeover detection.

---

## Technical Definition

Sniff performs parallel subdomain discovery across three passive sources (crt.sh certificate transparency, AlienVault OTX pulse feed, DNS brute-force via built-in 130-entry wordlist), resolves discovered subdomains, checks for wildcard DNS poisoning, probes each live subdomain over HTTP for status code + HTML title extraction, runs CNAME-based takeover fingerprinting against 11 cloud services (AWS S3, Azure, GitHub Pages, Heroku, Netlify, Shopify, Bitbucket, WordPress, Squarespace, Tumblr, Surge), and tests for DNS zone transfer vulnerabilities.

**Key capabilities:**
- Multi-source subdomain aggregation with deduplication
- Wildcard DNS detection to filter false positives
- DNS brute-force with configurable wordlist and thread count
- Zone transfer (AXFR) testing against discovered nameservers
- HTTP probing with redirect following and HTML title extraction
- Subdomain takeover fingerprinting via CNAME analysis
- JSON output with full SniffResult schema

---

## Offensive Use Cases

- **External attack surface discovery:** Find every subdomain before the blue team knows they exist  
- **Takeover chain automation:** Identify dangling CNAMEs pointing to deleted cloud services  
- **Bug bounty recon:** Passive-only mode (`-b`) for undetected scope expansion  
- **Red team initial access:** Discover forgotten dev/staging environments with weak security  
- **Cloud asset inventory:** Map S3 buckets, CloudFront, and Heroku apps via CNAME fingerprints

---

## CLI Usage

```
sniff <domain> [OPTIONS]
```

### Positional

| Argument | Description |
|----------|-------------|
| `target` | Domain to enumerate (e.g. `example.com`) |

### Options

| Flag | Description |
|------|-------------|
| `-f`, `--wordlist` | Custom wordlist file for DNS brute-force |
| `-j`, `--json` | JSON output |
| `-o`, `--output` | Save results to file |
| `-b`, `--no-bruteforce` | Skip DNS brute-force (passive only) |
| `-z`, `--zone-transfer` | Test for DNS zone transfer |
| `-t`, `--threads` | Brute-force threads (default: 10) |
| `-p`, `--no-probe` | Skip HTTP probing |
| `-w`, `--no-wildcard` | Skip wildcard DNS detection |
| `--no-otx` | Skip AlienVault OTX lookup |

### Examples

```bash
# Quick passive-only scan
sniff example.com -b -p

# Full recon with all sources + HTTP probing
sniff target.com -t 20

# Zone transfer + takeover check, JSON output
sniff corp.com -z --json -o results.json

# Stealth passive mode (no probes, no brute-force)
sniff internal.target.com -b -p -w --no-otx

# Large engagement with custom wordlist
sniff mega-corp.io -f ~/wordlists/subdomains.txt -t 50 -o subs.json
```

---

## Targets

- **Websites:** Full subdomain enumeration for scope mapping  
- **Cloud deployments:** Discover S3 buckets, cloud apps, and CDN endpoints  
- **Enterprise:** Find dev, staging, CI/CD, and monitoring subdomains  
- **Bug bounty:** Passive enumeration without triggering alerts  
- **Red team ops:** Initial recon phase for domain-based targets
