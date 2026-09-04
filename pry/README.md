# PRY v0.2.0

**Author:** KhaninKali · HyperSecurity Offensive Labs  
**Version:** 0.2.0  
**Description:** Precision Reconnaissance Yield — pry open any domain or IP  

---

## Technical Definition

PRY is a multi-source reconnaissance engine combining RDAP, WHOIS, and DNS resolution into a single concurrent lookup tool. It aggregates registrant data, domain metadata, name server information, and DNS records (A/AAAA) from multiple registries simultaneously. Designed for bulk intelligence gathering with configurable concurrency and JSON serialization.

## Capabilities

- **WHOIS Lookup**: Registrant name, organization, email, phone, address, domain status, creation/expiration dates
- **RDAP Lookup**: Registration Data Access Protocol — registrar info, IANA IDs, domain registry IDs
- **DNS Resolution**: A record and AAAA record discovery
- **Raw WHOIS Mode**: Full raw WHOIS output including referral data
- **Bulk Processing**: File-based target list with concurrent workers
- **JSON Export**: Structured output for toolchain integration

## Offensive Use Cases

- Domain ownership attribution for phishing target selection
- Registrar identification for social engineering pretext development
- Name server enumeration for DNS takeover assessment
- Registrant contact harvesting for credential phishing campaigns
- Expiration date analysis for domain squatting opportunities
- Bulk reconnaissance of target infrastructure before engagement

## Usage

```
pry <target>
pry -f <file> [options]
```

### Single Domain Lookup
```
pry example.com
```

### Bulk Reconnaissance with High Concurrency
```
pry -f targets.txt -c 100 -j -o results.json
```

### RDAP-Only Lookup
```
pry --rdap-only example.com
```

### WHOIS-Only with Raw Output
```
pry -r example.com
```

### Combined: RDAP + WHOIS + DNS (Default)
```
pry example.com -j -o intel.json
```

## Flags

| Flag | Description |
|------|-------------|
| `-f, --file` | Target file (one domain/IP per line) |
| `-c, --concurrency` | Concurrent workers (default: 50) |
| `-j, --json` | JSON output to stdout |
| `-o, --output` | Save results to file |
| `--rdap-only` | RDAP lookup only |
| `--whois-only` | WHOIS lookup only |
| `-r, --raw` | Raw WHOIS output mode |

## Targets

- Any domain or IP address
- Bulk target lists from subdomain enumeration tools
- Email domain investigation for phishing campaign targeting
- Competitor infrastructure mapping
- Acquisition target due diligence
