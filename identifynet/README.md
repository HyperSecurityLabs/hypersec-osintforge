# IdentifyNet

**Version:** 0.1.0  
**Author:** khaninkali · HyperSecurity Offensive Labs  
**Description:** *IP Intelligence & Geolocation Profiler*

---

## Technical Definition

IdentifyNet is an IP intelligence and geolocation engine that resolves a target (IP or domain) into a comprehensive profile: geographic location via MaxMind GeoLite2, ASN ownership, DNS records (PTR/MX/NS/TXT), WHOIS registration data, and open port detection across 23 common services.

**Capabilities:**
- GeoIP lookup (city, state, country, postal code, coordinates, timezone)
- ASN number and organization identification
- DNS resolution: PTR reverse lookup, MX mail servers, NS name servers, TXT records
- WHOIS parsing (netrange, orgname, tech/abuse contacts)
- Port scanning (23 top services: FTP, SSH, SMTP, HTTP, HTTPS, MySQL, Redis, MongoDB, etc.)
- Public IP detection
- JSON output for programmatic consumption
- Automatic MaxMind database download with license key
- Concurrent DNS + WHOIS + port scan via async tokio tasks

---

## Offensive Use Cases

| Use Case | Description |
|---|---|
| **Reconnaissance Phase** | Full target profile from a single command — geo, ASN, DNS, WHOIS, ports |
| **Infrastructure Mapping** | Identify hosting provider, netblock owner, and colocation facility |
| **Phishing Prep** | Abuse contact email extraction for social engineering pretexts |
| **Pivot Hunting** | Open port discovery for lateral movement points |
| **CDN Origin Discovery** | ASN/organization cross-reference to find origin netblocks behind CDNs |
| **Target Prioritization** | Score targets by geography, ISP, and exposed services |

---

## CLI Usage

```
identifynet [OPTIONS] <TARGET>
identifynet -m
```

### Single Target Scan

```
identifynet example.com
identifynet 192.168.1.1
```

### JSON Output & File Save

```
identifynet example.com -j -o report.json
```

### Full Recon (No Port Scan, No WHOIS)

```
identifynet example.com -p -w
```

### My Public IP

```
identifynet -m
```

### With MaxMind DB Download

```
identifynet example.com --maxmind-key YOUR_LICENSE_KEY
identifynet example.com --maxmind-key YOUR_KEY -o profile.json -j
```

### Options Reference

| Flag | Description |
|---|---|
| `<TARGET>` | IP address or domain name |
| `-j, --json` | JSON output |
| `-o, --output <PATH>` | Save results to file |
| `-p, --no-portscan` | Skip port scan |
| `-w, --no-whois` | Skip WHOIS lookup |
| `--db-path <PATH>` | Custom GeoIP database path |
| `-m, --my-ip` | Lookup your own public IP |
| `--maxmind-key <KEY>` | MaxMind license key for DB download |

---

## Port Scan Targets

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 993 | IMAPS |
| 995 | POP3S |
| 1433 | MSSQL |
| 1521 | Oracle DB |
| 2049 | NFS |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 8080 | HTTP-Alt |
| 8443 | HTTPS-Alt |
| 9090 | HTTP-Alt2 |
| 27017 | MongoDB |

---

## Targets

- **IP addresses** for geolocation, ASN, WHOIS, and port scanning
- **Domains** for DNS enumeration (MX, NS, TXT, PTR) plus resolved IP intelligence
- **Your own public IP** for verifying VPN/proxy leak status
- **Infrastructure** for recon phase of penetration tests and red team operations
