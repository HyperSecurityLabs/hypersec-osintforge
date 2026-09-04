# SPOOF — Mail Forger: SPF/DMARC/DKIM Audit, SMTP Relay Test & Spoofability Check

**Version:** 0.1.0  
**Author:** khaninkali · HyperSecurity Offensive Labs  
**Description:** Automated email security posture assessment tool that audits SPF, DMARC, DKIM records, tests SMTP open relay, and determines domain spoofability in one pass.

---

## Technical Definition

Spoof performs a full email security audit against a target domain: MX record resolution with IP extraction, SPF record parsing with include/all-mechanism classification, DMARC policy extraction with p/pct/rua parsing, DKIM selector probing across 14 common selectors (default, google, selector1, selector2, dkim, mail, zoho, mx, spf, protonmail, etc.), live SMTP relay testing to determine if MX servers accept mail from arbitrary senders, and a spoofability analysis engine that grades the domain as CRITICAL, HIGH, MEDIUM, LOW, or SAFE based on the email security control state.

**Key capabilities:**
- Parallel MX/SPF/DMARC/DKIM DNS lookup
- SMTP banner grabbing and open relay verification via EHLO/MAIL FROM/RCPT TO sequence
- DKIM selector brute-force (14 selectors)
- Spoofability grading with detailed reasoning
- JSON output with full SpoofResult schema

---

## Offensive Use Cases

- **Phishing campaign pre-check:** Verify target domain is spoofable before sending  
- **Social engineering enabler:** Determine which email security controls to bypass  
- **SMTP relay discovery:** Find open relays for anonymous email injection  
- **Internal red team:** Assess your own organisation's email security posture  
- **Bug bounty / VDP:** Report misconfigured SPF/DMARC with clear exploit PoC  
- **Business email compromise (BEC) prep:** Identify domains where impersonation is trivial

---

## CLI Usage

```
spoof <domain> [OPTIONS]
```

### Positional

| Argument | Description |
|----------|-------------|
| `target` | Domain to audit (e.g. `example.com`) |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-j`, `--json` | `false` | JSON output (no banner, machine-readable) |
| `-o`, `--output` | None | Save results to file |
| `--no-mx` | `false` | Skip MX lookup |
| `--no-dkim` | `false` | Skip DKIM lookup |
| `--relay` | `false` | Test SMTP relay on port 25 |
| `--relay-from` | `test@spoof-check.local` | From address for relay test |
| `--relay-to` | `postmaster@example.com` | To address for relay test |

### Examples

```bash
# Quick spoofability check
spoof example.com

# Full audit with SMTP relay test
spoof target.com --relay

# Machine-readable output for reporting pipeline
spoof bank.example --json -o spoof-report.json

# Targeted DKIM and relay test only
spoof shop.example --no-dkim --json

# Relay test with custom addresses
spoof mail.target.com --relay --relay-from "attacker@evil.com" --relay-to "ceo@target.com"
```

---

## Targets

- **Websites:** Any domain that sends or receives email  
- **Enterprise:** Corporate domains, financial institutions, SaaS providers  
- **Networks:** MX servers and SMTP gateways  
- **Applications:** Transactional email senders, marketing platforms  
- **Cloud tenants:** G-Suite, Office 365, custom mail server deployments
