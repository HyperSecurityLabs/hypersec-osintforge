# STALK — Identity Mapper

**Version:** 0.1.0  
**Author:** KhaninKali / HyperSecurity Offensive Labs  
**Description:** Cross-platform username correlation, GitHub OSINT, breach intelligence, and Google dork generation engine.

## Technical Definition

STALK is a Rust-powered OSINT framework that accepts a username or email and executes four parallel intelligence-gathering modules:

| Module | Scope | Method |
|--------|-------|--------|
| **Username Enumeration** | 77 platforms (social, dev, forum, streaming) | HTTP GET probe on profile URLs, 404-based presence detection |
| **GitHub Recon** | Public profile + repos + metadata | GitHub REST API (`/users/{user}`, `/users/{user}/repos`) |
| **Breach Intelligence** | HIBP credential exposure check | Have I Been Pwned API v3 / k-anonymity password range query |
| **Google Dork Generator** | 15+ targeted search queries | Template-based dork construction for username/domain |

## Offensive Use Cases

- **Initial Recon Phase** — Map a target's digital footprint before engagement. Identify every platform they touch.
- **Credential Triage** — Check if a known email appears in breaches; test passwords without revealing them (k-anonymity).
- **Social Media Mapping** — Correlate usernames across platforms to build a unified identity graph.
- **Target Enrichment** — Feed discovered GitHub repos, emails, and bios into follow-on phishing or exploitation workflows.
- **OSINT Baseline** — Establish a "stalking dossier" on a target for social engineering pretext development.

## CLI Usage

```bash
# Basic username scan
stalk johndoe

# Email breach check with platform scan
stalk jdoe@example.com -t email

# Full scan with JSON output saved to file
stalk johndoe -j -o report.json

# Skip GitHub to speed up (77-site username scan only)
stalk johndoe --no-github

# Password check only (k-anonymity, no plaintext sent)
stalk --password-check "P@ssw0rd123!"

# Increase thread count for faster enumeration
stalk johndoe -T 20

# Email-targeted dorks + breach check
stalk admin@targetcorp.com -t email --no-username
```

### Flags Reference

| Flag | Description |
|------|-------------|
| `<target>` | Username or email to investigate |
| `-j, --json` | Machine-readable JSON output |
| `-o, --output FILE` | Save result to file |
| `-t, --target-type` | `username` (default) or `email` |
| `--no-username` | Skip 77-site platform scan |
| `--no-github` | Skip GitHub API lookup |
| `--no-breach` | Skip HIBP breach check |
| `--no-dorks` | Skip dork generation |
| `--password-check PW` | Check password pwnage count only |
| `-T, --threads N` | Concurrent request count (default 10) |

## Targets

- **Websites** — 77 platforms including GitHub, Reddit, Instagram, LinkedIn, Twitter/X, YouTube, Telegram, Steam, HackerOne, Bugcrowd, etc.
- **Email Domains** — Any email address; breach intelligence from HIBP (1B+ records).
- **Applications** — Dev platforms (NPM, PyPI, Crates.io, DockerHub), forums, freelance sites.
- **Code Repositories** — GitHub profile + repo metadata (stars, forks, languages, description).

## Dependencies

- Rust tokio async runtime
- reqwest HTTP client
- HIBP API v3 (breachedaccount endpoint)
- Pwned Passwords API (k-anonymity SHA-1 range query)
- GitHub public REST API (no token required — rate limited)
