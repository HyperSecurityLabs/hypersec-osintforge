# EXFIL — Data Bleed Scanner

**Version:** 0.1.0  
**Author:** KhaninKali / HyperSecurity Offensive Labs

## Technical Definition

EXFIL is a multi-engine web application security scanner that checks for **CORS misconfigurations**, **Insecure Direct Object References (IDOR)**, **publicly accessible S3 buckets**, and **hidden parameter disclosures**. Each module operates independently and can be toggled via flags. Results are color-coded by severity (CRITICAL, HIGH, MEDIUM, INFO) and support JSON output for programmatic consumption.

## Offensive Use Cases

- **Bug Bounty Recon:** Rapidly scan targets for common data exposure vulnerabilities in a single command
- **Red Team Recon Phase:** Identify CORS trust violations, IDOR endpoints, and exposed S3 buckets before deeper exploitation
- **Third-Party Asset Audit:** Check for misconfigured S3 buckets leaking customer data (e.g., `--bucket target-company`)
- **Data Exfiltration Prep:** IDOR and parameter fuzzing find endpoints that return sensitive data without proper auth
- **Supply Chain Risk:** CORS scans on API endpoints reveal which origins are trusted — find XSS-able partners

## CLI Usage

```
exfil [OPTIONS] <target-url>

  <target-url>             Target URL or domain to scan

  -j, --json               JSON output (machine-readable, no banner)
  -o, --output <file>      Save results to file

  --no-cors                Skip CORS scanning
  --no-idor                Skip IDOR checking
  --no-s3                  Skip S3 bucket checks
  --no-fuzz                Skip parameter fuzzing

  --bucket <name>          S3 bucket name to check (e.g., my-bucket)
  --id <value>             Custom ID for baseline IDOR comparison
```

### Examples

```
# Full scan of target
exfil https://api.target.com/users/123

# Focused S3 bucket audit
exfil --bucket internal-backups-prod

# JSON output for pipeline ingestion
exfil https://admin.corp.com/api/users/1 -j
```

## Targets

- **Websites:** CORS tests reveal cross-origin trust boundaries; IDOR finds data access bugs; fuzzing discovers hidden parameters
- **Networks:** S3 bucket checks are DNS-based; scan buckets from anywhere without direct network access
- **Applications:** API endpoints, admin panels, user profiles, file download handlers, S3-hosted static assets
