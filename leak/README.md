# LEAK

**Version:** 0.1.0  
**Author:** KhaninKali — HyperSecurity Offensive Labs  
**Description:** Secret Scanner — API keys, tokens, credentials, and hardcoded secrets in files and git history

---

## Technical Definition

LEAK is a static analysis secret scanner that uses regex pattern matching to identify hardcoded credentials, API keys, tokens, database connection strings, cryptographic material, and authentication secrets across file systems and git repositories.

### Detection Capabilities

**Critical Severity:**
- AWS Secret Access Keys (`secret_access_key.{0,30}[0-9a-zA-Z/+]{40}`)
- GitHub Personal Access Tokens (`ghp_[0-9a-zA-Z]{36}`)
- GitHub OAuth Tokens (`gho_[0-9a-zA-Z]{36}`)
- GitLab Personal Access Tokens (`glpat-[0-9a-zA-Z\-_]{20,40}`)
- Slack Tokens (`xox[baprs]-[0-9a-zA-Z\-]{20,80}`)
- Discord Bot Tokens (`[MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6}\.[A-Za-z\d\-_]{27,38}`)
- SSH Private Keys (`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)
- PGP Private Key Blocks
- Authorization Bearer tokens

**High Severity:**
- AWS Access Key IDs (`AKIA[0-9A-Z]{16}`)
- Google API Keys (`AIza[0-9A-Za-z\-_]{35}`)
- Google OAuth Client IDs
- Heroku API Keys
- Azure Connection Strings
- Telegram Bot Tokens
- JWT Tokens
- Database URLs (MySQL, PostgreSQL, MongoDB, Redis)
- Authorization Basic headers

**Medium Severity:**
- Generic API Keys
- Generic Passwords
- Generic Secrets/Tokens
- PEM Certificates
- S3 Bucket URLs

**Low Severity (requires `--entropy` flag):**
- SHA256 hashes
- SHA1 hashes
- MD5 hashes

---

## Offensive Use Cases

- **Source Code Recon:** Scan cloned repos, stolen source code, or internal repos for hardcoded credentials
- **Git History Mining:** Extract secrets committed months ago and never rotated
- **Configuration Auditing:** Find credentials in `.env`, configuration files, Dockerfiles, CI/CD pipelines
- **Supply Chain Attacks:** Scan third-party code for embedded backdoor credentials
- **Privilege Escalation:** Find stored passwords in internal application code

---

## CLI Usage

```
leak <TARGET> [OPTIONS]
```

### Single File Scan
```
leak ./config/settings.env
```

### Directory Recursive Scan
```
leak /path/to/project
```

### Scan with Git History
```
leak /path/to/repo --git
```

### JSON Output (Machine Readable)
```
leak ./target --json
```

### Save Results to File
```
leak ./target -o results.json
```

### Include Low-Severity (Entropy-Based) Patterns
```
leak ./target --entropy
```

### Exclude Specific Patterns
```
leak ./target -i "test" -i "vendor"
```

### Full Pipeline
```
leak ./target --git --entropy -o results.json --json
```

### Flags Reference

| Flag | Description | Default |
|------|-------------|---------|
| `target` | File or directory to scan | Required |
| `-j, --json` | JSON output (machine-readable) | false |
| `-o, --output` | Save results to file | None |
| `--git` | Scan git commit history | false |
| `--entropy` | Enable low-severity patterns | false |
| `-i, --ignore` | Additional ignore pattern | None |

---

## Targets

- **Websites:** Extract secrets from web-accessible config files
- **Applications:** Source code repositories, CI/CD pipelines
- **Networks:** Misconfigured S3 buckets, exposed `.git` directories, exposed configuration management tools
