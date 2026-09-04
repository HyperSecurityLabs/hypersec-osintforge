<div align="center">

> ⚡HYPERSEC-OSINTFORGE

 `Rust × OSINT × Reconnaissance × Threat Intelligence`

[![Rust](https://img.shields.io/badge/Rust-141414?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![OSINT](https://img.shields.io/badge/OSINT-8E4968?style=for-the-badge)](https://github.com/HyperSecurityLabs/hypersec-osintforge)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-342844?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Linux x86_64](https://img.shields.io/badge/Linux_x86__64-596B4A?style=for-the-badge&logo=linux&logoColor=white)](https://kernel.org/)
[![Production Ready](https://img.shields.io/badge/Production_Ready-D8784A?style=for-the-badge)](#)
[![GPL--3.0](https://img.shields.io/badge/GPL--3.0-B85C83?style=for-the-badge)](LICENSE)

[![Repository](https://img.shields.io/badge/GitHub-0B1426?style=for-the-badge&logo=github&logoColor=white)](https://github.com/HyperSecurityLabs/hypersec-osintforge)
[![Releases](https://img.shields.io/badge/Releases-E2C477?style=for-the-badge&logo=github&logoColor=141414)](https://github.com/HyperSecurityLabs/hypersec-osintforge/releases)
[![Issues](https://img.shields.io/badge/Issues-278A83?style=for-the-badge&logo=github&logoColor=white)](https://github.com/HyperSecurityLabs/hypersec-osintforge/issues)
[![Stars](https://img.shields.io/github/stars/HyperSecurityLabs/hypersec-osintforge?style=for-the-badge&color=B98A38)](https://github.com/HyperSecurityLabs/hypersec-osintforge/stargazers)
[![Website](https://img.shields.io/badge/HSOL_Website-E8A0B8?style=for-the-badge&logo=googlechrome&logoColor=141414)](https://hypersecurityoffseclabs.great-site.net)

<br>


</div>



---



## 🛰️ About

**hypersec-osintforge** is a **production-ready, Rust-powered OSINT collection** developed by **HyperSecurity Offensive Labs (HSOL)** for authorized reconnaissance, threat intelligence, digital investigations, and security research.

> **12+ specialized tools. One intelligence forge.**

---

> 🔎Specialized OSINT



- **Username Search** — public username and handle discovery
- **WHOIS Investigation** — domain registration intelligence
- **RDAP Investigation** — structured registration-data research
- **URL Investigation** — URL-focused intelligence
- **Node Discovery** — related public node discovery
- **Reconnaissance** — authorized intelligence-gathering workflows
- **Additional Tools** — more specialized OSINT utilities

> Tool-specific documentation and capabilities are maintained with the individual tools.

---

## 🎯 MITRE ATT&CK

OSINTForge supports workflows that can map to the **Reconnaissance tactic — TA0043**, depending on the tool and research workflow.

| Technique | ID |
|---|---|
| Active Scanning | `T1595` |
| Gather Victim Network Information | `T1590` |
| Gather Victim Identity Information | `T1589` |
| Gather Victim Organization Information | `T1591` |
| Gather Victim Host Information | `T1592` |
| Gather Victim Location Information | `T1614` |
| Search Open Websites/Domains | `T1593` |
| Search Open Technical Databases | `T1596` |
| Search Open Websites for Technical Information | `T1593` |

**MITRE ATT&CK:**  

https://attack.mitre.org/tactics/TA0043/

> ATT&CK mappings describe relevant intelligence/reconnaissance workflows and do not mean every tool implements every technique.

---


## 🐧 Supported Platform

**Linux only.**
Primary target:

```text
Kali Linux
Linux x86_64
```

The release is intended for Kali Linux and compatible **64-bit Linux environments**. Windows and macOS are not supported by this release.

### 📦 Binary Release

```text
HyperSecurity-OSINT-Suite-Linux-x86_64.zip
```
---



> 🚀 Build From Source

```bash
git clone https://github.com/HyperSecurityLabs/hypersec-osintforge.git
cd hypersec-osintforge
cargo build --release
```

Release binaries are generated under:

```text
target/release/
```
---

> 📊 Intelligence Workflow

```text
DISCOVER
   ↓
COLLECT
   ↓
CORRELATE
   ↓
VALIDATE
   ↓
ANALYZE
   ↓
REPORT
```
Reports are designed to be **modifiable**. Researchers can customize, annotate, restructure, or extend generated report output to match their investigation, documentation, or operational requirements.

---
> 👥 Development & Research
>⚡HyperSecurity Offensive Labs — HSOL
The primary organization behind OSINTForge, focused on:

`OSINT` · `Reconnaissance` · `Threat Intelligence` · `Offensive Security Research` · `Security Tooling`

🌐 https://hypersecurityoffseclabs.great-site.net

### 🛠️ Oxide DevOps & Security Research Team

Supporting the wider HyperSecurity engineering ecosystem through:

`Rust Engineering` · `DevOps` · `Security Tooling` · `Research Infrastructure` · `Testing`

---

## ⚠️ Security & Responsible Use

> **OSINTForge is a research and intelligence toolset — not an attack framework.**
Use it only against information, systems, domains, or infrastructure that you **own or are explicitly authorized to investigate**.

### 🚫 Do not use it to:

- Attack other people's infrastructure
- Conduct unauthorized scanning or intrusion
- Harass, stalk, or doxx individuals
- Circumvent access controls
- Abuse credentials or priate information
- Conduct unlawful surveillance
- Turn intelligence gathering into unauthorized attacks

> Communities, projects, or actors that may be associated with malicious activity—including **Shadow Legion or similar groups**—do not provide authorization to target their infrastructure. Analyze publicly available information responsibly and follow applicable laws.

> **Reconnaissance is not permission to attack. Authorization comes first.**

---

## 📋 Reporting & Research

If you discover an issue, inaccurate result, false positive, or improvement opportunity:

1. Validate the finding.
2. Preserve relevant evidence.
3. Document the research context.
4. Report it through the repository issue tracker.
5. Modify or annotate generated reports as required for your legitimate workflow.

**Issues:**  

https://github.com/HyperSecurityLabs/hypersec-osintforge/issues

---

## 🔗 Official Links

[![GitHub](https://img.shields.io/badge/Repository-111C2B?style=for-the-badge&logo=github&logoColor=white)](https://github.com/HyperSecurityLabs/hypersec-osintforge)
[![Releases](https://img.shields.io/badge/Releases-B98A38?style=for-the-badge&logo=github&logoColor=white)](https://github.com/HyperSecurityLabs/hypersec-osintforge/releases)
[![Issues](https://img.shields.io/badge/Issues-278A83?style=for-the-badge&logo=github&logoColor=white)](https://github.com/HyperSecurityLabs/hypersec-osintforge/issues)
[![Website](https://img.shields.io/badge/HyperSecurity_Offensive_Labs-8E4968?style=for-the-badge&logo=googlechrome&logoColor=white)](https://hypersecurityoffseclabs.great-site.net)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-264653?style=for-the-badge)](https://attack.mitre.org/)

---

## 📜 License

Licensed under the **GNU General Public License v3.0**.
See [`LICENSE`](LICENSE).

---

<div align="center">

> HYPERSECURITY OFFENSIVE LABS

**Research deeply. Analyze intelligently. Publish responsibly.**

`Rust × OSINT × Recon × Intelligence`

## ⭐ Support the Project

If OSINTForge is useful to your research:

- ⭐ Star the repository
- 🐛 Report reproducible issues
- 🔬 Share legitimate research findings
- 🛠️ Contribute improvements
- 📖 Improve documentation

[![Star hypersec-osintforge](https://img.shields.io/badge/⭐_Star_the_Repository-D5A64A?style=for-the-badge)](https://github.com/HyperSecurityLabs/hypersec-osintforge)

---

<div align="center">

### ⚡ HYPERSECURITY OFFENSIVE LABS
**Research deeply. Analyze intelligently. Publish responsibly.**

**Rust × OSINT × Reconnaissance × Threat Intelligence**

<br>

[![GitHub](https://img.shields.io/badge/GitHub-9E3045?style=for-the-badge&logo=github&logoColor=FFFFFF)](https://github.com/HyperSecurityLabs/hypersec-osintforge) [![Website](https://img.shields.io/badge/Website-668C63?style=for-the-badge&logo=googlechrome&logoColor=FFFFFF)](https://hypersecurityoffseclabs.great-site.net) [![Releases](https://img.shields.io/badge/Releases-D5A64A?style=for-the-badge&logo=github&logoColor=141414)](https://github.com/HyperSecurityLabs/hypersec-osintforge/releases) [![Issues](https://img.shields.io/badge/Issues-B85C83?style=for-the-badge&logo=github&logoColor=FFFFFF)](https://github.com/HyperSecurityLabs/hypersec-osintforge/issues) [![Telegram](https://img.shields.io/badge/Telegram-26A5E4?style=for-the-badge&logo=telegram&logoColor=FFFFFF)](https://t.me/hypersecurity_offsec)

</div>


## 🌸 Visual Identity our Secreat 

The project uses a cybernetic palette inspired by deep indigo, Japanese blue, sakura, plum, pine, and cyber-teal tones.

Selected project colors:

[![Midnight Blue](https://img.shields.io/badge/Midnight_Blue-0B1426?style=for-the-badge)](#)
[![Japanese Indigo](https://img.shields.io/badge/Japanese_Indigo-17324D?style=for-the-badge)](#)
[![Deep Indigo](https://img.shields.io/badge/Deep_Indigo-243B55?style=for-the-badge)](#)
[![Steel Blue](https://img.shields.io/badge/Steel_Blue-315B78?style=for-the-badge)](#)
[![Sakura Pink](https://img.shields.io/badge/Sakura_Pink-E8A0B8?style=for-the-badge)](#)
[![Rose Plum](https://img.shields.io/badge/Rose_Plum-8E4968?style=for-the-badge)](#)
[![Pine Green](https://img.shields.io/badge/Pine_Green-2F5D50?style=for-the-badge)](#)
[![Cyber Teal](https://img.shields.io/badge/Cyber_Teal-278A83?style=for-the-badge)](#)
[![Electric Purple](https://img.shields.io/badge/Electric_Purple-8B6FC8?style=for-the-badge)](#)

---
