<div align="center">

# ⚡ HYPERSEC-OSINTFORGE

### **Specialized Rust-Powered OSINT Intelligence Suite**

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![OSINT](https://img.shields.io/badge/OSINT-17324D?style=for-the-badge)](https://github.com/HyperSecurityLabs/hypersec-osintforge)
[![Linux](https://img.shields.io/badge/Linux-243B55?style=for-the-badge&logo=linux&logoColor=white)](https://www.kernel.org/)
[![GPL--3.0](https://img.shields.io/badge/License-GPL--3.0-B85C83?style=for-the-badge)](LICENSE)
[![HyperSecurity](https://img.shields.io/badge/HyperSecurity_Offensive_Labs-8E4968?style=for-the-badge)](https://hypersecurityoffseclabs.great-site.net)

<br>

[![GitHub Repository](https://img.shields.io/badge/Repository-141414?style=for-the-badge&logo=github&logoColor=white)](https://github.com/HyperSecurityLabs/hypersec-osintforge)
[![Website](https://img.shields.io/badge/Website-315B78?style=for-the-badge&logo=googlechrome&logoColor=white)](https://hypersecurityoffseclabs.great-site.net)
[![Issues](https://img.shields.io/badge/Issues-278A83?style=for-the-badge&logo=github)](https://github.com/HyperSecurityLabs/hypersec-osintforge/issues)
[![Releases](https://img.shields.io/badge/Releases-668C63?style=for-the-badge&logo=github)](https://github.com/HyperSecurityLabs/hypersec-osintforge/releases)
[![Stars](https://img.shields.io/github/stars/HyperSecurityLabs/hypersec-osintforge?style=for-the-badge&color=D5A64A)](https://github.com/HyperSecurityLabs/hypersec-osintforge/stargazers)
[![Forks](https://img.shields.io/github/forks/HyperSecurityLabs/hypersec-osintforge?style=for-the-badge&color=3E7FA6)](https://github.com/HyperSecurityLabs/hypersec-osintforge/network/members)

<br>

**12+ specialized OSINT utilities • Rust • Reconnaissance • Threat Intelligence • Security Research**

</div>

---

## 🛰️ About

**hypersec-osintforge** is a specialized collection of **Rust-powered OSINT tools** developed by **HyperSecurity Offensive Labs (HSOL)**.

The project is designed around focused intelligence workflows including reconnaissance, public-source discovery, domain and URL investigation, identity-oriented research, network intelligence, and digital investigation.

Rather than being a single oversized utility, OSINTForge brings multiple specialized tools together under one project identity.

> **One forge. Multiple intelligence workflows. Built in Rust.**

---

## 🔗 Quick Links

| Resource | Link |
|---|---|
| ⚡ **GitHub Repository** | [hypersec-osintforge](https://github.com/HyperSecurityLabs/hypersec-osintforge) |
| 🌐 **HyperSecurity Offensive Labs** | [Official Website](https://hypersecurityoffseclabs.great-site.net) |
| 📦 **Releases** | [GitHub Releases](https://github.com/HyperSecurityLabs/hypersec-osintforge/releases) |
| 🐛 **Issues** | [Issue Tracker](https://github.com/HyperSecurityLabs/hypersec-osintforge/issues) |
| ⭐ **Stars** | [Star the Project](https://github.com/HyperSecurityLabs/hypersec-osintforge/stargazers) |
| 🔀 **Forks** | [Project Forks](https://github.com/HyperSecurityLabs/hypersec-osintforge/network/members) |

---

## 🧰 Specialized OSINT Collection

OSINTForge is being released as a multi-tool collection with **12+ specialized utilities**.

Current tool categories include:

| Capability | Purpose |
|---|---|
| 🔎 **Username Searching** | Discover publicly exposed username/handle references |
| 🌐 **WHOIS Investigation** | Domain registration and ownership intelligence |
| 🧬 **RDAP Investigation** | Structured registration-data investigation |
| 🔗 **URL Investigation** | Analyze URLs and related public intelligence |
| 🕸️ **Node Discovery** | Discover relevant public nodes and relationships |
| 🛰️ **Reconnaissance** | Support authorized reconnaissance and intelligence workflows |
| 🗂️ **Public-Source Research** | Collect and correlate information from publicly available sources |
| 🔬 **Digital Investigation** | Assist structured research and evidence-oriented workflows |
| ➕ **Additional Utilities** | More specialized OSINT tools included across the collection |



---

## 🎯 MITRE ATT&CK Alignment

OSINTForge can support workflows associated with the **MITRE ATT&CK Reconnaissance tactic — TA0043**, depending on the tool and intended workflow.

| Technique | ID | Relevance |
|---|---|---|
| Active Scanning | `T1595` | Reconnaissance and discovery workflows |
| Gather Victim Network Information | `T1590` | Network-related intelligence gathering |
| Gather Victim Identity Information | `T1589` | Identity and username-oriented research |
| Search Open Technical Databases | `T1596` | Public technical-data research |

MITRE ATT&CK references:

- [Reconnaissance — TA0043](https://attack.mitre.org/tactics/TA0043/)
- [T1595 — Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1590 — Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)
- [T1589 — Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
- [T1596 — Search Open Technical Databases](https://attack.mitre.org/techniques/T1596/)

> ATT&CK mappings are provided for research and classification purposes and do not imply that every tool implements every technique.

---

## 🦀 Why Rust?

OSINTForge is built around **Rust** to provide a modern foundation for command-line intelligence tooling.

- ⚙️ Native compiled performance
- 🧩 Modular tool architecture
- 🔒 Strong memory-safety model
- 🐧 Linux-friendly deployment
- 📦 Convenient distribution of compiled binaries
- 🛠️ Well suited for independent security utilities

---

## 🐧 Linux Release

The primary binary distribution is designed for **64-bit Linux environments**, including:

```text
Kali Linux
Parrot OS
Debian
Ubuntu
Arch Linux
Other compatible x86_64 Linux distributions
```

### Release Package

```text
HyperSecurity-OSINT-Suite-Linux-x86_64.zip
```

The release archive contains the compiled OSINT utilities and supporting release material.

---

## 🚀 Getting Started

Clone the repository:

```bash
git clone https://github.com/HyperSecurityLabs/hypersec-osintforge.git
cd hypersec-osintforge
```

Build with Cargo:

```bash
cargo build --release
```

Compiled binaries will normally be available under:

```text
target/release/
```

For individual tools, consult the README or documentation inside the corresponding tool directory.

---

## 📁 Project Philosophy

OSINTForge follows a simple principle:

```text
Collect → Correlate → Analyze → Validate → Report
```

The goal is not simply to collect large amounts of information.

The goal is to turn **publicly available information into structured, useful intelligence** while keeping research reproducible and responsible.

---

## 🧠 Research Focus

OSINTForge is intended to support areas such as:

- Threat intelligence
- Security research
- Authorized reconnaissance
- Digital investigations
- Domain intelligence
- Identity and username research
- Network intelligence
- Public-source analysis
- Defensive security workflows
- CTF and controlled laboratory environments

---

## 👥 Development & Research Teams

### ⚡ HyperSecurity Offensive Labs — HSOL

**HyperSecurity Offensive Labs (HSOL)** is the primary development and security-research organization behind the project.

The team focuses on:

- Offensive security research
- Security tooling
- Reconnaissance research
- Threat intelligence
- Vulnerability research
- Adversary-simulation studies
- Defensive security research

🌐 **HSOL:**  
https://hypersecurityoffseclabs.great-site.net

---

### 🛠️ Oxide DevOps & Security Research Team

The **Oxide DevOps & Security Research Team** contributes to the wider HyperSecurity tooling ecosystem, with emphasis on:

- Rust-based security tooling
- Development infrastructure
- Build and release workflows
- Security research
- Tool integration
- Testing and engineering workflows

The team operates alongside the broader HSOL research ecosystem and supports projects such as **Oxide** and related security tooling.

---

## 🔬 Research Standards

OSINTForge is built around responsible intelligence research.

Good research should be:

```text
Public-source
Reproducible
Evidence-based
Authorized
Privacy-aware
Technically validated
```

Avoid treating unverified online information as fact. Correlate sources, validate findings, document evidence, and distinguish observations from assumptions.

---

## ⚠️ Responsible Use

These tools are intended for:

- Authorized security research
- Threat intelligence
- Defensive investigations
- CTFs
- Security laboratories
- Research on information you are legally permitted to investigate

Do **not** use OSINTForge for harassment, stalking, doxxing, unauthorized surveillance, credential abuse, privacy violations, intimidation, or unlawful investigation.

Users are responsible for complying with applicable laws, regulations, platform policies, and organizational authorization requirements.

---

## 📦 Repository Structure

The project is organized as a collection of specialized tools and supporting resources.

```text
hypersec-osintforge/
├── tools/
│   ├── ...
│   └── ...
├── docs/
├── assets/
├── README.md
├── LICENSE
└── ...
```

> The exact directory structure may evolve as additional OSINT utilities are integrated.

---

## 🌸 Visual Identity

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

## 📜 License

This project is distributed under the:

**GNU General Public License v3.0 — GPL-3.0**

See [`LICENSE`](LICENSE) for the complete license text.

---

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

[GitHub](https://github.com/HyperSecurityLabs/hypersec-osintforge) •
[Website](https://hypersecurityoffseclabs.great-site.net) •
[Releases](https://github.com/HyperSecurityLabs/hypersec-osintforge/releases)

</div>
