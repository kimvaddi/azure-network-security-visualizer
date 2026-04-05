# Azure Network Security Visualizer

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/KimVaddi.azure-network-security-visualizer)](https://marketplace.visualstudio.com/items?itemName=KimVaddi.azure-network-security-visualizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Assess your Azure network security posture in one click.** Connect via Entra ID, scan across subscriptions, get a grade (A–F), and fix what matters — all inside VS Code.

---

## The Problem

You can't see your Azure network security posture without clicking through 50 portal blades. Open SSH ports, missing NSGs, permissive firewall rules, and no DDoS protection sit undetected until an incident.

## The Solution

This extension connects to your Azure tenant, scans your live infrastructure, and tells you:
- **What's wrong** — 26 security checks aligned to [Microsoft Zero Trust](https://learn.microsoft.com/security/zero-trust/azure-networking-overview)
- **How bad it is** — posture grade A–F with severity counts
- **How to fix it** — one-line remediation + Microsoft Learn link per finding
- **Who to share it with** — export to Excel, HTML, Markdown, or JSON

Also analyzes Bicep/ARM templates offline for pre-deployment checks.

---

## Quick Start

### Assess Live Azure (Recommended)

1. `Ctrl+Shift+P` → **"Assess Security Posture"**
2. Sign in with your Azure (Entra ID) credentials
3. Select subscriptions to scan
4. Review your posture grade and findings
5. Click **📊 Export Report** for Excel/HTML/Markdown

### Analyze Bicep/ARM Files (No Azure Account Needed)

1. Open a folder with `.bicep` or `.json` ARM templates
2. `Ctrl+Shift+P` → **"Analyze Bicep/ARM Templates"**
3. Review findings in the sidebar and inline squiggles

---

## What It Checks (26 Rules)

| # | Severity | Check | Fix |
|---|----------|-------|-----|
| 001 | 🔴 Critical | SSH open to internet | [Azure Bastion](https://learn.microsoft.com/azure/bastion/bastion-overview) |
| 002 | 🔴 Critical | RDP open to internet | [JIT Access](https://learn.microsoft.com/azure/defender-for-cloud/enable-just-in-time-access) |
| 003 | 🟠 High | Any-to-any allow | [Filter traffic](https://learn.microsoft.com/azure/virtual-network/tutorial-filter-network-traffic) |
| 004 | 🟡 Warning | No deny-all rule | [Default rules](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#default-security-rules) |
| 005 | 🟠 High | Permissive source 0.0.0.0/0 | [Service Tags](https://learn.microsoft.com/azure/virtual-network/service-tags-overview) |
| 006 | 🟠 High | Permissive outbound | [Segmentation](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices#logically-segment-subnets) |
| 007 | 🟠 High | Subnet without NSG | [Manage NSGs](https://learn.microsoft.com/azure/virtual-network/manage-network-security-group) |
| 008 | 🟡 Warning | Wide port range | [Best practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices) |
| 009 | 🟡 Warning | Catch-all allow at low priority | [JIT access](https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-overview) |
| 010 | 🟠 High | Firewall threat intel off | [Threat intel](https://learn.microsoft.com/azure/firewall/threat-intel) |
| 011 | 🔵 Info | No flow logs | [Traffic Analytics](https://learn.microsoft.com/azure/network-watcher/traffic-analytics-usage-scenarios) |
| 012 | 🔵 Info | Hardcoded IPs | [Service Tags](https://learn.microsoft.com/azure/virtual-network/service-tags-overview) |
| 013 | 🔵 Info | Overlapping rules | [Rule evaluation](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#security-rules) |
| 014 | 🟡 Warning | Default route to internet | [UDR overview](https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview) |
| 015 | 🟠 High | VNet without DDoS | [DDoS Protection](https://learn.microsoft.com/azure/networking/security/zero-trust-ddos-protection) |
| 016 | 🟡 Warning | No Bastion subnet | [Azure Bastion](https://learn.microsoft.com/azure/bastion/bastion-overview) |
| 017 | 🟡 Warning | PE without DNS zone | [PE DNS](https://learn.microsoft.com/azure/private-link/private-endpoint-dns) |
| 018 | 🟠 High | App Gateway without WAF | [WAF overview](https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview) |
| 019 | 🟡 Warning | WAF in Detection only | [WAF modes](https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview) |
| 020 | 🟠 High | TLS below 1.2 | [TLS policy](https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview) |
| 021 | 🟡 Warning | Subnet bypasses firewall | [Forced tunneling](https://learn.microsoft.com/azure/firewall/forced-tunneling) |
| 022 | 🟠 High | VPN Gateway Basic SKU | [Gateway SKUs](https://learn.microsoft.com/azure/vpn-gateway/about-gateway-skus) |
| 023 | 🟡 Warning | Policy-based VPN (legacy) | [VPN settings](https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#vpntype) |
| 024 | 🔵 Info | IPs instead of ASGs | [ASGs](https://learn.microsoft.com/azure/virtual-network/application-security-groups) |
| 025 | 🔵 Info | No forced tunnel to firewall | [Forced tunneling](https://learn.microsoft.com/azure/firewall/forced-tunneling) |
| 026 | 🔵 Info | Public IP no DDoS | [DDoS overview](https://learn.microsoft.com/azure/ddos-protection/ddos-protection-overview) |

---

## Commands

| Command | What It Does |
|---------|-------------|
| **Assess Security Posture** | Connect to Azure → scan → grade → findings |
| **Connect to Azure (Entra ID)** | Sign in and list subscriptions |
| **Visualize Live Topology** | Draw your deployed network with connections |
| **Export Security Report** | CSV, HTML, Markdown, or JSON |
| **Analyze Bicep/ARM Templates** | Scan local files (no Azure needed) |
| **Show Effective Rules** | View sorted NSG rules for any security group |

All commands: `Ctrl+Shift+P` → type "Azure NetSec"

---

## Resources Scanned

VNets · Subnets · NSGs · Route Tables · Private Endpoints · Azure Firewalls · Application Gateways · Bastion Hosts · VPN Gateways · VNet Peerings

---

## Export Formats

| Format | Use Case |
|--------|----------|
| **CSV** | Opens in Excel — sort, filter, pivot for audit |
| **HTML** | Visual report — print to PDF via Ctrl+P |
| **Markdown** | Add to PRs, wikis, Git repos |
| **JSON** | CI/CD pipelines, automation |

---

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `azureNetSec.severityThreshold` | `warning` | Minimum severity to show |
| `azureNetSec.autoAnalyzeOnSave` | `true` | Re-analyze Bicep/ARM on save |
| `azureNetSec.reportFormat` | `html` | Default export format |

---

## Requirements

- **VS Code** 1.85+
- **For live Azure**: An Azure account with **Reader** role on target subscriptions
- **For Bicep/ARM**: No Azure account needed — works offline

---

## Based On

- [Microsoft Security Benchmark — Network Security](https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-network-security)
- [Azure Zero Trust Networking](https://learn.microsoft.com/security/zero-trust/azure-networking-overview)
- [Azure Network Security Best Practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)
- [Well-Architected Framework — Security](https://learn.microsoft.com/azure/well-architected/security/)
- [Cloud Adoption Framework — Network Segmentation](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-landing-zone-network-segmentation)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © KimVaddi
