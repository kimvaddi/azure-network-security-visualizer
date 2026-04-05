# Azure Network Security Visualizer

[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/KimVaddi.azure-network-security-visualizer)](https://marketplace.visualstudio.com/items?itemName=KimVaddi.azure-network-security-visualizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Catch Azure network misconfigurations before they become security incidents.**

> Network misconfiguration is the #1 cause of Azure security incidents ([Microsoft Digital Defense Report](https://learn.microsoft.com/security/benchmark/azure/overview)). This extension catches them before deployment — no Azure subscription required.

---

## Table of Contents

- [What Is This?](#what-is-this)
- [Who Is This For?](#who-is-this-for)
- [Quick Start Guide](#quick-start-guide)
  - [Step 1: Install the Extension](#step-1-install-the-extension)
  - [Step 2: Open or Create a Bicep File](#step-2-open-or-create-a-bicep-file)
  - [Step 3: Visualize Your Network](#step-3-visualize-your-network)
  - [Step 4: Review Security Findings](#step-4-review-security-findings)
  - [Step 5: Fix Issues and Re-Analyze](#step-5-fix-issues-and-re-analyze)
  - [Step 6: Export a Security Report](#step-6-export-a-security-report)
  - [Step 7: Visualize Live Azure Topology](#step-7-visualize-live-azure-topology-optional--requires-azure-account)
- [Features](#features)
- [Security Rules Reference](#security-rules-reference)
- [Commands](#commands)
- [Configuration](#configuration)
- [Supported Azure Resources](#supported-azure-resources)
- [New to Azure? Start Here](#new-to-azure-start-here)
- [Microsoft Learn References](#microsoft-learn-references)
- [Contributing](#contributing)

---

## What Is This?

A **Zero Trust network security assessment tool** built into VS Code. Connect to your Azure environment via Entra ID and instantly get a security posture grade — with specific remediation steps for every finding, aligned to [Microsoft Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/overview) and [Azure Zero Trust networking](https://learn.microsoft.com/security/zero-trust/azure-networking-overview).

### Primary: Live Azure Assessment (Enterprise)
1. ☁️ **Connect via Entra ID** — sign in, pick subscriptions across your tenant
2. 🔍 **Assess Security Posture** — runs 26 Zero Trust checks against your deployed resources
3. 🛡️ **Get a posture grade** (A–F) with actionable fix guidance per finding
4. 📊 **Export reports** — CSV for Excel, HTML for management, Markdown for Git

### Secondary: Pre-Deployment Analysis
5. 📄 **Analyze Bicep/ARM templates** before deploying — catch issues in code review
6. 🌐 **Interactive topology map** — visualize VNets, subnets, NSGs, firewalls, peerings

---

## Who Is This For?

| Role | How You Benefit |
|------|-----------------|
| **Security Teams** | One-click posture assessment across all subscriptions. Export to Excel for audit. |
| **Cloud Architects** | Validate Zero Trust alignment for existing infrastructure |
| **Platform Engineers** | Audit network security posture before and after changes |
| **Cloud Engineers** | Catch NSG misconfigurations before `az deployment` |
| **DevOps / Platform Teams** | Add security checks to your PR review process |
| **Students / Beginners** | Learn Azure networking visually — see how VNets, subnets, and NSGs connect |

---

## Quick Start Guide

> 💡 **New to Azure?** No problem. This guide walks you through everything from installation to your first security report. No Azure account needed.

### Step 1: Install the Extension

**Option A — From VS Code (Recommended)**

1. Open **VS Code**
2. Click the **Extensions** icon in the left sidebar (or press `Ctrl+Shift+X`)
3. Search for **"Azure Network Security Visualizer"**
4. Click **Install**

```
┌──────────────────────────────────────────────────┐
│  Extensions: Marketplace                    🔍   │
│  ┌──────────────────────────────────────────┐    │
│  │ Azure Network Security Visualizer        │    │
│  │ KimVaddi                                 │    │
│  │ ★★★★★  [Install]                         │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

**Option B — From Command Line**

```bash
code --install-extension KimVaddi.azure-network-security-visualizer
```

After installation, you'll see a **🛡️ shield icon** in your VS Code status bar — that's the extension ready to go.

---

### Step 2: Open or Create a Bicep File

If you already have Bicep (`.bicep`) or ARM template (`.json`) files, open that folder in VS Code.

**Don't have any Bicep files yet?** Create one to try it out:

1. Open VS Code → **File** → **Open Folder** → create or choose an empty folder
2. Create a new file called `main.bicep`
3. Paste this sample (it has intentional security issues for the extension to catch):

```bicep
// main.bicep — Sample Azure network with security issues
// Try it: Ctrl+Shift+P → "Azure NetSec: Visualize Network Topology"

resource myVnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: 'vnet-myapp-eastus'
  location: 'eastus'
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'snet-web'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: {
            id: webNsg.id
          }
        }
      }
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.0.2.0/24'
          // ⚠️ No NSG attached — the extension will flag this!
        }
      }
    ]
  }
}

resource webNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: 'nsg-web'
  location: 'eastus'
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPS'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
      {
        // ⚠️ BAD: SSH open to the internet — the extension will flag this as CRITICAL
        name: 'AllowSSH-INSECURE'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'          // ← This means ANY source on the internet
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'        // ← SSH port
        }
      }
    ]
  }
}
```

> 📖 **What is Bicep?** Bicep is Microsoft's language for defining Azure cloud resources as code. Think of it as a blueprint that tells Azure what to build. [Learn more →](https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview)

---

### Step 3: Visualize Your Network

1. Press `Ctrl+Shift+P` to open the **Command Palette**
2. Type **"Visualize"** and select **"Azure NetSec: Visualize Network Topology"**

```
┌──────────────────────────────────────────────────┐
│  > Visualize                                     │
│  ┌──────────────────────────────────────────┐    │
│  │ 🛡️ Azure NetSec: Visualize Network       │ ← │
│  │    Topology                               │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

A new panel opens beside your code showing:

```
┌─────────────────────────────────┬─────────────────────┐
│  🌐 Network Topology            │ 🔍 Security Findings │
│                                 │                     │
│  ┌─────────────────────────┐   │  🔴 [NETSEC-001]    │
│  │ 🌐 vnet-myapp-eastus    │   │  SSH port 22 open   │
│  │    10.0.0.0/16          │   │  to the internet    │
│  │                         │   │                     │
│  │  ┌──────┐ ┌──────────┐ │   │  🟠 [NETSEC-005]    │
│  │  │snet- │ │snet-app  │ │   │  Overly permissive  │
│  │  │web   │ │ ⚠️ NO NSG│ │   │  source address     │
│  │  │🛡 NSG│ │          │ │   │                     │
│  │  └──────┘ └──────────┘ │   │  🟠 [NETSEC-007]    │
│  └─────────────────────────┘   │  Subnet "snet-app"  │
│                                 │  has no NSG         │
│  🛡️ Network Security Groups    │                     │
│  ┌─────────────────────────┐   │  🟡 [NETSEC-004]    │
│  │ 🛡️ nsg-web  (2 rules)  │   │  No explicit        │
│  │ Click to see rules →    │   │  deny-all rule      │
│  └─────────────────────────┘   │                     │
└─────────────────────────────────┴─────────────────────┘
```

**What you see:**
- **Left panel** — Your network topology as a visual map. VNets are blue boxes, subnets are cards inside them. Tags show which subnets have NSGs, route tables, or private endpoints.
- **Right panel** — Security findings sorted by severity (critical first). Click any finding to see details and a link to Microsoft's official fix guide.
- **Top toolbar** — Summary badges (e.g., "2 Critical, 1 High"), zoom controls.

---

### Step 4: Review Security Findings

Each finding tells you:
- **What's wrong** — e.g., "SSH port 22 is open to the internet"
- **Why it matters** — e.g., "This exposes your VM to brute force attacks"
- **How to fix it** — e.g., "Use Azure Bastion instead of opening SSH directly"
- **Learn more** — Direct link to the official Microsoft Learn documentation

**Try these interactions:**

| Action | What Happens |
|--------|-------------|
| **Click an NSG card** in the topology | See all its security rules sorted by priority |
| **Click a finding** in the sidebar | See the full description, recommendation, and "Learn More" / "Go to Source" buttons |
| **Click "Learn More"** | Opens the Microsoft Learn page with the official best practice |
| **Click "Go to Source"** | Jumps to the exact line in your Bicep/ARM file |

You'll also notice **inline warnings** in your code editor — yellow and red squiggles on the lines that have security issues. Hover over them to see the finding details.

```
┌──────────────────────────────────────────────────────────────┐
│  main.bicep                                                  │
│                                                              │
│  55│          sourceAddressPrefix: '*'                        │
│    │  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                     │
│    │  ⚠️ [NETSEC-001] SSH port 22 open to the internet:      │
│    │  NSG rule "AllowSSH-INSECURE" allows inbound SSH...     │
│    │  Source: Azure NetSec                                    │
│    │  [NETSEC-001 — Learn More ↗]                            │
└──────────────────────────────────────────────────────────────┘
```

---

### Step 5: Fix Issues and Re-Analyze

Fix the issues using the recommendations. Here's how to fix the sample:

**Fix 1 — Replace open SSH with Azure Bastion (NETSEC-001):**

```bicep
      // ✅ FIXED: Restrict SSH to your corporate VPN IP only
      {
        name: 'AllowSSH-Restricted'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '203.0.113.50/32'   // ← Your office IP only
          sourcePortRange: '*'
          destinationAddressPrefix: '10.0.1.0/24'
          destinationPortRange: '22'
        }
      }
```

> 📖 **Best practice:** Use [Azure Bastion](https://learn.microsoft.com/azure/bastion/bastion-overview) instead of opening SSH/RDP ports at all. Bastion provides secure, browser-based access without exposing any ports.

**Fix 2 — Attach an NSG to snet-app (NETSEC-007):**

```bicep
      {
        name: 'snet-app'
        properties: {
          addressPrefix: '10.0.2.0/24'
          networkSecurityGroup: {
            id: appNsg.id                         // ← Now protected!
          }
        }
      }
```

**Fix 3 — Add explicit deny-all rule (NETSEC-004):**

```bicep
      {
        name: 'DenyAllInbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
```

> 📖 **Why add deny-all when Azure already has a default deny?** Because an explicit rule (1) makes your intent clear to auditors, (2) appears in [NSG flow logs](https://learn.microsoft.com/azure/network-watcher/nsg-flow-logs-overview), and (3) prevents accidental permissive rules from taking effect. [Learn more →](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#default-security-rules)

After saving (`Ctrl+S`), the extension **automatically re-analyzes** your file. The fixed issues disappear from the findings panel and the inline warnings clear.

---

### Step 6: Export a Security Report

Share your findings with your team or attach them to a pull request:

1. Click the **📊 Export Report** button in the topology toolbar, or press `Ctrl+Shift+P` → **"Azure NetSec: Export Security Report"**
2. Choose a format:

| Format | Best For |
|--------|----------|
| **📊 CSV (Excel)** | Opens directly in Excel — sort, filter, pivot. Best for security teams. |
| **🌐 HTML** | Rich visual report — print to PDF from browser (Ctrl+P). Best for management. |
| **📝 Markdown** | Adding to pull requests, wikis, or Git repos. Best for DevOps. |
| **🔧 JSON** | Feeding into CI/CD pipelines or automated compliance tools. Best for automation. |

3. Choose a save location
4. Open the report — it includes topology summary, all findings with recommendations, and links to Microsoft Learn

> 💡 **Need PDF or Word?** Export as HTML → open in browser → Ctrl+P → "Save as PDF". Or open the HTML in Microsoft Word → "Save As .docx".

---

### Step 7: Visualize Live Azure Topology (Optional — Requires Azure Account)

> ☁️ **This step requires an Azure subscription.** If you're just analyzing Bicep/ARM files, you can skip this.

Connect to your real Azure environment and visualize deployed resources across **all your subscriptions** in one tenant:

1. Press `Ctrl+Shift+P` → **"Azure NetSec: Sign In to Azure (Entra ID)"**

```
┌──────────────────────────────────────────────────┐
│  > Sign In                                       │
│  ┌──────────────────────────────────────────┐    │
│  │ 🛡️ Azure NetSec: Sign In to Azure        │ ← │
│  │    (Entra ID)                             │    │
│  └──────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

2. A browser window opens for **Microsoft Entra ID** authentication. Sign in with your Azure credentials.

3. After sign-in, you'll see: `"Signed in to Azure. Found 5 subscription(s)."` — click **"Visualize Live Topology"** (or run `Ctrl+Shift+P` → **"Azure NetSec: Visualize Live Azure Topology"** anytime)

4. **Select which subscriptions to scan** (all selected by default):

```
┌──────────────────────────────────────────────────┐
│  Azure Subscriptions                             │
│  Select subscriptions to scan                    │
│  ┌──────────────────────────────────────────┐    │
│  │ ☑ Production (abc123-...)                 │    │
│  │ ☑ Staging (def456-...)                    │    │
│  │ ☑ Development (ghi789-...)                │    │
│  │ ☐ Sandbox (jkl012-...)                    │    │
│  └──────────────────────────────────────────┘    │
│                            [OK]  [Cancel]        │
└──────────────────────────────────────────────────┘
```

5. The extension queries **Azure Resource Graph** across all selected subscriptions and builds the live topology. The same security analysis runs on your deployed resources — you'll see the same findings panel, topology map, and can export reports.

**What it fetches:**
- VNets, Subnets with their NSG and Route Table associations
- NSGs with all security rules
- Route Tables with routes
- Azure Firewalls with threat intelligence mode
- Private Endpoints with their connected services
- VNet Peerings across VNets (even cross-subscription)

**What it does NOT do:**
- It does **not** make any changes to your Azure resources (read-only)
- It does **not** access storage, databases, or compute resources
- It requires **Reader** role at minimum on the subscriptions you want to scan

> 📖 **How does authentication work?** The extension uses [Microsoft Entra ID](https://learn.microsoft.com/entra/identity/) (formerly Azure AD) through VS Code's built-in Microsoft authentication provider. Your credentials are handled by VS Code — the extension never sees your password. [Learn more about Azure Identity →](https://learn.microsoft.com/javascript/api/overview/azure/identity-readme)

> 📖 **What is Azure Resource Graph?** It's Microsoft's service for querying resources across subscriptions efficiently — like a search engine for your Azure infrastructure. [Learn more →](https://learn.microsoft.com/azure/governance/resource-graph/overview)

---

## Features

### 🌐 Interactive Network Topology
- **Professional 2.5D visual design** — glassmorphism cards, gradient icons, depth shadows, hover animations
- Dot-grid background with color-coded resource cards (blue=VNet, green=subnet, orange=NSG, red=firewall, purple=PE)
- VNets rendered as perspective-shifted containers with glow effects
- Subnet cards with accent bars — green for healthy, red for security issues
- Connection lines between subnets, NSGs, route tables, and private endpoints
- Click any NSG to inspect its security rules sorted by priority
- Zoom, pan, and navigate the topology

### 📐 Mermaid Diagram Export
- Click **📐 Mermaid** in the toolbar to generate a `.mmd` diagram from your topology
- VNets as subgraphs, resources as styled nodes, connections as edges
- Color-coded node classes: danger (red), NSG (orange), firewall (red), PE (purple)
- Copy to clipboard for pasting into GitHub README, Confluence, or any Markdown doc
- Install the [Mermaid Preview](https://marketplace.visualstudio.com/items?itemName=bierner.markdown-mermaid) extension for live rendering in VS Code

### 🛡️ Security Analysis Engine (14 Rules)
Automatically detects misconfigurations based on [Microsoft Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/overview). Runs offline — no Azure subscription required.

- **Security posture assessment** — instant summary: "Immediate Action Required" vs "Good posture"
- **Findings grouped by action** — "Fix Immediately", "Review & Remediate", "Best Practice Improvements", "Safe to Acknowledge"
- **Actionable guidance per rule** — tells you exactly what to do, not just what's wrong
- **Deduplicated by rule** — 29 NETSEC-001 findings become one card showing "12 resources affected"
- **Clickable MS Learn links** — "📖 How to Fix" opens the official Microsoft remediation guide

### 📊 Security Reports
Export findings directly from the webview via the **📊 Export Report** button:
- **CSV (Excel)** — Opens directly in Excel with sortable, filterable columns
- **HTML** — Rich visual report — print to PDF from browser (Ctrl+P)
- **Markdown** — For pull requests, wikis, Git repos
- **JSON** — Machine-readable for CI/CD pipelines

### ☁️ Live Azure Topology (Cross-Subscription)
- Sign in via **Microsoft Entra ID** (Azure AD) — uses VS Code's built-in auth
- **Multi-subscription** — pick which subscriptions to scan within your tenant
- Queries **Azure Resource Graph** for efficient cross-subscription discovery
- Same visualization, same security analysis, same reports — on your live deployed resources
- **Read-only** — never modifies your Azure resources

### ⚡ Real-time Analysis
- **Auto-analyzes on save** — no need to re-run manually
- **Inline diagnostics** — yellow/red squiggles on problematic lines
- **Status bar indicator** — shows `🛡️ NetSec: 2 Critical` at a glance
- **Activity bar panel** — tree view of all findings, click to navigate to source

---

## Security Rules Reference

All 26 rules are based on [Microsoft Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-network-security), [Azure Zero Trust Networking](https://learn.microsoft.com/security/zero-trust/azure-networking-overview), and [Azure Network Security Best Practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices):

| Rule ID | Severity | What It Detects | Fix Guide |
|---------|----------|-----------------|-----------|
| NETSEC-001 | 🔴 Critical | SSH port 22 open to the internet | [Use Azure Bastion](https://learn.microsoft.com/azure/bastion/bastion-overview) |
| NETSEC-002 | 🔴 Critical | RDP port 3389 open to the internet | [Use JIT Access](https://learn.microsoft.com/azure/defender-for-cloud/enable-just-in-time-access) |
| NETSEC-003 | 🟠 High | Any-to-any allow rules | [Filter network traffic](https://learn.microsoft.com/azure/virtual-network/tutorial-filter-network-traffic) |
| NETSEC-004 | 🟡 Warning | Missing explicit deny-all inbound rule | [NSG default rules](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#default-security-rules) |
| NETSEC-005 | 🟠 High | Overly permissive source (0.0.0.0/0) | [Use Service Tags](https://learn.microsoft.com/azure/virtual-network/service-tags-overview) |
| NETSEC-006 | 🟠 High | Overly permissive outbound destination | [Network segmentation](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices#logically-segment-subnets) |
| NETSEC-007 | 🟠 High | Subnets without NSG attached | [Manage NSGs](https://learn.microsoft.com/azure/virtual-network/manage-network-security-group) |
| NETSEC-008 | 🟡 Warning | Excessively wide port ranges | [Network best practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices) |
| NETSEC-009 | 🟡 Warning | Low-priority catch-all allow rule | [JIT access](https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-overview) |
| NETSEC-010 | 🟠 High | Firewall threat intelligence disabled | [Firewall threat intel](https://learn.microsoft.com/azure/firewall/threat-intel) |
| NETSEC-011 | 🔵 Info | Missing NSG/VNet flow logs | [Traffic Analytics](https://learn.microsoft.com/azure/network-watcher/traffic-analytics-usage-scenarios) |
| NETSEC-012 | 🔵 Info | Hardcoded IPs (use Service Tags instead) | [Service Tags](https://learn.microsoft.com/azure/virtual-network/service-tags-overview) |
| NETSEC-013 | 🔵 Info | Overlapping rules with conflicting actions | [NSG rule evaluation](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#security-rules) |
| NETSEC-014 | 🟡 Warning | Default route to Internet (bypasses firewall) | [UDR overview](https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview) |
| NETSEC-015 | 🟠 High | VNet without DDoS Protection | [Zero Trust DDoS](https://learn.microsoft.com/azure/networking/security/zero-trust-ddos-protection) |
| NETSEC-016 | 🟡 Warning | No Azure Bastion subnet in VNet | [Azure Bastion](https://learn.microsoft.com/azure/bastion/bastion-overview) |
| NETSEC-017 | 🟡 Warning | Private Endpoint without DNS zone group | [PE DNS config](https://learn.microsoft.com/azure/private-link/private-endpoint-dns) |
| NETSEC-018 | 🟠 High | Application Gateway without WAF enabled | [WAF on App Gateway](https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview) |
| NETSEC-019 | 🟡 Warning | WAF in Detection mode (not blocking attacks) | [WAF modes](https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview) |
| NETSEC-020 | 🟠 High | Application Gateway allows TLS below 1.2 | [TLS policy](https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview) |
| NETSEC-021 | 🟡 Warning | Subnet without route table (bypasses firewall) | [Forced tunneling](https://learn.microsoft.com/azure/firewall/forced-tunneling) |
| NETSEC-022 | 🟠 High | VPN Gateway using Basic SKU (no custom crypto) | [Gateway SKUs](https://learn.microsoft.com/azure/vpn-gateway/about-gateway-skus) |
| NETSEC-023 | 🟡 Warning | VPN Gateway is policy-based (legacy IKEv1) | [VPN settings](https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#vpntype) |
| NETSEC-024 | 🔵 Info | NSG rules use IPs instead of ASGs | [ASG overview](https://learn.microsoft.com/azure/virtual-network/application-security-groups) |
| NETSEC-025 | 🔵 Info | No forced tunneling route to firewall | [Forced tunneling](https://learn.microsoft.com/azure/firewall/forced-tunneling) |
| NETSEC-026 | 🔵 Info | Public IP without DDoS protection | [DDoS Protection](https://learn.microsoft.com/azure/ddos-protection/ddos-protection-overview) |

---

## Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| `Azure NetSec: Visualize Network Topology` | `Ctrl+Shift+P` → type "Visualize" | Open interactive topology from local Bicep/ARM files |
| `Azure NetSec: Analyze Current File` | | Analyze the active Bicep/ARM file and show inline diagnostics |
| `Azure NetSec: Analyze Workspace Security` | | Scan all networking files in the workspace |
| `Azure NetSec: Export Security Report` | | Export findings as CSV (Excel), HTML, Markdown, or JSON |
| `Azure NetSec: Show Effective Rules for Resource` | | Pick an NSG and view all its rules sorted by priority |
| `Azure NetSec: Sign In to Azure (Entra ID)` | | Authenticate to Azure and list available subscriptions |
| `Azure NetSec: Visualize Live Azure Topology` | | Fetch and visualize deployed resources across selected subscriptions |

---

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `azureNetSec.severityThreshold` | `warning` | Minimum severity to show (`critical`, `high`, `warning`, `info`) |
| `azureNetSec.autoAnalyzeOnSave` | `true` | Automatically re-analyze when you save a Bicep/ARM file |
| `azureNetSec.showInlineDecorations` | `true` | Show yellow/red squiggles on problematic lines |
| `azureNetSec.reportFormat` | `html` | Default format: `html`, `markdown`, `json`, `csv` |

To change settings: **File** → **Preferences** → **Settings** → search **"azureNetSec"**.

---

## Supported Azure Resources

| Resource Type | What It Is (Beginner-Friendly) |
|---------------|-------------------------------|
| `Microsoft.Network/virtualNetworks` | **Virtual Network (VNet)** — Your private network in Azure, like a building with rooms (subnets) |
| `Microsoft.Network/networkSecurityGroups` | **NSG** — A firewall-like filter that controls which traffic can enter or leave a subnet |
| `Microsoft.Network/routeTables` | **Route Table** — Traffic directions: "send traffic to X via Y" |
| `Microsoft.Network/privateEndpoints` | **Private Endpoint** — Connects to Azure services (databases, storage) over your private network instead of the public internet |
| `Microsoft.Network/azureFirewalls` | **Azure Firewall** — A cloud-managed firewall that inspects and filters all traffic |
| `Microsoft.Network/applicationGateways` | **Application Gateway** — Layer 7 load balancer with optional WAF (Web Application Firewall) for web apps |
| `Microsoft.Network/bastionHosts` | **Azure Bastion** — Secure, browser-based VM access without exposing SSH/RDP ports |
| `Microsoft.Network/virtualNetworkGateways` | **VPN Gateway** — Encrypted tunnel between Azure and your on-premises network |
| `Microsoft.Network/virtualNetworks/virtualNetworkPeerings` | **VNet Peering** — Connects two VNets so they can communicate, like building a bridge |

---

## New to Azure? Start Here

If you've never worked with Azure before, here's the learning path to get the most out of this extension:

### 1. Understand the Basics (15 min)
- 📖 [What is Azure?](https://learn.microsoft.com/azure/cloud-adoption-framework/get-started/what-is-azure) — Start here if you've never used cloud computing
- 📖 [What is a Virtual Network?](https://learn.microsoft.com/azure/virtual-network/virtual-networks-overview) — The foundation of Azure networking
- 📖 [What is a Network Security Group?](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview) — How traffic filtering works

### 2. Learn Bicep (30 min)
- 📖 [What is Bicep?](https://learn.microsoft.com/azure/azure-resource-manager/bicep/overview) — Infrastructure-as-Code for Azure
- 📖 [Bicep Quickstart](https://learn.microsoft.com/azure/azure-resource-manager/bicep/quickstart-create-bicep-use-visual-studio-code) — Write your first Bicep file in VS Code
- 📖 [Install the Bicep Extension](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-bicep) — Syntax highlighting and IntelliSense for Bicep files

### 3. Security Fundamentals (20 min)
- 📖 [Azure Network Security Best Practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices) — The rules this extension enforces
- 📖 [Cloud Adoption Framework — Network Segmentation](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-landing-zone-network-segmentation) — How to structure your network like a pro
- 📖 [Well-Architected Framework — Security Pillar](https://learn.microsoft.com/azure/well-architected/security/) — Microsoft's blueprint for secure cloud architecture

### 4. Try It Hands-On
1. Install this extension ([Step 1](#step-1-install-the-extension))
2. Paste the sample Bicep code ([Step 2](#step-2-open-or-create-a-bicep-file))
3. Visualize and fix the security issues ([Steps 3-5](#step-3-visualize-your-network))
4. Explore the Microsoft Learn links in each finding — they're curated to teach you exactly what you need

---

## Microsoft Learn References

This extension's security rules are based on official Microsoft best practices:

- [Azure Security Benchmark — Network Security](https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-network-security)
- [Azure Network Security Best Practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)
- [NSG Overview & Default Rules](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview)
- [Secure VNet Deployment](https://learn.microsoft.com/azure/virtual-network/secure-virtual-network)
- [Traffic Analytics](https://learn.microsoft.com/azure/network-watcher/traffic-analytics-usage-scenarios)
- [Azure Bastion (Replace open SSH/RDP)](https://learn.microsoft.com/azure/bastion/bastion-overview)
- [Service Tags](https://learn.microsoft.com/azure/virtual-network/service-tags-overview)
- [Private Link](https://learn.microsoft.com/azure/private-link/private-link-overview)
- [Azure Firewall Threat Intelligence](https://learn.microsoft.com/azure/firewall/threat-intel)
- [Cloud Adoption Framework — Network Segmentation](https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/plan-for-landing-zone-network-segmentation)
- [Well-Architected Framework — Security](https://learn.microsoft.com/azure/well-architected/security/)

---

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © KimVaddi
