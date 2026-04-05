# Changelog

All notable changes to Azure Network Security Visualizer will be documented here.

## [0.2.0] — 2026-04-04

### Added
- **Enterprise-first UX** — live Azure posture assessment as primary workflow
- **Assess Security Posture** command — one-click connect → scan → grade → export
- **Security posture grade (A–F)** with numeric score and color-coded circle
- 26 Zero Trust security rules (NETSEC-001–026)
- Application Gateway parsing — WAF detection, TLS version enforcement
- Bastion Host and VPN Gateway parsing
- WAF rules: no WAF (018), Detection-only mode (019), weak TLS (020)
- Forced tunneling rule: subnet bypasses firewall (021)
- VPN Gateway rules: Basic SKU (022), policy-based/legacy (023)
- DDoS Protection for VNets (015), Bastion subnet check (016), PE DNS zones (017)
- Welcome sidebar panel with "Get Started" view — Azure actions first
- 9 resource types: VNet, NSG, RouteTable, PE, Firewall, AppGateway, Bastion, VPN Gateway, Peering
- 99 unit tests across 4 suites
- Concise README — 102 lines, enterprise-focused

### Changed
- Commands reordered: Connect → Assess → Visualize Live → Export → Bicep/ARM
- Description updated to reflect Zero Trust posture assessment focus

## [0.1.0] — 2026-04-04

### Added
- Initial release
- Bicep file parser for Azure networking resources (VNets, Subnets, NSGs, Route Tables, PEs, Firewalls, Peerings)
- ARM template JSON parser with line number tracking
- Professional 2.5D topology webview — glassmorphism cards, gradient icons, depth shadows, hover animations
- Security analyzer with 26 rules (NETSEC-001–026) based on Microsoft Security Benchmark + Azure Zero Trust
- Security posture assessment — instant summary with action groups (Fix Now / Review / Improve / Safe)
- Actionable guidance per rule — tells you what to do, not just what's wrong
- Findings deduplicated by rule ID with affected resource counts
- Live Azure topology via Entra ID authentication — cross-subscription Resource Graph queries
- Multi-subscription picker — scan all subscriptions in your tenant
- Mermaid diagram export — generates `.mmd` from topology with styled nodes and edges
- Security report export — CSV (Excel), HTML, Markdown, JSON via toolbar button
- VS Code diagnostics integration (inline warnings with clickable MS Learn links)
- Status bar security posture indicator
- Activity bar panel with findings tree view
- Auto-analyze on file save
- Click-to-source navigation from findings
- Effective rules viewer for NSGs
- MS Learn links validated via Microsoft documentation (all 14 rules)
- VNet Peering parsing (Bicep standalone resources)
- 99 unit tests across 4 suites
- Zero Trust coverage: DDoS, Bastion, PE DNS, WAF, TLS, forced tunneling, VPN Gateway security
