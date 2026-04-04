# Changelog

All notable changes to Azure Network Security Visualizer will be documented here.

## [0.1.0] — 2026-04-04

### Added
- Initial release
- Bicep file parser for Azure networking resources (VNets, Subnets, NSGs, Route Tables, PEs, Firewalls, Peerings)
- ARM template JSON parser with line number tracking
- Professional 2.5D topology webview — glassmorphism cards, gradient icons, depth shadows, hover animations
- Security analyzer with 14 rules (NETSEC-001–014) based on Microsoft Security Benchmark
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
- 85 unit tests across 4 suites
