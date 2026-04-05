/**
 * VS Code Webview Panel provider for the network topology diagram.
 * Renders an interactive D3.js-based diagram showing VNets, subnets, NSGs,
 * firewalls, private endpoints, and security findings.
 */

import * as vscode from 'vscode';
import { NetworkTopology, SecurityFinding } from '../models/networkModel';

export class TopologyWebviewProvider {
  public static readonly viewType = 'azureNetSec.topologyView';
  private panel: vscode.WebviewPanel | undefined;

  constructor(private readonly extensionUri: vscode.Uri) {}

  public show(topology: NetworkTopology, findings: SecurityFinding[]): void {
    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.Beside);
    } else {
      this.panel = vscode.window.createWebviewPanel(
        TopologyWebviewProvider.viewType,
        'Azure Network Topology',
        vscode.ViewColumn.Beside,
        {
          enableScripts: true,
          retainContextWhenHidden: true,
          localResourceRoots: [
            vscode.Uri.joinPath(this.extensionUri, 'media'),
          ],
        }
      );

      this.panel.onDidDispose(() => {
        this.panel = undefined;
      });
    }

    this.panel.webview.html = this.getWebviewContent(
      this.panel.webview,
      topology,
      findings
    );

    // Handle messages from the webview
    this.panel.webview.onDidReceiveMessage((message) => {
      switch (message.command) {
        case 'showRules':
          this.showEffectiveRules(message.resourceId, topology);
          break;
        case 'goToSource':
          this.goToSourceLocation(message.filePath, message.line);
          break;
        case 'showFinding':
          this.showFindingDetail(message.findingId, findings);
          break;
        case 'openLink':
          if (message.url && message.url.startsWith('https://')) {
            vscode.env.openExternal(vscode.Uri.parse(message.url));
          }
          break;
        case 'exportReport':
          vscode.commands.executeCommand('azureNetSec.exportReport');
          break;
        case 'generateMermaid':
          this.generateMermaidDiagram(topology, findings);
          break;
      }
    });
  }

  public update(topology: NetworkTopology, findings: SecurityFinding[]): void {
    if (this.panel) {
      this.panel.webview.html = this.getWebviewContent(
        this.panel.webview,
        topology,
        findings
      );
    }
  }

  private showEffectiveRules(resourceId: string, topology: NetworkTopology): void {
    const nsg = topology.nsgs.find(n => n.id === resourceId);
    if (nsg) {
      const rulesText = nsg.rules
        .sort((a, b) => a.priority - b.priority)
        .map(r => `[${r.priority}] ${r.access} ${r.direction} ${r.protocol} ${r.sourceAddressPrefix}:${r.sourcePortRange} → ${r.destinationAddressPrefix}:${r.destinationPortRange} (${r.name})`)
        .join('\n');

      vscode.window.showInformationMessage(
        `Effective rules for ${nsg.name}`,
        { modal: true, detail: rulesText }
      );
    }
  }

  private goToSourceLocation(filePath: string, line: number): void {
    if (filePath) {
      const uri = vscode.Uri.file(filePath);
      vscode.window.showTextDocument(uri, {
        selection: new vscode.Range(
          new vscode.Position(Math.max(0, line - 1), 0),
          new vscode.Position(Math.max(0, line - 1), 0)
        ),
      });
    }
  }

  private async generateMermaidDiagram(topology: NetworkTopology, findings: SecurityFinding[]): Promise<void> {
    const lines: string[] = ['graph TB'];
    const sanitize = (s: string) => s.replace(/[^a-zA-Z0-9_-]/g, '_');

    // VNets and subnets
    topology.vnets.forEach(vnet => {
      const vid = sanitize(vnet.name);
      lines.push(`  subgraph ${vid}["🌐 ${vnet.name}<br/>${vnet.addressSpace.join(', ')}"]`);
      lines.push(`    direction TB`);
      vnet.subnets.forEach(subnet => {
        const sid = sanitize(subnet.name);
        const hasIssue = findings.some(f => f.resourceName === subnet.name);
        const style = hasIssue ? ':::danger' : '';
        lines.push(`    ${sid}["📦 ${subnet.name}<br/>${subnet.addressPrefix}"]${style}`);
      });
      lines.push(`  end`);
    });

    // NSGs
    topology.nsgs.forEach(nsg => {
      const nid = sanitize(nsg.name);
      lines.push(`  ${nid}["🛡️ ${nsg.name}<br/>${nsg.rules.length} rules"]:::nsg`);
    });

    // Firewalls
    topology.firewalls.forEach(fw => {
      const fid = sanitize(fw.name);
      lines.push(`  ${fid}["🔥 ${fw.name}<br/>SKU: ${fw.skuTier}"]:::firewall`);
    });

    // Private Endpoints
    topology.privateEndpoints.forEach(pe => {
      const pid = sanitize(pe.name);
      lines.push(`  ${pid}["🔒 ${pe.name}<br/>${pe.groupIds.join(', ')}"]:::pe`);
    });

    // Connections
    topology.connections.forEach(conn => {
      const src = sanitize(conn.sourceId);
      const tgt = sanitize(conn.targetId);
      const label = conn.label ? `|${conn.label}|` : '';

      switch (conn.connectionType) {
        case 'subnet-nsg':
          lines.push(`  ${src} -.->${label} ${tgt}`);
          break;
        case 'peering':
          lines.push(`  ${src} <==>${label} ${tgt}`);
          break;
        case 'private-endpoint':
          lines.push(`  ${src} --->${label} ${tgt}`);
          break;
        default:
          lines.push(`  ${src} -->${label} ${tgt}`);
      }
    });

    // Peerings as explicit connections
    topology.vnets.forEach(vnet => {
      vnet.peerings.forEach(p => {
        const src = sanitize(vnet.name);
        const tgt = sanitize(p.remoteVNetId);
        lines.push(`  ${src} <==>|"${p.name}"| ${tgt}`);
      });
    });

    // Styles
    lines.push('');
    lines.push('  classDef danger fill:#fecaca,stroke:#ef4444,stroke-width:2px,color:#991b1b');
    lines.push('  classDef nsg fill:#fed7aa,stroke:#f97316,stroke-width:2px,color:#9a3412');
    lines.push('  classDef firewall fill:#fecaca,stroke:#ef4444,stroke-width:2px,color:#991b1b');
    lines.push('  classDef pe fill:#ddd6fe,stroke:#8b5cf6,stroke-width:2px,color:#5b21b6');

    const mermaidContent = lines.join('\n');

    // Open as a new unsaved document
    const doc = await vscode.workspace.openTextDocument({
      content: mermaidContent,
      language: 'mermaid',
    });
    vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
    vscode.window.showInformationMessage(
      'Mermaid diagram generated. Install the "Mermaid Preview" extension to render it visually.',
      'Copy to Clipboard'
    ).then(action => {
      if (action === 'Copy to Clipboard') {
        vscode.env.clipboard.writeText(mermaidContent);
      }
    });
  }

  private showFindingDetail(findingId: string, findings: SecurityFinding[]): void {
    const finding = findings.find(f => f.id === findingId);
    if (finding) {
      vscode.window.showWarningMessage(
        `[${finding.severity.toUpperCase()}] ${finding.title}\n\n${finding.description}\n\nRecommendation: ${finding.recommendation}`,
        'Learn More',
        'Go to Source'
      ).then(selection => {
        if (selection === 'Learn More') {
          vscode.env.openExternal(vscode.Uri.parse(finding.learnMoreUrl));
        } else if (selection === 'Go to Source' && finding.filePath && finding.line) {
          this.goToSourceLocation(finding.filePath, finding.line);
        }
      });
    }
  }

  private getWebviewContent(
    webview: vscode.Webview,
    topology: NetworkTopology,
    findings: SecurityFinding[]
  ): string {
    const nonce = getNonce();

    // Prepare data for the webview
    const topologyJson = JSON.stringify(topology);
    const findingsJson = JSON.stringify(findings);

    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'nonce-${nonce}'; script-src 'nonce-${nonce}'; img-src ${webview.cspSource} data:;">
  <title>Azure Network Topology</title>
  <style nonce="${nonce}">
    :root {
      --bg-primary: var(--vscode-editor-background);
      --bg-secondary: var(--vscode-sideBar-background);
      --bg-elevated: var(--vscode-editorWidget-background, var(--bg-secondary));
      --fg-primary: var(--vscode-editor-foreground);
      --fg-secondary: var(--vscode-descriptionForeground);
      --border: var(--vscode-panel-border);
      --accent: var(--vscode-focusBorder);
      --critical: #ef4444;
      --high: #f97316;
      --warning: #eab308;
      --info: #3b82f6;
      --success: #22c55e;
      --vnet-gradient: linear-gradient(135deg, rgba(59,130,246,0.12) 0%, rgba(59,130,246,0.04) 100%);
      --subnet-gradient: linear-gradient(135deg, rgba(16,185,129,0.10) 0%, rgba(16,185,129,0.03) 100%);
      --nsg-gradient: linear-gradient(135deg, rgba(249,115,22,0.12) 0%, rgba(249,115,22,0.04) 100%);
      --fw-gradient: linear-gradient(135deg, rgba(239,68,68,0.12) 0%, rgba(239,68,68,0.04) 100%);
      --pe-gradient: linear-gradient(135deg, rgba(139,92,246,0.12) 0%, rgba(139,92,246,0.04) 100%);
      --glass: rgba(255,255,255,0.04);
      --glass-border: rgba(255,255,255,0.08);
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.08);
      --shadow-md: 0 4px 12px rgba(0,0,0,0.15), 0 2px 4px rgba(0,0,0,0.10);
      --shadow-lg: 0 8px 30px rgba(0,0,0,0.20), 0 4px 8px rgba(0,0,0,0.12);
      --shadow-glow-blue: 0 0 20px rgba(59,130,246,0.15);
      --shadow-glow-red: 0 0 15px rgba(239,68,68,0.20);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg-primary);
      color: var(--fg-primary);
      font-family: var(--vscode-font-family, 'Segoe UI', system-ui, sans-serif);
      font-size: var(--vscode-font-size, 13px);
      overflow: hidden;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }

    /* ─── Toolbar ─── */
    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 20px;
      background: var(--bg-elevated);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
      backdrop-filter: blur(8px);
    }
    .toolbar-title {
      font-weight: 700;
      font-size: 13px;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .toolbar button {
      background: var(--glass);
      color: var(--fg-primary);
      border: 1px solid var(--glass-border);
      padding: 5px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 11px;
      transition: all 0.15s ease;
      backdrop-filter: blur(4px);
    }
    .toolbar button:hover {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border-color: transparent;
      box-shadow: var(--shadow-sm);
      transform: translateY(-1px);
    }
    .toolbar .export-btn {
      margin-left: auto;
      background: linear-gradient(135deg, #0078d4, #005a9e);
      color: #fff;
      border: none;
      font-weight: 600;
      padding: 6px 16px;
    }
    .toolbar .export-btn:hover {
      background: linear-gradient(135deg, #1a8ae6, #0068b8);
      box-shadow: 0 0 12px rgba(0,120,212,0.3);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 3px 10px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.02em;
      box-shadow: var(--shadow-sm);
    }
    .badge.critical { background: var(--critical); color: white; }
    .badge.high { background: var(--high); color: white; }
    .badge.warning { background: var(--warning); color: #1a1a1a; }
    .badge.info { background: var(--info); color: white; }

    .summary { display: flex; gap: 8px; }

    .main-content { display: flex; flex: 1; overflow: hidden; }

    /* ─── Topology Canvas ─── */
    .topology-canvas {
      flex: 1;
      overflow: auto;
      padding: 28px;
      position: relative;
      background-image:
        radial-gradient(circle at 1px 1px, rgba(100,100,100,0.08) 1px, transparent 0);
      background-size: 24px 24px;
    }

    /* ─── VNet Container (3D Card) ─── */
    .vnet-container {
      background: var(--vnet-gradient);
      border: 1px solid rgba(59,130,246,0.25);
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: var(--shadow-md), var(--shadow-glow-blue);
      backdrop-filter: blur(8px);
      transform: perspective(1000px) rotateX(1deg);
      transition: transform 0.3s ease, box-shadow 0.3s ease;
    }
    .vnet-container:hover {
      transform: perspective(1000px) rotateX(0deg) translateY(-2px);
      box-shadow: var(--shadow-lg), var(--shadow-glow-blue);
    }
    .vnet-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 16px;
      font-size: 14px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .vnet-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: linear-gradient(135deg, #3b82f6, #1d4ed8);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      box-shadow: 0 2px 8px rgba(59,130,246,0.3);
    }
    .vnet-address {
      font-size: 11px;
      color: var(--fg-secondary);
      font-weight: 400;
      font-family: 'Cascadia Code', 'Fira Code', monospace;
      background: var(--glass);
      padding: 2px 8px;
      border-radius: 4px;
    }
    .vnet-location {
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 4px;
      background: rgba(59,130,246,0.15);
      color: #60a5fa;
      font-weight: 600;
    }

    /* ─── Subnet Cards ─── */
    .subnet-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
      gap: 12px;
    }
    .subnet-card {
      background: var(--subnet-gradient);
      border: 1px solid rgba(16,185,129,0.20);
      border-radius: 12px;
      padding: 14px;
      cursor: pointer;
      transition: all 0.2s ease;
      position: relative;
      overflow: hidden;
    }
    .subnet-card::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 3px;
      background: linear-gradient(90deg, #10b981, #059669);
      opacity: 0.6;
      border-radius: 12px 12px 0 0;
    }
    .subnet-card:hover {
      transform: translateY(-3px);
      box-shadow: var(--shadow-md);
      border-color: rgba(16,185,129,0.4);
    }
    .subnet-card.has-issues {
      border-color: rgba(239,68,68,0.4);
      box-shadow: var(--shadow-glow-red);
    }
    .subnet-card.has-issues::before {
      background: linear-gradient(90deg, var(--critical), #dc2626);
      opacity: 1;
    }
    .subnet-name {
      font-weight: 600;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 12px;
    }
    .subnet-icon {
      width: 22px; height: 22px;
      border-radius: 6px;
      background: linear-gradient(135deg, #10b981, #059669);
      display: flex; align-items: center; justify-content: center;
      font-size: 11px;
      box-shadow: 0 1px 4px rgba(16,185,129,0.3);
    }
    .subnet-prefix {
      font-size: 11px;
      color: var(--fg-secondary);
      font-family: 'Cascadia Code', 'Fira Code', monospace;
    }
    .subnet-meta { display: flex; gap: 5px; margin-top: 8px; flex-wrap: wrap; }
    .tag {
      font-size: 9px;
      padding: 2px 7px;
      border-radius: 6px;
      font-weight: 600;
      letter-spacing: 0.03em;
      text-transform: uppercase;
      backdrop-filter: blur(4px);
    }
    .tag.nsg { background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.25); }
    .tag.pe { background: rgba(139,92,246,0.15); color: #a78bfa; border: 1px solid rgba(139,92,246,0.25); }
    .tag.rt { background: rgba(6,182,212,0.15); color: #22d3ee; border: 1px solid rgba(6,182,212,0.25); }
    .tag.se { background: rgba(59,130,246,0.12); color: #60a5fa; border: 1px solid rgba(59,130,246,0.20); }
    .severity-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; box-shadow: 0 0 6px currentColor; }
    .severity-dot.critical { background: var(--critical); color: var(--critical); }
    .severity-dot.high { background: var(--high); color: var(--high); }
    .severity-dot.warning { background: var(--warning); color: var(--warning); }
    .severity-dot.info { background: var(--info); color: var(--info); }

    /* ─── Resource Section Headers ─── */
    .section-header {
      display: flex;
      align-items: center;
      gap: 10px;
      margin: 24px 0 12px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }
    .section-header h3 {
      font-size: 13px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .section-count {
      font-size: 10px;
      background: var(--glass);
      padding: 2px 8px;
      border-radius: 10px;
      color: var(--fg-secondary);
    }

    /* ─── Resource Cards (NSG, Firewall, PE, Peering) ─── */
    .resource-card {
      border: 1px solid var(--glass-border);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 10px;
      backdrop-filter: blur(8px);
      transition: all 0.2s ease;
      position: relative;
      overflow: hidden;
    }
    .resource-card:hover {
      transform: translateY(-2px);
      box-shadow: var(--shadow-md);
    }
    .resource-card.nsg-card { background: var(--nsg-gradient); border-color: rgba(249,115,22,0.20); cursor: pointer; }
    .resource-card.nsg-card::before { content: ''; position: absolute; top:0;left:0;bottom:0;width:3px; background: linear-gradient(180deg, #f97316, #ea580c); }
    .resource-card.fw-card { background: var(--fw-gradient); border-color: rgba(239,68,68,0.20); }
    .resource-card.fw-card::before { content: ''; position: absolute; top:0;left:0;bottom:0;width:3px; background: linear-gradient(180deg, #ef4444, #dc2626); }
    .resource-card.pe-card { background: var(--pe-gradient); border-color: rgba(139,92,246,0.20); }
    .resource-card.pe-card::before { content: ''; position: absolute; top:0;left:0;bottom:0;width:3px; background: linear-gradient(180deg, #8b5cf6, #7c3aed); }
    .resource-card .name {
      font-weight: 600; font-size: 12px;
      display: flex; align-items: center; gap: 8px;
    }
    .resource-card .detail {
      font-size: 11px; color: var(--fg-secondary); margin-top: 4px; padding-left: 30px;
    }
    .resource-icon {
      width: 22px; height: 22px;
      border-radius: 6px;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px;
      box-shadow: var(--shadow-sm);
    }
    .resource-icon.nsg { background: linear-gradient(135deg, #f97316, #ea580c); }
    .resource-icon.fw { background: linear-gradient(135deg, #ef4444, #dc2626); }
    .resource-icon.pe { background: linear-gradient(135deg, #8b5cf6, #7c3aed); }
    .resource-icon.peer { background: linear-gradient(135deg, #06b6d4, #0891b2); }

    /* ─── Peering Cards ─── */
    .peering-card {
      border: 1px dashed rgba(6,182,212,0.35);
      border-radius: 12px;
      padding: 14px;
      margin-bottom: 10px;
      background: linear-gradient(135deg, rgba(6,182,212,0.10) 0%, rgba(6,182,212,0.03) 100%);
      transition: all 0.2s ease;
    }
    .peering-card:hover { transform: translateY(-2px); box-shadow: var(--shadow-md); }
    .peering-card .name { font-weight: 600; font-size: 12px; display: flex; align-items: center; gap: 8px; }
    .peering-card .detail { font-size: 11px; color: var(--fg-secondary); margin-top: 4px; padding-left: 30px; }

    /* ─── Connection Lines ─── */
    .connection-line { stroke-width: 1.5; fill: none; opacity: 0.5; }
    .connection-line.subnet-nsg { stroke: #f97316; stroke-dasharray: 6,3; }
    .connection-line.subnet-routetable { stroke: #06b6d4; stroke-dasharray: 6,3; }
    .connection-line.peering { stroke: #8b5cf6; stroke-width: 2; }
    .connection-line.private-endpoint { stroke: #10b981; stroke-dasharray: 4,2; }
    .connection-label { font-size: 9px; fill: var(--fg-secondary); }

    /* ─── Empty State ─── */
    .empty-state {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      height: 100%; color: var(--fg-secondary); text-align: center; padding: 40px;
    }
    .empty-state .icon { font-size: 48px; margin-bottom: 16px; filter: grayscale(0.3); }
    .empty-state h2 { font-size: 16px; margin-bottom: 8px; }
    .empty-state p { font-size: 13px; max-width: 400px; opacity: 0.8; }

    /* ─── Sidebar ─── */
    .sidebar {
      width: 340px;
      border-left: 1px solid var(--border);
      background: var(--bg-secondary);
      overflow-y: auto;
      flex-shrink: 0;
    }
    .sidebar-header {
      padding: 14px 18px;
      font-weight: 700;
      font-size: 13px;
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      background: var(--bg-secondary);
      z-index: 1;
      backdrop-filter: blur(8px);
    }
    }

    .sidebar-header {
      padding: 12px 16px;
      font-weight: 600;
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      background: var(--bg-secondary);
      z-index: 1;
    }

    .finding-card {
      padding: 10px 16px;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      transition: background 0.15s;
    }

    .finding-card:hover {
      background: var(--vscode-list-hoverBackground);
    }

    .finding-title {
      font-size: 12px;
      font-weight: 600;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .finding-desc {
      font-size: 11px;
      color: var(--fg-secondary);
      line-height: 1.4;
    }

    .finding-resource {
      font-size: 10px;
      margin-top: 4px;
      font-family: monospace;
      color: var(--fg-secondary);
    }

    .severity-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      flex-shrink: 0;
    }

    .severity-dot.critical { background: var(--critical); }
    .severity-dot.high { background: var(--high); }
    .severity-dot.warning { background: var(--warning); }
    .severity-dot.info { background: var(--info); }

    /* ─── Empty State ─── */
    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      height: 100%;
      color: var(--fg-secondary);
      text-align: center;
      padding: 40px;
    }

    .empty-state .icon { font-size: 48px; margin-bottom: 16px; }
    .empty-state h2 { font-size: 16px; margin-bottom: 8px; }
    .empty-state p { font-size: 13px; max-width: 400px; }

    /* Connections/Peering */
    .peering-list, .firewall-list, .pe-list {
      margin-top: 16px;
    }

    .resource-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 8px;
      background: var(--bg-secondary);
    }

    .resource-card .name {
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .resource-card .detail {
      font-size: 11px;
      color: var(--fg-secondary);
      margin-top: 4px;
    }

    /* ─── Connection Lines ─── */
    .connection-line {
      stroke-width: 1.5;
      fill: none;
      opacity: 0.6;
    }
    .connection-line.subnet-nsg { stroke: var(--nsg-border); stroke-dasharray: 6,3; }
    .connection-line.subnet-routetable { stroke: #06b6d4; stroke-dasharray: 6,3; }
    .connection-line.peering { stroke: #8b5cf6; stroke-width: 2; }
    .connection-line.private-endpoint { stroke: #10b981; stroke-dasharray: 4,2; }

    .connection-label {
      font-size: 9px;
      fill: var(--fg-secondary);
    }

    /* ─── Peering Cards ─── */
    .peering-card {
      border: 1px dashed #8b5cf6;
      border-radius: 8px;
      padding: 10px 12px;
      margin-bottom: 8px;
      background: rgba(139, 92, 246, 0.06);
    }
    .peering-card .name { font-weight: 600; display: flex; align-items: center; gap: 6px; }
    .peering-card .detail { font-size: 11px; color: var(--fg-secondary); margin-top: 4px; }

    /* ─── Security Posture Card ─── */
    .posture-card {
      padding: 16px;
      border-bottom: 1px solid var(--border);
    }
    .score-row { display: flex; align-items: center; gap: 14px; margin-bottom: 10px; }
    .score-circle {
      width: 56px; height: 56px; border-radius: 50%;
      border: 3px solid var(--accent);
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      flex-shrink: 0;
    }
    .score-grade { font-size: 18px; font-weight: 800; line-height: 1; }
    .score-num { font-size: 10px; color: var(--fg-secondary); }
    .score-detail { flex: 1; }
    .posture-scope { font-size: 10px; color: var(--fg-secondary); margin-top: 4px; font-family: monospace; }
    .posture-icon { font-size: 24px; margin-bottom: 6px; }
    .posture-title { font-size: 14px; font-weight: 700; margin-bottom: 4px; }
    .posture-desc { font-size: 12px; color: var(--fg-secondary); line-height: 1.5; margin-bottom: 8px; }
    .posture-counts { display: flex; gap: 6px; flex-wrap: wrap; }
    .posture-critical { border-left: 4px solid var(--critical); }
    .posture-high { border-left: 4px solid var(--high); }
    .posture-warning { border-left: 4px solid var(--warning); }
    .posture-info { border-left: 4px solid var(--info); }
    .posture-good { border-left: 4px solid var(--success); }

    /* ─── Action Groups ─── */
    .action-group { border-bottom: 1px solid var(--border); }
    .group-header {
      padding: 10px 16px;
      cursor: pointer;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 4px;
      position: relative;
    }
    .group-header:hover { background: var(--vscode-list-hoverBackground); }
    .group-title { font-weight: 600; font-size: 12px; width: 100%; }
    .group-subtitle { font-size: 11px; color: var(--fg-secondary); width: calc(100% - 20px); }
    .group-chevron { position: absolute; right: 12px; top: 12px; font-size: 10px; color: var(--fg-secondary); }
    .group-body { padding: 0; }
    .group-critical .group-title { color: var(--critical); }
    .group-high .group-title { color: var(--high); }
    .group-warning .group-title { color: var(--warning); }
    .group-info .group-title { color: var(--info); }

    /* ─── Finding Card V2 ─── */
    .finding-card-v2 {
      padding: 10px 16px;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      transition: background 0.15s;
    }
    .finding-card-v2:hover { background: var(--vscode-list-hoverBackground); }
    .finding-header-v2 { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
    .finding-id { font-size: 10px; color: var(--fg-secondary); font-family: monospace; }
    .finding-title-v2 { font-size: 12px; font-weight: 600; margin-bottom: 4px; }
    .finding-guidance {
      font-size: 11px;
      color: var(--fg-primary);
      line-height: 1.5;
      margin-bottom: 6px;
      padding: 6px 8px;
      background: var(--bg-secondary);
      border-radius: 4px;
      border-left: 2px solid var(--accent);
    }
    .finding-resources {
      font-size: 10px;
      color: var(--fg-secondary);
      margin-bottom: 4px;
    }
    .finding-resources code {
      background: var(--bg-secondary);
      padding: 1px 4px;
      border-radius: 3px;
      font-size: 10px;
    }
    .finding-actions-v2 { display: flex; gap: 12px; }
    .finding-actions-v2 a {
      font-size: 11px;
      color: var(--accent);
      text-decoration: none;
      cursor: pointer;
    }
    .finding-actions-v2 a:hover { text-decoration: underline; }

    .action-badge {
      font-size: 10px;
      padding: 1px 6px;
      border-radius: 3px;
      font-weight: 700;
      white-space: nowrap;
    }
    .action-badge.action-needed { background: rgba(231,76,60,0.15); color: var(--critical); }
    .action-badge.safe { background: rgba(46,204,113,0.15); color: var(--success); }
  </style>
</head>
<body>
  <div class="toolbar">
    <span class="toolbar-title">🛡️ Azure Network Security</span>
    <button data-action="zoomIn">+ Zoom</button>
    <button data-action="zoomOut">− Zoom</button>
    <button data-action="resetView">Reset</button>
    <button data-action="generateMermaid">📐 Mermaid</button>
    <button class="export-btn" data-action="exportReport">📊 Export Report</button>
    <div class="summary" id="summary"></div>
  </div>

  <div class="main-content">
    <div class="topology-canvas" id="canvas">
      <svg id="connections-svg" style="position:absolute;top:0;left:0;width:100%;height:100%;pointer-events:none;z-index:1;overflow:visible;">
        <defs>
          <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
            <polygon points="0 0, 8 3, 0 6" fill="var(--accent, #0078d4)" opacity="0.7"/>
          </marker>
        </defs>
      </svg>
      <div id="topology-content" style="position:relative;z-index:2;"></div>
    </div>
    <div class="sidebar" id="sidebar">
      <div class="sidebar-header">�️ Security Assessment</div>
      <div id="posture-summary"></div>
      <div id="action-groups"></div>
    </div>
  </div>

  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const topology = ${topologyJson};
    const findings = ${findingsJson};

    // ─── Render Summary ───
    function renderSummary() {
      const counts = { critical: 0, high: 0, warning: 0, info: 0 };
      findings.forEach(f => counts[f.severity]++);

      document.getElementById('summary').innerHTML = [
        counts.critical > 0 ? '<span class="badge critical">' + counts.critical + ' Critical</span>' : '',
        counts.high > 0 ? '<span class="badge high">' + counts.high + ' High</span>' : '',
        counts.warning > 0 ? '<span class="badge warning">' + counts.warning + ' Warning</span>' : '',
        counts.info > 0 ? '<span class="badge info">' + counts.info + ' Info</span>' : '',
      ].filter(Boolean).join('');
    }

    // ─── Render Topology ───
    function renderTopology() {
      const canvas = document.getElementById('topology-content');

      if (topology.vnets.length === 0 && topology.nsgs.length === 0) {
        canvas.innerHTML = '<div class="empty-state">' +
          '<div class="icon">🌐</div>' +
          '<h2>No Network Resources Found</h2>' +
          '<p>Open a Bicep or ARM template file containing Azure networking resources, then run "Visualize Network Topology".</p>' +
          '</div>';
        return;
      }

      let html = '';

      // Render VNets with subnets
      topology.vnets.forEach(vnet => {
        html += '<div class="vnet-container">';
        html += '<div class="vnet-header">';
        html += '<div class="vnet-icon">🌐</div>';
        html += '<span>' + escapeHtml(vnet.name) + '</span>';
        html += '<span class="vnet-address">' + escapeHtml(vnet.addressSpace.join(', ')) + '</span>';
        if (vnet.location) {
          html += '<span class="vnet-location">📍 ' + escapeHtml(vnet.location) + '</span>';
        }
        html += '</div>';

        html += '<div class="subnet-grid">';
        vnet.subnets.forEach(subnet => {
          const subnetFindings = findings.filter(f => f.resourceName === subnet.name || f.resourceId === subnet.id);
          const hasIssues = subnetFindings.length > 0;

          html += '<div class="subnet-card' + (hasIssues ? ' has-issues' : '') + '" data-resource-id="' + escapeHtml(subnet.id) + '" data-action="subnetClick" data-id="' + escapeHtml(subnet.id) + '">';
          html += '<div class="subnet-name">';
          html += '<div class="subnet-icon">📦</div> ' + escapeHtml(subnet.name);
          if (hasIssues) {
            html += ' <span class="severity-dot critical"></span>';
          }
          html += '</div>';
          html += '<div class="subnet-prefix">' + escapeHtml(subnet.addressPrefix) + '</div>';
          html += '<div class="subnet-meta">';
          if (subnet.nsgId) {
            html += '<span class="tag nsg">🛡 NSG</span>';
          }
          if (subnet.routeTableId) {
            html += '<span class="tag rt">🔀 UDR</span>';
          }
          if (subnet.privateEndpoints && subnet.privateEndpoints.length > 0) {
            html += '<span class="tag pe">🔒 PE</span>';
          }
          subnet.serviceEndpoints.forEach(se => {
            html += '<span class="tag se">' + escapeHtml(se.replace('Microsoft.', '')) + '</span>';
          });
          html += '</div></div>';
        });
        html += '</div></div>';
      });

      // Render standalone NSGs
      const standaloneNsgs = topology.nsgs.filter(n => n.rules.length > 0);
      if (standaloneNsgs.length > 0) {
        html += '<div class="section-header"><h3>🛡️ Network Security Groups</h3><span class="section-count">' + standaloneNsgs.length + '</span></div>';
        standaloneNsgs.forEach(nsg => {
          html += '<div class="resource-card nsg-card" data-resource-id="' + escapeHtml(nsg.id) + '" data-action="showRules" data-id="' + escapeHtml(nsg.id) + '">';
          html += '<div class="name"><div class="resource-icon nsg">🛡</div> ' + escapeHtml(nsg.name) + '</div>';
          html += '<div class="detail">' + nsg.rules.length + ' security rules — click to inspect</div>';
          html += '</div>';
        });
      }

      // Render Firewalls
      if (topology.firewalls.length > 0) {
        html += '<div class="section-header"><h3>🔥 Azure Firewalls</h3><span class="section-count">' + topology.firewalls.length + '</span></div>';
        topology.firewalls.forEach(fw => {
          html += '<div class="resource-card fw-card">';
          html += '<div class="name"><div class="resource-icon fw">🔥</div> ' + escapeHtml(fw.name) + '</div>';
          html += '<div class="detail">SKU: ' + escapeHtml(fw.skuTier) + ' · Threat Intel: ' + escapeHtml(fw.threatIntelMode) + '</div>';
          html += '</div>';
        });
      }

      // Render Private Endpoints
      if (topology.privateEndpoints.length > 0) {
        html += '<div class="section-header"><h3>🔒 Private Endpoints</h3><span class="section-count">' + topology.privateEndpoints.length + '</span></div>';
        topology.privateEndpoints.forEach(pe => {
          html += '<div class="resource-card pe-card" data-resource-id="' + escapeHtml(pe.id) + '">';
          html += '<div class="name"><div class="resource-icon pe">🔒</div> ' + escapeHtml(pe.name) + '</div>';
          html += '<div class="detail">Groups: ' + escapeHtml(pe.groupIds.join(', ')) + '</div>';
          html += '</div>';
        });
      }

      // Render VNet Peerings
      const allPeerings = topology.vnets.flatMap(v => v.peerings.map(p => ({ vnetName: v.name, peering: p })));
      if (allPeerings.length > 0) {
        html += '<div class="section-header"><h3>🔗 VNet Peerings</h3><span class="section-count">' + allPeerings.length + '</span></div>';
        allPeerings.forEach(({ vnetName, peering }) => {
          html += '<div class="peering-card" data-resource-id="' + escapeHtml(peering.id) + '">';
          html += '<div class="name"><div class="resource-icon peer">🔗</div> ' + escapeHtml(peering.name) + '</div>';
          html += '<div class="detail">' + escapeHtml(vnetName) + ' ↔ ' + escapeHtml(peering.remoteVNetId) + '</div>';
          const flags = [];
          if (peering.allowForwardedTraffic) flags.push('forwarding');
          if (peering.allowGatewayTransit) flags.push('gateway transit');
          if (flags.length > 0) {
            html += '<div class="detail">Flags: ' + escapeHtml(flags.join(', ')) + '</div>';
          }
          html += '</div>';
        });
      }

      canvas.innerHTML = html;

      // Draw connection lines after DOM is rendered
      requestAnimationFrame(() => renderConnections());
    }

    // ─── Render Findings ───
    function renderFindings() {
      renderPostureSummary();
      renderActionGroups();
    }

    function renderPostureSummary() {
      const el = document.getElementById('posture-summary');
      const counts = { critical: 0, high: 0, warning: 0, info: 0 };
      findings.forEach(f => counts[f.severity]++);
      const total = findings.length;

      // Calculate posture score (100 = perfect, deduct for severity)
      const maxScore = 100;
      const deductions = counts.critical * 10 + counts.high * 5 + counts.warning * 1;
      const score = Math.max(0, Math.min(maxScore, maxScore - deductions));
      let grade, gradeColor;
      if (score >= 90) { grade = 'A'; gradeColor = 'var(--success)'; }
      else if (score >= 75) { grade = 'B'; gradeColor = '#22d3ee'; }
      else if (score >= 60) { grade = 'C'; gradeColor = 'var(--warning)'; }
      else if (score >= 40) { grade = 'D'; gradeColor = 'var(--high)'; }
      else { grade = 'F'; gradeColor = 'var(--critical)'; }

      // Topology stats
      const vnetCount = topology.vnets ? topology.vnets.length : 0;
      const nsgCount = topology.nsgs ? topology.nsgs.length : 0;
      const subnetCount = topology.vnets ? topology.vnets.reduce(function(s,v){ return s + v.subnets.length; }, 0) : 0;
      const fwCount = topology.firewalls ? topology.firewalls.length : 0;

      if (total === 0) {
        el.innerHTML = '<div class="posture-card posture-good">' +
          '<div class="score-row"><div class="score-circle" style="border-color:var(--success)"><span class="score-grade">A</span><span class="score-num">100</span></div>' +
          '<div class="score-detail"><div class="posture-title">Excellent Security Posture</div><div class="posture-desc">Zero Trust aligned. No misconfigurations detected across ' + vnetCount + ' VNets, ' + nsgCount + ' NSGs.</div></div></div>' +
          '</div>';
        return;
      }

      let postureClass, postureIcon, postureTitle, postureAction;
      if (counts.critical > 0) {
        postureClass = 'posture-critical';
        postureIcon = '🚨';
        postureTitle = 'Immediate Action Required';
        postureAction = counts.critical + ' critical issue' + (counts.critical > 1 ? 's' : '') + ' expose resources to the internet. Fix before anything else.';
      } else if (counts.high > 0) {
        postureClass = 'posture-high';
        postureIcon = '⚠️';
        postureTitle = 'Action Recommended';
        postureAction = counts.high + ' high-severity issue' + (counts.high > 1 ? 's' : '') + ' weaken your security posture. Remediate promptly.';
      } else if (counts.warning > 0) {
        postureClass = 'posture-warning';
        postureIcon = '💡';
        postureTitle = 'Good — Minor Improvements Available';
        postureAction = 'No critical or high issues. ' + counts.warning + ' best-practice improvement' + (counts.warning > 1 ? 's' : '') + ' for Zero Trust alignment.';
      } else {
        postureClass = 'posture-info';
        postureIcon = '✅';
        postureTitle = 'Strong Security Posture';
        postureAction = 'Only informational advisories. Your network follows Microsoft Zero Trust best practices.';
      }

      el.innerHTML = '<div class="posture-card ' + postureClass + '">' +
        '<div class="score-row">' +
        '<div class="score-circle" style="border-color:' + gradeColor + '"><span class="score-grade">' + grade + '</span><span class="score-num">' + score + '</span></div>' +
        '<div class="score-detail">' +
        '<div class="posture-title">' + postureIcon + ' ' + postureTitle + '</div>' +
        '<div class="posture-desc">' + postureAction + '</div>' +
        '<div class="posture-scope">' + vnetCount + ' VNets · ' + subnetCount + ' Subnets · ' + nsgCount + ' NSGs · ' + fwCount + ' Firewalls</div>' +
        '</div></div>' +
        '<div class="posture-counts">' +
        (counts.critical > 0 ? '<span class="badge critical">' + counts.critical + ' Critical</span>' : '') +
        (counts.high > 0 ? '<span class="badge high">' + counts.high + ' High</span>' : '') +
        (counts.warning > 0 ? '<span class="badge warning">' + counts.warning + ' Warning</span>' : '') +
        (counts.info > 0 ? '<span class="badge info">' + counts.info + ' Info</span>' : '') +
        '</div>' +
        '</div>';
    }

    // Action guidance per rule ID
    const ruleGuidance = {
      'NETSEC-001': { action: '🔴 FIX NOW', guidance: 'Remove SSH rule. Use Azure Bastion for secure access.', safe: false },
      'NETSEC-002': { action: '🔴 FIX NOW', guidance: 'Remove RDP rule. Use Azure Bastion or JIT access.', safe: false },
      'NETSEC-003': { action: '🔴 FIX NOW', guidance: 'Replace with specific allow rules for required traffic only.', safe: false },
      'NETSEC-004': { action: '🟡 IMPROVE', guidance: 'Add explicit deny-all at priority 4096. Aids auditing and flow logs.', safe: true },
      'NETSEC-005': { action: '🟠 REVIEW', guidance: 'Restrict source to specific IPs or Service Tags.', safe: false },
      'NETSEC-006': { action: '🟠 REVIEW', guidance: 'Restrict outbound to required destinations and ports.', safe: false },
      'NETSEC-007': { action: '🟠 REVIEW', guidance: 'Attach an NSG with least-privilege rules to this subnet.', safe: false },
      'NETSEC-008': { action: '🟡 IMPROVE', guidance: 'Narrow port range to only the ports your app actually needs.', safe: true },
      'NETSEC-009': { action: '🟡 IMPROVE', guidance: 'Remove catch-all allow rule. Use JIT access if temporary.', safe: false },
      'NETSEC-010': { action: '🟠 REVIEW', guidance: 'Set threatIntelMode to Deny to block known malicious IPs.', safe: false },
      'NETSEC-011': { action: '✅ ADVISORY', guidance: 'Enable VNet/NSG flow logs for visibility. Not a vulnerability.', safe: true },
      'NETSEC-012': { action: '✅ ADVISORY', guidance: 'Consider Service Tags instead of hardcoded IPs — auto-updated by Microsoft.', safe: true },
      'NETSEC-013': { action: '✅ ADVISORY', guidance: 'Review overlapping rules — higher priority rule wins. Confirm intent.', safe: true },
      'NETSEC-014': { action: '🟡 IMPROVE', guidance: 'Route through Azure Firewall for inspection instead of direct internet.', safe: false },
      'NETSEC-015': { action: '🟠 REVIEW', guidance: 'Enable Azure DDoS Protection on this VNet. Required for Zero Trust.', safe: false },
      'NETSEC-016': { action: '🟡 IMPROVE', guidance: 'Add AzureBastionSubnet and deploy Bastion for secure VM access without open ports.', safe: true },
      'NETSEC-017': { action: '🟡 IMPROVE', guidance: 'Add Private DNS Zone Group so DNS resolves to the private IP, not public.', safe: true },
      'NETSEC-018': { action: '🟠 REVIEW', guidance: 'Enable WAF (WAF_v2 SKU) on this Application Gateway. Required for Zero Trust.', safe: false },
      'NETSEC-019': { action: '🟡 IMPROVE', guidance: 'Switch WAF from Detection to Prevention mode to actively block attacks.', safe: false },
      'NETSEC-020': { action: '🔴 FIX NOW', guidance: 'Set minProtocolVersion to TLSv1_2. TLS 1.0/1.1 are deprecated.', safe: false },
      'NETSEC-021': { action: '🟡 IMPROVE', guidance: 'Add route table with 0.0.0.0/0 → Firewall for forced tunneling.', safe: false },
      'NETSEC-022': { action: '🟠 REVIEW', guidance: 'Upgrade from Basic SKU — lacks IKEv2, custom crypto, RADIUS auth.', safe: false },
      'NETSEC-023': { action: '🟡 IMPROVE', guidance: 'Switch to RouteBased VPN for IKEv2, multiple tunnels, custom IPsec.', safe: false },
      'NETSEC-024': { action: '✅ ADVISORY', guidance: 'Consider Application Security Groups for microsegmentation instead of IP CIDRs.', safe: true },
      'NETSEC-025': { action: '✅ ADVISORY', guidance: 'Add forced tunneling UDR (0.0.0.0/0 → Firewall) on workload subnets.', safe: true },
      'NETSEC-026': { action: '✅ ADVISORY', guidance: 'Enable DDoS Protection on public IP addresses or parent VNet.', safe: true },
    };

    function renderActionGroups() {
      const el = document.getElementById('action-groups');
      if (findings.length === 0) { el.innerHTML = ''; return; }

      // Group findings into action categories
      const fixNow = findings.filter(f => ['critical'].includes(f.severity));
      const review = findings.filter(f => ['high'].includes(f.severity));
      const improve = findings.filter(f => ['warning'].includes(f.severity));
      const advisory = findings.filter(f => ['info'].includes(f.severity));

      let html = '';

      if (fixNow.length > 0) {
        html += renderGroup('🚨 Fix Immediately', 'These expose your network to the internet.', fixNow, 'group-critical');
      }
      if (review.length > 0) {
        html += renderGroup('⚠️ Review & Remediate', 'These weaken your security posture.', review, 'group-high');
      }
      if (improve.length > 0) {
        html += renderGroup('💡 Best Practice Improvements', 'Not vulnerabilities — but improvements for defense-in-depth.', improve, 'group-warning');
      }
      if (advisory.length > 0) {
        html += renderGroup('ℹ️ Informational — Safe to Acknowledge', 'Advisories only — no action required. Your configuration is safe.', advisory, 'group-info');
      }

      el.innerHTML = html;
    }

    function renderGroup(title, subtitle, groupFindings, cssClass) {
      // Deduplicate by rule ID and aggregate affected resources
      const byRule = {};
      groupFindings.forEach(f => {
        if (!byRule[f.id]) {
          byRule[f.id] = { finding: f, resources: [] };
        }
        byRule[f.id].resources.push(f.resourceName);
      });

      let html = '<div class="action-group ' + cssClass + '">';
      html += '<div class="group-header" data-action="toggleGroup">';
      html += '<span class="group-title">' + title + ' (' + groupFindings.length + ')</span>';
      html += '<span class="group-subtitle">' + subtitle + '</span>';
      html += '<span class="group-chevron">▼</span>';
      html += '</div>';
      html += '<div class="group-body">';

      Object.keys(byRule).forEach(ruleId => {
        const { finding, resources } = byRule[ruleId];
        const guide = ruleGuidance[ruleId] || { action: '❓ REVIEW', guidance: finding.recommendation, safe: false };
        const uniqueResources = [...new Set(resources)];

        html += '<div class="finding-card-v2" data-action="findingClick" data-id="' + escapeHtml(finding.id) + '">';
        html += '<div class="finding-header-v2">';
        html += '<span class="action-badge ' + (guide.safe ? 'safe' : 'action-needed') + '">' + guide.action + '</span>';
        html += '<span class="finding-id">' + escapeHtml(ruleId) + '</span>';
        html += '</div>';
        html += '<div class="finding-title-v2">' + escapeHtml(finding.title) + '</div>';
        html += '<div class="finding-guidance">' + escapeHtml(guide.guidance) + '</div>';
        html += '<div class="finding-resources">' + uniqueResources.length + ' resource' + (uniqueResources.length > 1 ? 's' : '') + ': ';
        html += uniqueResources.slice(0, 5).map(r => '<code>' + escapeHtml(r) + '</code>').join(', ');
        if (uniqueResources.length > 5) html += ' +' + (uniqueResources.length - 5) + ' more';
        html += '</div>';
        html += '<div class="finding-actions-v2">';
        html += '<a class="ms-learn-link" data-url="' + escapeHtml(finding.learnMoreUrl) + '">📖 How to Fix (MS Learn)</a>';
        html += '</div>';
        html += '</div>';
      });

      html += '</div></div>';
      return html;
    }

    function toggleGroup(header) {
      const body = header.nextElementSibling;
      const chevron = header.querySelector('.group-chevron');
      if (body.style.display === 'none') {
        body.style.display = 'block';
        chevron.textContent = '▼';
      } else {
        body.style.display = 'none';
        chevron.textContent = '▶';
      }
    }

    function openLink(url) {
      vscode.postMessage({ command: 'openLink', url: url });
    }

    // ─── Event Handlers ───
    function onSubnetClick(subnetId) {
      // Highlight related findings
      const related = findings.filter(f => f.resourceId === subnetId || f.resourceName === subnetId);
      if (related.length > 0) {
        onFindingClick(related[0].id);
      }
    }

    function showRules(nsgId) {
      vscode.postMessage({ command: 'showRules', resourceId: nsgId });
    }

    function onFindingClick(findingId) {
      vscode.postMessage({ command: 'showFinding', findingId: findingId });
    }

    function exportReport() {
      vscode.postMessage({ command: 'exportReport' });
    }

    function generateMermaid() {
      vscode.postMessage({ command: 'generateMermaid' });
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ─── Render Connection Lines ───
    function renderConnections() {
      const svg = document.getElementById('connections-svg');
      if (!svg || !topology.connections || topology.connections.length === 0) return;

      // Clear previous lines
      const existingLines = svg.querySelectorAll('.connection-line, .connection-label');
      existingLines.forEach(el => el.remove());

      const canvasRect = document.getElementById('canvas').getBoundingClientRect();

      topology.connections.forEach(conn => {
        const sourceEl = document.querySelector('[data-resource-id="' + conn.sourceId + '"]');
        const targetEl = document.querySelector('[data-resource-id="' + conn.targetId + '"]');

        if (!sourceEl || !targetEl) return;

        const sourceRect = sourceEl.getBoundingClientRect();
        const targetRect = targetEl.getBoundingClientRect();

        const x1 = sourceRect.left + sourceRect.width / 2 - canvasRect.left;
        const y1 = sourceRect.top + sourceRect.height / 2 - canvasRect.top;
        const x2 = targetRect.left + targetRect.width / 2 - canvasRect.left;
        const y2 = targetRect.top + targetRect.height / 2 - canvasRect.top;

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', x1);
        line.setAttribute('y1', y1);
        line.setAttribute('x2', x2);
        line.setAttribute('y2', y2);
        line.setAttribute('marker-end', 'url(#arrowhead)');
        line.classList.add('connection-line', conn.connectionType);
        svg.appendChild(line);

        if (conn.label) {
          const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
          text.setAttribute('x', (x1 + x2) / 2);
          text.setAttribute('y', (y1 + y2) / 2 - 4);
          text.setAttribute('text-anchor', 'middle');
          text.classList.add('connection-label');
          text.textContent = conn.label;
          svg.appendChild(text);
        }
      });
    }

    let currentZoom = 1;
    function zoomIn() {
      currentZoom = Math.min(currentZoom + 0.1, 2);
      document.getElementById('topology-content').style.transform = 'scale(' + currentZoom + ')';
      document.getElementById('topology-content').style.transformOrigin = 'top left';
      requestAnimationFrame(() => renderConnections());
    }
    function zoomOut() {
      currentZoom = Math.max(currentZoom - 0.1, 0.5);
      document.getElementById('topology-content').style.transform = 'scale(' + currentZoom + ')';
      document.getElementById('topology-content').style.transformOrigin = 'top left';
      requestAnimationFrame(() => renderConnections());
    }
    function resetView() {
      currentZoom = 1;
      document.getElementById('topology-content').style.transform = 'scale(1)';
      requestAnimationFrame(() => renderConnections());
    }

    // ─── Initialize ───
    renderSummary();
    renderTopology();
    renderFindings();

    // Single delegated event handler for ALL clicks (CSP blocks inline onclick)
    document.addEventListener('click', function(e) {
      // MS Learn links
      const link = e.target.closest('.ms-learn-link');
      if (link) {
        e.preventDefault();
        e.stopPropagation();
        const url = link.getAttribute('data-url');
        if (url) { vscode.postMessage({ command: 'openLink', url: url }); }
        return;
      }

      // data-action elements (buttons, cards, headers)
      const actionEl = e.target.closest('[data-action]');
      if (!actionEl) return;

      const action = actionEl.getAttribute('data-action');
      const id = actionEl.getAttribute('data-id');

      switch (action) {
        case 'zoomIn': zoomIn(); break;
        case 'zoomOut': zoomOut(); break;
        case 'resetView': resetView(); break;
        case 'exportReport': exportReport(); break;
        case 'generateMermaid': generateMermaid(); break;
        case 'subnetClick': onSubnetClick(id); break;
        case 'showRules': showRules(id); break;
        case 'findingClick': onFindingClick(id); break;
        case 'toggleGroup':
          const body = actionEl.nextElementSibling;
          const chevron = actionEl.querySelector('.group-chevron');
          if (body.style.display === 'none') {
            body.style.display = 'block';
            if (chevron) chevron.textContent = '▼';
          } else {
            body.style.display = 'none';
            if (chevron) chevron.textContent = '▶';
          }
          break;
      }
    });
  </script>
</body>
</html>`;
  }
}

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
