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
      --fg-primary: var(--vscode-editor-foreground);
      --fg-secondary: var(--vscode-descriptionForeground);
      --border: var(--vscode-panel-border);
      --accent: var(--vscode-focusBorder);
      --critical: #e74c3c;
      --high: #e67e22;
      --warning: #f39c12;
      --info: #3498db;
      --success: #2ecc71;
      --vnet-bg: rgba(59, 130, 246, 0.08);
      --subnet-bg: rgba(16, 185, 129, 0.08);
      --nsg-border: #e67e22;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: var(--bg-primary);
      color: var(--fg-primary);
      font-family: var(--vscode-font-family, 'Segoe UI', sans-serif);
      font-size: var(--vscode-font-size, 13px);
      overflow: hidden;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }

    .toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }

    .toolbar button {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 4px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
    }

    .toolbar button:hover {
      background: var(--vscode-button-hoverBackground);
    }

    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 11px;
      font-weight: 600;
    }

    .badge.critical { background: var(--critical); color: white; }
    .badge.high { background: var(--high); color: white; }
    .badge.warning { background: var(--warning); color: #1a1a1a; }
    .badge.info { background: var(--info); color: white; }

    .summary {
      display: flex;
      gap: 12px;
      margin-left: auto;
    }

    .main-content {
      display: flex;
      flex: 1;
      overflow: hidden;
    }

    /* ─── Topology Canvas ─── */
    .topology-canvas {
      flex: 1;
      overflow: auto;
      padding: 24px;
      position: relative;
    }

    .vnet-container {
      border: 2px solid #3b82f6;
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
      background: var(--vnet-bg);
    }

    .vnet-header {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 12px;
      font-size: 14px;
      font-weight: 600;
    }

    .vnet-header .icon { font-size: 18px; }
    .vnet-address { font-size: 11px; color: var(--fg-secondary); font-weight: normal; }

    .subnet-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 12px;
    }

    .subnet-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      background: var(--subnet-bg);
      cursor: pointer;
      transition: box-shadow 0.2s;
    }

    .subnet-card:hover {
      box-shadow: 0 0 0 2px var(--accent);
    }

    .subnet-card.has-issues {
      border-left: 3px solid var(--critical);
    }

    .subnet-name {
      font-weight: 600;
      margin-bottom: 4px;
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .subnet-prefix {
      font-size: 11px;
      color: var(--fg-secondary);
      font-family: monospace;
    }

    .subnet-meta {
      display: flex;
      gap: 6px;
      margin-top: 8px;
      flex-wrap: wrap;
    }

    .tag {
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 4px;
      background: var(--bg-secondary);
      border: 1px solid var(--border);
    }

    .tag.nsg { border-color: var(--nsg-border); color: var(--nsg-border); }
    .tag.pe { border-color: #8b5cf6; color: #8b5cf6; }
    .tag.rt { border-color: #06b6d4; color: #06b6d4; }

    /* ─── Sidebar (Findings) ─── */
    .sidebar {
      width: 320px;
      border-left: 1px solid var(--border);
      background: var(--bg-secondary);
      overflow-y: auto;
      flex-shrink: 0;
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
  </style>
</head>
<body>
  <div class="toolbar">
    <span style="font-weight:600;">🛡️ Azure Network Security Visualizer</span>
    <button onclick="zoomIn()">+ Zoom</button>
    <button onclick="zoomOut()">- Zoom</button>
    <button onclick="resetView()">Reset</button>
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
      <div class="sidebar-header">🔍 Security Findings</div>
      <div id="findings-list"></div>
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
        html += '<span class="icon">🌐</span>';
        html += '<span>' + escapeHtml(vnet.name) + '</span>';
        html += '<span class="vnet-address">' + escapeHtml(vnet.addressSpace.join(', ')) + '</span>';
        if (vnet.location) {
          html += '<span class="tag">' + escapeHtml(vnet.location) + '</span>';
        }
        html += '</div>';

        html += '<div class="subnet-grid">';
        vnet.subnets.forEach(subnet => {
          const subnetFindings = findings.filter(f => f.resourceName === subnet.name || f.resourceId === subnet.id);
          const hasIssues = subnetFindings.length > 0;

          html += '<div class="subnet-card' + (hasIssues ? ' has-issues' : '') + '" data-resource-id="' + escapeHtml(subnet.id) + '" onclick="onSubnetClick(\\'' + escapeHtml(subnet.id) + '\\')">';
          html += '<div class="subnet-name">';
          html += '<span>📦</span> ' + escapeHtml(subnet.name);
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
            html += '<span class="tag rt">🔀 Route Table</span>';
          }
          if (subnet.privateEndpoints && subnet.privateEndpoints.length > 0) {
            html += '<span class="tag pe">🔒 PE</span>';
          }
          subnet.serviceEndpoints.forEach(se => {
            html += '<span class="tag">' + escapeHtml(se.replace('Microsoft.', '')) + '</span>';
          });
          html += '</div></div>';
        });
        html += '</div></div>';
      });

      // Render standalone NSGs (not attached to VNets)
      const standaloneNsgs = topology.nsgs.filter(n => n.rules.length > 0);
      if (standaloneNsgs.length > 0) {
        html += '<h3 style="margin:16px 0 8px;">🛡️ Network Security Groups</h3>';
        standaloneNsgs.forEach(nsg => {
          html += '<div class="resource-card" data-resource-id="' + escapeHtml(nsg.id) + '" onclick="showRules(\\'' + escapeHtml(nsg.id) + '\\')" style="cursor:pointer">';
          html += '<div class="name">🛡️ ' + escapeHtml(nsg.name) + '</div>';
          html += '<div class="detail">' + nsg.rules.length + ' rules</div>';
          html += '</div>';
        });
      }

      // Render Firewalls
      if (topology.firewalls.length > 0) {
        html += '<h3 style="margin:16px 0 8px;">🔥 Azure Firewalls</h3>';
        topology.firewalls.forEach(fw => {
          html += '<div class="resource-card">';
          html += '<div class="name">🔥 ' + escapeHtml(fw.name) + '</div>';
          html += '<div class="detail">SKU: ' + escapeHtml(fw.skuTier) + ' | Threat Intel: ' + escapeHtml(fw.threatIntelMode) + '</div>';
          html += '</div>';
        });
      }

      // Render Private Endpoints
      if (topology.privateEndpoints.length > 0) {
        html += '<h3 style="margin:16px 0 8px;">🔒 Private Endpoints</h3>';
        topology.privateEndpoints.forEach(pe => {
          html += '<div class="resource-card" data-resource-id="' + escapeHtml(pe.id) + '">';
          html += '<div class="name">🔒 ' + escapeHtml(pe.name) + '</div>';
          html += '<div class="detail">Groups: ' + escapeHtml(pe.groupIds.join(', ')) + '</div>';
          html += '</div>';
        });
      }

      // Render VNet Peerings
      const allPeerings = topology.vnets.flatMap(v => v.peerings.map(p => ({ vnetName: v.name, peering: p })));
      if (allPeerings.length > 0) {
        html += '<h3 style="margin:16px 0 8px;">🔗 VNet Peerings</h3>';
        allPeerings.forEach(({ vnetName, peering }) => {
          html += '<div class="peering-card" data-resource-id="' + escapeHtml(peering.id) + '">';
          html += '<div class="name">🔗 ' + escapeHtml(peering.name) + '</div>';
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
      const list = document.getElementById('findings-list');
      if (findings.length === 0) {
        list.innerHTML = '<div style="padding:16px;color:var(--fg-secondary);text-align:center;">✅ No security issues found</div>';
        return;
      }

      list.innerHTML = findings.map(f => {
        return '<div class="finding-card" onclick="onFindingClick(\\'' + escapeHtml(f.id) + '\\')">' +
          '<div class="finding-title">' +
          '<span class="severity-dot ' + f.severity + '"></span>' +
          '<span>[' + escapeHtml(f.id) + '] ' + escapeHtml(f.title) + '</span>' +
          '</div>' +
          '<div class="finding-desc">' + escapeHtml(f.description).substring(0, 120) + '...</div>' +
          '<div class="finding-resource">' + escapeHtml(f.resourceName) + '</div>' +
          '</div>';
      }).join('');
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
