/**
 * Security report generator.
 * Exports findings as HTML, Markdown, or JSON reports.
 *
 * Microsoft Learn Reference:
 * - Azure Security Benchmark: https://learn.microsoft.com/security/benchmark/azure/overview
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { SecurityFinding, NetworkTopology, Severity } from '../models/networkModel';

export type ReportFormat = 'html' | 'markdown' | 'json' | 'csv';

export async function exportSecurityReport(
  topology: NetworkTopology,
  findings: SecurityFinding[],
  format: ReportFormat,
  outputUri?: vscode.Uri
): Promise<string> {
  let content: string;

  switch (format) {
    case 'html':
      content = generateHtmlReport(topology, findings);
      break;
    case 'markdown':
      content = generateMarkdownReport(topology, findings);
      break;
    case 'json':
      content = generateJsonReport(topology, findings);
      break;
    case 'csv':
      content = generateCsvReport(topology, findings);
      break;
  }

  if (outputUri) {
    await vscode.workspace.fs.writeFile(outputUri, Buffer.from(content, 'utf-8'));
  }

  return content;
}

// ─── Summary Stats ──────────────────────────────────────────────────────────

function getSeverityCounts(findings: SecurityFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, warning: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity]++;
  }
  return counts;
}

// ─── HTML Report ────────────────────────────────────────────────────────────

function generateHtmlReport(topology: NetworkTopology, findings: SecurityFinding[]): string {
  const counts = getSeverityCounts(findings);
  const timestamp = new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Azure Network Security Report</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
    .container { max-width: 960px; margin: 0 auto; padding: 24px; }
    header { background: linear-gradient(135deg, #0078d4, #005a9e); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }
    header h1 { font-size: 24px; margin-bottom: 8px; }
    header .subtitle { opacity: 0.9; font-size: 14px; }
    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
    .summary-card { background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .summary-card .count { font-size: 28px; font-weight: 700; }
    .summary-card .label { font-size: 12px; color: #666; text-transform: uppercase; }
    .summary-card.critical .count { color: #e74c3c; }
    .summary-card.high .count { color: #e67e22; }
    .summary-card.warning .count { color: #f39c12; }
    .summary-card.info .count { color: #3498db; }
    .section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .section h2 { font-size: 16px; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid #eee; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #f8f9fa; font-weight: 600; }
    .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; color: white; }
    .severity-badge.critical { background: #e74c3c; }
    .severity-badge.high { background: #e67e22; }
    .severity-badge.warning { background: #f39c12; color: #1a1a1a; }
    .severity-badge.info { background: #3498db; }
    .learn-link { color: #0078d4; text-decoration: none; }
    .learn-link:hover { text-decoration: underline; }
    footer { text-align: center; padding: 16px; color: #999; font-size: 12px; }
    .topology-summary { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 8px; }
    .topo-item { padding: 8px 12px; border-radius: 6px; background: #f8f9fa; font-size: 13px; }
    .topo-item .label { font-weight: 600; }
  </style>
</head>
<body>
<div class="container">
  <header>
    <h1>🛡️ Azure Network Security Report</h1>
    <div class="subtitle">Generated: ${timestamp} | Azure Network Security Visualizer</div>
  </header>

  <div class="summary-grid">
    <div class="summary-card critical"><div class="count">${counts.critical}</div><div class="label">Critical</div></div>
    <div class="summary-card high"><div class="count">${counts.high}</div><div class="label">High</div></div>
    <div class="summary-card warning"><div class="count">${counts.warning}</div><div class="label">Warning</div></div>
    <div class="summary-card info"><div class="count">${counts.info}</div><div class="label">Info</div></div>
  </div>

  <div class="section">
    <h2>📊 Topology Summary</h2>
    <div class="topology-summary">
      <div class="topo-item"><span class="label">${topology.vnets.length}</span> Virtual Networks</div>
      <div class="topo-item"><span class="label">${topology.vnets.reduce((sum, v) => sum + v.subnets.length, 0)}</span> Subnets</div>
      <div class="topo-item"><span class="label">${topology.nsgs.length}</span> NSGs</div>
      <div class="topo-item"><span class="label">${topology.nsgs.reduce((sum, n) => sum + n.rules.length, 0)}</span> Security Rules</div>
      <div class="topo-item"><span class="label">${topology.routeTables.length}</span> Route Tables</div>
      <div class="topo-item"><span class="label">${topology.privateEndpoints.length}</span> Private Endpoints</div>
      <div class="topo-item"><span class="label">${topology.firewalls.length}</span> Firewalls</div>
    </div>
  </div>

  <div class="section">
    <h2>🔍 Security Findings (${findings.length})</h2>
    ${findings.length === 0 ? '<p>✅ No security issues found. Great job!</p>' : `
    <table>
      <thead>
        <tr><th>ID</th><th>Severity</th><th>Finding</th><th>Resource</th><th>Recommendation</th><th>Reference</th></tr>
      </thead>
      <tbody>
        ${findings.map(f => `
        <tr>
          <td><code>${f.id}</code></td>
          <td><span class="severity-badge ${f.severity}">${f.severity}</span></td>
          <td>${escapeHtml(f.title)}</td>
          <td><code>${escapeHtml(f.resourceName)}</code></td>
          <td>${escapeHtml(f.recommendation)}</td>
          <td><a class="learn-link" href="${f.learnMoreUrl}" target="_blank">MS Learn ↗</a></td>
        </tr>`).join('')}
      </tbody>
    </table>`}
  </div>

  <footer>
    Azure Network Security Visualizer by KimVaddi | 
    <a class="learn-link" href="https://learn.microsoft.com/security/benchmark/azure/overview">Azure Security Benchmark</a> |
    <a class="learn-link" href="https://learn.microsoft.com/azure/security/fundamentals/network-best-practices">Network Best Practices</a>
  </footer>
</div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Markdown Report ────────────────────────────────────────────────────────

function generateMarkdownReport(topology: NetworkTopology, findings: SecurityFinding[]): string {
  const counts = getSeverityCounts(findings);
  const timestamp = new Date().toISOString();

  let md = `# 🛡️ Azure Network Security Report

> Generated: ${timestamp}  
> Tool: Azure Network Security Visualizer

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | ${counts.critical} |
| 🟠 High | ${counts.high} |
| 🟡 Warning | ${counts.warning} |
| 🔵 Info | ${counts.info} |
| **Total** | **${findings.length}** |

## Topology

- **${topology.vnets.length}** Virtual Networks
- **${topology.vnets.reduce((sum, v) => sum + v.subnets.length, 0)}** Subnets
- **${topology.nsgs.length}** NSGs (${topology.nsgs.reduce((sum, n) => sum + n.rules.length, 0)} rules)
- **${topology.routeTables.length}** Route Tables
- **${topology.privateEndpoints.length}** Private Endpoints
- **${topology.firewalls.length}** Firewalls

## Findings

`;

  if (findings.length === 0) {
    md += '✅ No security issues found.\n';
  } else {
    for (const f of findings) {
      const severityEmoji = { critical: '🔴', high: '🟠', warning: '🟡', info: '🔵' }[f.severity];
      md += `### ${severityEmoji} [${f.id}] ${f.title}

- **Severity**: ${f.severity}
- **Resource**: \`${f.resourceName}\` (${f.resourceType})
- **Description**: ${f.description}
- **Recommendation**: ${f.recommendation}
- **Reference**: [Microsoft Learn](${f.learnMoreUrl})
${f.evidence ? `- **Evidence**: \`${f.evidence}\`` : ''}
${f.filePath ? `- **Source**: ${f.filePath}${f.line ? `:${f.line}` : ''}` : ''}

---

`;
    }
  }

  md += `## References

- [Azure Security Benchmark](https://learn.microsoft.com/security/benchmark/azure/overview)
- [Network Security Best Practices](https://learn.microsoft.com/azure/security/fundamentals/network-best-practices)
- [NSG Overview](https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview)
- [Traffic Analytics](https://learn.microsoft.com/azure/network-watcher/traffic-analytics-usage-scenarios)
- [VNet Security](https://learn.microsoft.com/azure/virtual-network/secure-virtual-network)
`;

  return md;
}

// ─── JSON Report ────────────────────────────────────────────────────────────

function generateJsonReport(topology: NetworkTopology, findings: SecurityFinding[]): string {
  return JSON.stringify(
    {
      reportVersion: '1.0',
      generatedAt: new Date().toISOString(),
      tool: 'Azure Network Security Visualizer',
      summary: getSeverityCounts(findings),
      topologySummary: {
        vnets: topology.vnets.length,
        subnets: topology.vnets.reduce((sum, v) => sum + v.subnets.length, 0),
        nsgs: topology.nsgs.length,
        securityRules: topology.nsgs.reduce((sum, n) => sum + n.rules.length, 0),
        routeTables: topology.routeTables.length,
        privateEndpoints: topology.privateEndpoints.length,
        firewalls: topology.firewalls.length,
      },
      findings,
    },
    null,
    2
  );
}

// ─── CSV Report (opens in Excel) ────────────────────────────────────────────

function generateCsvReport(_topology: NetworkTopology, findings: SecurityFinding[]): string {
  const headers = [
    'Rule ID',
    'Severity',
    'Title',
    'Description',
    'Recommendation',
    'Resource Name',
    'Resource Type',
    'Resource ID',
    'Evidence',
    'Source File',
    'Line',
    'MS Learn Link',
  ];

  const rows = findings.map(f => [
    f.id,
    f.severity,
    f.title,
    f.description,
    f.recommendation,
    f.resourceName,
    f.resourceType,
    f.resourceId,
    f.evidence ?? '',
    f.filePath ?? '',
    f.line?.toString() ?? '',
    f.learnMoreUrl,
  ]);

  // BOM for Excel UTF-8 compatibility
  const bom = '\uFEFF';
  const csvLine = (cols: string[]) => cols.map(c => '"' + c.replace(/"/g, '""') + '"').join(',');

  return bom + [csvLine(headers), ...rows.map(csvLine)].join('\n');
}
