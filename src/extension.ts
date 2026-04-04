/**
 * Azure Network Security Visualizer — VS Code Extension Entry Point
 *
 * Parses Bicep/ARM networking resources and renders an interactive topology
 * diagram with security analysis. Flags misconfigurations before deployment.
 *
 * Microsoft Learn References:
 * - NSG Best Practices: https://learn.microsoft.com/azure/security/fundamentals/network-best-practices
 * - Network Security Benchmark: https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-network-security
 * - VNet Security: https://learn.microsoft.com/azure/virtual-network/secure-virtual-network
 */

import * as vscode from 'vscode';
import * as path from 'path';
import { parseBicepFile } from './parsers/bicepParser';
import { parseArmTemplate, isArmTemplate } from './parsers/armParser';
import { analyzeTopology } from './analyzers/securityAnalyzer';
import { TopologyWebviewProvider } from './webview/webviewProvider';
import { exportSecurityReport, ReportFormat } from './reports/reportGenerator';
// Azure modules are lazy-loaded to avoid crashing activation if SDKs have issues
import type { AzureSession } from './azure/azureAuth';
import {
  NetworkTopology,
  SecurityFinding,
  ParseResult,
  TopologyConnection,
} from './models/networkModel';

// ─── State ──────────────────────────────────────────────────────────────────

let webviewProvider: TopologyWebviewProvider;
let lastParseResult: ParseResult | undefined;
let azureSession: AzureSession | undefined;
let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let findingsTreeProvider: FindingsTreeDataProvider;

// ─── Activation ─────────────────────────────────────────────────────────────

export function activate(context: vscode.ExtensionContext) {
  console.log('Azure Network Security Visualizer activated');

  webviewProvider = new TopologyWebviewProvider(context.extensionUri);
  diagnosticCollection = vscode.languages.createDiagnosticCollection('azureNetSec');
  context.subscriptions.push(diagnosticCollection);

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'azureNetSec.visualize';
  statusBarItem.text = '$(shield) NetSec';
  statusBarItem.tooltip = 'Azure Network Security Visualizer';
  context.subscriptions.push(statusBarItem);
  statusBarItem.show();

  // Tree view for findings
  findingsTreeProvider = new FindingsTreeDataProvider();
  vscode.window.registerTreeDataProvider('azureNetSec.findings', findingsTreeProvider);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('azureNetSec.visualize', () => commandVisualize()),
    vscode.commands.registerCommand('azureNetSec.analyzeFile', () => commandAnalyzeFile()),
    vscode.commands.registerCommand('azureNetSec.analyzeWorkspace', () => commandAnalyzeWorkspace()),
    vscode.commands.registerCommand('azureNetSec.exportReport', () => commandExportReport()),
    vscode.commands.registerCommand('azureNetSec.showEffectiveRules', () => commandShowEffectiveRules()),
    vscode.commands.registerCommand('azureNetSec.connectAzure', () => commandConnectAzure()),
    vscode.commands.registerCommand('azureNetSec.visualizeLive', () => commandVisualizeLive()),
  );

  // Auto-analyze on save (if enabled)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const config = vscode.workspace.getConfiguration('azureNetSec');
      if (config.get<boolean>('autoAnalyzeOnSave', true)) {
        if (isSupportedFile(doc)) {
          analyzeAndUpdateDiagnostics(doc);
        }
      }
    })
  );

  // Analyze any currently open supported files
  if (vscode.window.activeTextEditor && isSupportedFile(vscode.window.activeTextEditor.document)) {
    analyzeAndUpdateDiagnostics(vscode.window.activeTextEditor.document);
  }
}

export function deactivate() {
  diagnosticCollection.dispose();
  statusBarItem.dispose();
}

// ─── Command: Visualize ─────────────────────────────────────────────────────

async function commandVisualize(): Promise<void> {
  const result = await parseWorkspace();
  if (!result) { return; }

  lastParseResult = result;
  webviewProvider.show(result.topology, result.findings);
  findingsTreeProvider.update(result.findings);
  updateStatusBar(result.findings);
  updateDiagnostics(result);

  const counts = { critical: 0, high: 0, warning: 0, info: 0 };
  result.findings.forEach(f => counts[f.severity as keyof typeof counts]++);

  vscode.window.showInformationMessage(
    `Network topology visualized: ${result.topology.vnets.length} VNets, ${result.topology.nsgs.length} NSGs, ${result.findings.length} findings (${counts.critical} critical, ${counts.high} high)`
  );
}

// ─── Command: Analyze File ──────────────────────────────────────────────────

async function commandAnalyzeFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('No active editor. Open a Bicep or ARM template file.');
    return;
  }

  if (!isSupportedFile(editor.document)) {
    vscode.window.showWarningMessage('Current file is not a Bicep or ARM template file.');
    return;
  }

  await analyzeAndUpdateDiagnostics(editor.document);
}

// ─── Command: Analyze Workspace ─────────────────────────────────────────────

async function commandAnalyzeWorkspace(): Promise<void> {
  const result = await parseWorkspace();
  if (!result) { return; }

  lastParseResult = result;
  findingsTreeProvider.update(result.findings);
  updateStatusBar(result.findings);
  updateDiagnostics(result);

  const counts = { critical: 0, high: 0, warning: 0, info: 0 };
  result.findings.forEach(f => counts[f.severity as keyof typeof counts]++);

  const msg = `Workspace analysis complete: ${result.parsedFiles.length} files, ${result.topology.vnets.length} VNets, ${result.topology.nsgs.length} NSGs, ${result.findings.length} findings (${counts.critical} critical, ${counts.high} high)`;

  const action = await vscode.window.showInformationMessage(msg, 'View Topology', 'Export Report');
  if (action === 'View Topology') {
    webviewProvider.show(result.topology, result.findings);
  } else if (action === 'Export Report') {
    await commandExportReport();
  }
}

// ─── Command: Export Report ─────────────────────────────────────────────────

async function commandExportReport(): Promise<void> {
  if (!lastParseResult) {
    // Parse first
    lastParseResult = await parseWorkspace();
    if (!lastParseResult) { return; }
  }

  const config = vscode.workspace.getConfiguration('azureNetSec');
  const defaultFormat = config.get<ReportFormat>('reportFormat', 'html');

  const format = await vscode.window.showQuickPick(
    [
      { label: '📊 CSV (Excel)', description: 'Opens directly in Excel — sortable, filterable', value: 'csv' as ReportFormat },
      { label: '🌐 HTML Report', description: 'Rich visual report — print to PDF from browser', value: 'html' as ReportFormat },
      { label: '📝 Markdown Report', description: 'For pull requests, wikis, Git repos', value: 'markdown' as ReportFormat },
      { label: '🔧 JSON Report', description: 'Machine-readable for CI/CD pipelines', value: 'json' as ReportFormat },
    ],
    { placeHolder: 'Select report format' }
  );

  if (!format) { return; }

  const extMap: Record<string, string> = { csv: 'csv', html: 'html', markdown: 'md', json: 'json' };
  const ext = extMap[format.value] ?? format.value;
  const defaultUri = vscode.workspace.workspaceFolders?.[0]
    ? vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, `network-security-report.${ext}`)
    : undefined;

  const saveUri = await vscode.window.showSaveDialog({
    defaultUri,
    filters: {
      'CSV (Excel)': ['csv'],
      'HTML': ['html'],
      'Markdown': ['md'],
      'JSON': ['json'],
    },
  });

  if (!saveUri) { return; }

  await exportSecurityReport(
    lastParseResult.topology,
    lastParseResult.findings,
    format.value,
    saveUri
  );

  vscode.window.showInformationMessage(`Security report exported to ${path.basename(saveUri.fsPath)}`);
}

// ─── Command: Show Effective Rules ──────────────────────────────────────────

async function commandShowEffectiveRules(): Promise<void> {
  if (!lastParseResult || lastParseResult.topology.nsgs.length === 0) {
    const result = await parseWorkspace();
    if (!result || result.topology.nsgs.length === 0) {
      vscode.window.showWarningMessage('No NSGs found in workspace.');
      return;
    }
    lastParseResult = result;
  }

  const nsgItems = lastParseResult.topology.nsgs.map(nsg => ({
    label: nsg.name,
    description: `${nsg.rules.length} rules`,
    nsg,
  }));

  const selected = await vscode.window.showQuickPick(nsgItems, {
    placeHolder: 'Select an NSG to view effective rules',
  });

  if (!selected) { return; }

  const rules = selected.nsg.rules
    .sort((a, b) => a.priority - b.priority)
    .map(r => `${r.priority.toString().padStart(5)} | ${r.access.padEnd(5)} | ${r.direction.padEnd(8)} | ${r.protocol.padEnd(4)} | ${r.sourceAddressPrefix}:${r.sourcePortRange} → ${r.destinationAddressPrefix}:${r.destinationPortRange} | ${r.name}`);

  const header = 'Prior | Acces | Directn  | Prot | Source → Destination | Name';
  const doc = await vscode.workspace.openTextDocument({
    content: `Effective Rules: ${selected.nsg.name}\n${'='.repeat(60)}\n\n${header}\n${'-'.repeat(80)}\n${rules.join('\n')}`,
    language: 'plaintext',
  });
  vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
}

// ─── Command: Connect to Azure ──────────────────────────────────────────────

async function commandConnectAzure(): Promise<void> {
  let auth: typeof import('./azure/azureAuth');
  try {
    auth = require('./azure/azureAuth');
  } catch (err) {
    vscode.window.showErrorMessage('Azure SDK failed to load. Ensure node_modules are installed.');
    console.error('[Azure NetSec] Failed to load azureAuth:', err);
    return;
  }

  const session = await auth.authenticateAzure();
  if (!session) { return; }

  azureSession = session;

  vscode.window.showInformationMessage(
    `Signed in to Azure. Found ${session.subscriptions.length} subscription(s).`,
    'Visualize Live Topology'
  ).then(action => {
    if (action === 'Visualize Live Topology') {
      commandVisualizeLive();
    }
  });
}

// ─── Command: Visualize Live Topology ───────────────────────────────────────

async function commandVisualizeLive(): Promise<void> {
  let auth: typeof import('./azure/azureAuth');
  let live: typeof import('./azure/liveTopology');
  try {
    auth = require('./azure/azureAuth');
    live = require('./azure/liveTopology');
  } catch (err) {
    vscode.window.showErrorMessage('Azure SDK failed to load. Ensure node_modules are installed.');
    console.error('[Azure NetSec] Failed to load Azure modules:', err);
    return;
  }

  // Authenticate if not already signed in
  if (!azureSession) {
    azureSession = (await auth.authenticateAzure()) ?? undefined;
    if (!azureSession) { return; }
  }

  // Let user pick which subscriptions to scan
  const selectedSubs = await auth.pickSubscriptions(azureSession.subscriptions);
  if (selectedSubs.length === 0) {
    vscode.window.showWarningMessage('No subscriptions selected.');
    return;
  }

  const result = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Fetching live Azure topology...',
      cancellable: false,
    },
    async (progress) => {
      try {
        const topology = await live.fetchLiveTopology(
          azureSession!.credential,
          selectedSubs,
          (p) => progress.report({ message: p.message }),
        );

        // Resolve cross-references (reuse existing function)
        resolveConnections(topology);

        // Run security analysis on live resources
        const findings = analyzeTopology(topology);

        const parseResult: ParseResult = {
          topology,
          findings,
          parsedFiles: selectedSubs.map(s => `azure://${s.subscriptionId}`),
          parseErrors: [],
        };

        return parseResult;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const stack = err instanceof Error ? err.stack : '';
        console.error('[Azure NetSec] Live topology fetch failed:', msg, stack);
        vscode.window.showErrorMessage(`Failed to fetch live topology: ${msg}`);
        return undefined;
      }
    }
  );

  if (!result) { return; }

  lastParseResult = result;
  webviewProvider.show(result.topology, result.findings);
  findingsTreeProvider.update(result.findings);
  updateStatusBar(result.findings);

  const counts = { critical: 0, high: 0, warning: 0, info: 0 };
  result.findings.forEach(f => counts[f.severity as keyof typeof counts]++);

  const subNames = selectedSubs.map(s => s.displayName).join(', ');
  vscode.window.showInformationMessage(
    `Live topology: ${result.topology.vnets.length} VNets, ${result.topology.nsgs.length} NSGs, ${result.findings.length} findings across [${subNames}]`
  );
}

// ─── Parsing Logic ──────────────────────────────────────────────────────────

async function parseWorkspace(): Promise<ParseResult | undefined> {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    vscode.window.showWarningMessage('No workspace folder open.');
    return undefined;
  }

  return vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Analyzing network security...',
      cancellable: false,
    },
    async (progress) => {
      // Find all Bicep and ARM template files
      progress.report({ message: 'Scanning for Bicep/ARM files...' });

      const bicepFiles = await vscode.workspace.findFiles('**/*.bicep', '**/node_modules/**');
      const jsonFiles = await vscode.workspace.findFiles('**/*.json', '**/node_modules/**');

      const mergedTopology: NetworkTopology = {
        vnets: [],
        nsgs: [],
        routeTables: [],
        privateEndpoints: [],
        firewalls: [],
        applicationGateways: [],
        bastionHosts: [],
        vpnGateways: [],
        connections: [],
      };

      const allFindings: SecurityFinding[] = [];
      const parsedFiles: string[] = [];
      const parseErrors: Array<{ filePath: string; line: number; message: string }> = [];

      // Parse Bicep files
      for (const file of bicepFiles) {
        progress.report({ message: `Parsing ${path.basename(file.fsPath)}...` });
        try {
          const content = (await vscode.workspace.fs.readFile(file)).toString();
          const partial = parseBicepFile(content, { filePath: file.fsPath });
          mergeTopology(mergedTopology, partial);
          parsedFiles.push(file.fsPath);
        } catch (err) {
          parseErrors.push({
            filePath: file.fsPath,
            line: 0,
            message: `Failed to parse: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
      }

      // Parse ARM template JSON files
      for (const file of jsonFiles) {
        try {
          const content = (await vscode.workspace.fs.readFile(file)).toString();
          if (isArmTemplate(content)) {
            progress.report({ message: `Parsing ${path.basename(file.fsPath)}...` });
            const partial = parseArmTemplate(content, { filePath: file.fsPath });
            if (partial) {
              mergeTopology(mergedTopology, partial);
              parsedFiles.push(file.fsPath);
            }
          }
        } catch (err) {
          // Skip non-ARM JSON files silently
        }
      }

      if (parsedFiles.length === 0) {
        vscode.window.showWarningMessage(
          'No Bicep or ARM template files with networking resources found in the workspace.'
        );
        return undefined;
      }

      // Resolve cross-references
      progress.report({ message: 'Resolving connections...' });
      resolveConnections(mergedTopology);

      // Run security analysis
      progress.report({ message: 'Analyzing security rules...' });
      allFindings.push(...analyzeTopology(mergedTopology));

      return {
        topology: mergedTopology,
        findings: allFindings,
        parsedFiles,
        parseErrors,
      };
    }
  );
}

function mergeTopology(target: NetworkTopology, partial: Partial<NetworkTopology>): void {
  if (partial.vnets) { target.vnets.push(...partial.vnets); }
  if (partial.nsgs) { target.nsgs.push(...partial.nsgs); }
  if (partial.routeTables) { target.routeTables.push(...partial.routeTables); }
  if (partial.privateEndpoints) { target.privateEndpoints.push(...partial.privateEndpoints); }
  if (partial.firewalls) { target.firewalls.push(...partial.firewalls); }
  if (partial.applicationGateways) { target.applicationGateways.push(...partial.applicationGateways); }
  if (partial.bastionHosts) { target.bastionHosts.push(...partial.bastionHosts); }
  if (partial.vpnGateways) { target.vpnGateways.push(...partial.vpnGateways); }
}

function resolveConnections(topology: NetworkTopology): void {
  const connections: TopologyConnection[] = [];

  for (const vnet of topology.vnets) {
    for (const subnet of vnet.subnets) {
      // Subnet → NSG
      if (subnet.nsgId) {
        connections.push({
          sourceId: subnet.id,
          targetId: subnet.nsgId,
          connectionType: 'subnet-nsg',
          label: 'NSG Association',
        });
      }

      // Subnet → Route Table
      if (subnet.routeTableId) {
        connections.push({
          sourceId: subnet.id,
          targetId: subnet.routeTableId,
          connectionType: 'subnet-routetable',
          label: 'Route Table',
        });
      }
    }

    // VNet Peerings
    for (const peering of vnet.peerings) {
      connections.push({
        sourceId: vnet.id,
        targetId: peering.remoteVNetId,
        connectionType: 'peering',
        label: peering.name,
      });
    }
  }

  // Private Endpoints → Subnets
  for (const pe of topology.privateEndpoints) {
    connections.push({
      sourceId: pe.id,
      targetId: pe.subnetId,
      connectionType: 'private-endpoint',
      label: pe.groupIds.join(', '),
    });
  }

  topology.connections = connections;
}

// ─── Diagnostics ────────────────────────────────────────────────────────────

async function analyzeAndUpdateDiagnostics(document: vscode.TextDocument): Promise<void> {
  const content = document.getText();
  const filePath = document.uri.fsPath;
  let partial: Partial<NetworkTopology> | null = null;

  if (filePath.endsWith('.bicep')) {
    partial = parseBicepFile(content, { filePath });
  } else if (isArmTemplate(content)) {
    partial = parseArmTemplate(content, { filePath });
  }

  if (!partial) { return; }

  const topology: NetworkTopology = {
    vnets: partial.vnets ?? [],
    nsgs: partial.nsgs ?? [],
    routeTables: partial.routeTables ?? [],
    privateEndpoints: partial.privateEndpoints ?? [],
    firewalls: partial.firewalls ?? [],
    applicationGateways: partial.applicationGateways ?? [],
    bastionHosts: partial.bastionHosts ?? [],
    vpnGateways: partial.vpnGateways ?? [],
    connections: [],
  };

  resolveConnections(topology);
  const findings = analyzeTopology(topology);

  // Convert findings to VS Code diagnostics
  const diagnostics: vscode.Diagnostic[] = findings
    .filter(f => f.filePath === filePath && f.line !== undefined)
    .map(f => {
      const range = new vscode.Range(
        new vscode.Position(Math.max(0, (f.line ?? 1) - 1), 0),
        new vscode.Position(Math.max(0, (f.line ?? 1) - 1), Number.MAX_SAFE_INTEGER)
      );

      const severity = {
        critical: vscode.DiagnosticSeverity.Error,
        high: vscode.DiagnosticSeverity.Error,
        warning: vscode.DiagnosticSeverity.Warning,
        info: vscode.DiagnosticSeverity.Information,
      }[f.severity];

      const diag = new vscode.Diagnostic(range, `[${f.id}] ${f.title}: ${f.description}`, severity);
      diag.source = 'Azure NetSec';
      diag.code = {
        value: f.id,
        target: vscode.Uri.parse(f.learnMoreUrl),
      };
      return diag;
    });

  diagnosticCollection.set(document.uri, diagnostics);
  updateStatusBar(findings);
}

function updateDiagnostics(result: ParseResult): void {
  // Group findings by file
  const byFile = new Map<string, SecurityFinding[]>();
  for (const f of result.findings) {
    if (f.filePath) {
      const existing = byFile.get(f.filePath) ?? [];
      existing.push(f);
      byFile.set(f.filePath, existing);
    }
  }

  diagnosticCollection.clear();
  for (const [filePath, findings] of byFile) {
    const uri = vscode.Uri.file(filePath);
    const diagnostics = findings
      .filter(f => f.line !== undefined)
      .map(f => {
        const range = new vscode.Range(
          new vscode.Position(Math.max(0, (f.line ?? 1) - 1), 0),
          new vscode.Position(Math.max(0, (f.line ?? 1) - 1), Number.MAX_SAFE_INTEGER)
        );

        const severity = {
          critical: vscode.DiagnosticSeverity.Error,
          high: vscode.DiagnosticSeverity.Error,
          warning: vscode.DiagnosticSeverity.Warning,
          info: vscode.DiagnosticSeverity.Information,
        }[f.severity];

        const diag = new vscode.Diagnostic(range, `[${f.id}] ${f.title}`, severity);
        diag.source = 'Azure NetSec';
        diag.code = {
          value: f.id,
          target: vscode.Uri.parse(f.learnMoreUrl),
        };
        return diag;
      });

    diagnosticCollection.set(uri, diagnostics);
  }
}

function updateStatusBar(findings: SecurityFinding[]): void {
  const critical = findings.filter(f => f.severity === 'critical').length;
  const high = findings.filter(f => f.severity === 'high').length;

  if (critical > 0) {
    statusBarItem.text = `$(shield) NetSec: ${critical} Critical`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else if (high > 0) {
    statusBarItem.text = `$(shield) NetSec: ${high} High`;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  } else {
    statusBarItem.text = `$(shield) NetSec: ✓`;
    statusBarItem.backgroundColor = undefined;
  }
}

// ─── Helper ─────────────────────────────────────────────────────────────────

function isSupportedFile(doc: vscode.TextDocument): boolean {
  return doc.languageId === 'bicep' || (doc.languageId === 'json' && doc.fileName.endsWith('.json'));
}

// ─── Findings Tree Data Provider ────────────────────────────────────────────

class FindingsTreeDataProvider implements vscode.TreeDataProvider<FindingTreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<FindingTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private findings: SecurityFinding[] = [];

  update(findings: SecurityFinding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: FindingTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingTreeItem): FindingTreeItem[] {
    if (element) { return []; }

    return this.findings.map(f => {
      const icon = {
        critical: '🔴',
        high: '🟠',
        warning: '🟡',
        info: '🔵',
      }[f.severity];

      const item = new FindingTreeItem(
        `${icon} [${f.id}] ${f.title}`,
        vscode.TreeItemCollapsibleState.None
      );
      item.tooltip = `${f.description}\n\nRecommendation: ${f.recommendation}`;
      item.description = f.resourceName;

      if (f.filePath && f.line) {
        item.command = {
          command: 'vscode.open',
          title: 'Go to Source',
          arguments: [
            vscode.Uri.file(f.filePath),
            { selection: new vscode.Range(f.line - 1, 0, f.line - 1, 0) },
          ],
        };
      }

      return item;
    });
  }
}

class FindingTreeItem extends vscode.TreeItem {
  constructor(label: string, collapsibleState: vscode.TreeItemCollapsibleState) {
    super(label, collapsibleState);
  }
}
