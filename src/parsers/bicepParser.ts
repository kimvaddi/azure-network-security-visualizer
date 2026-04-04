/**
 * Bicep file parser for Azure networking resources.
 * Extracts VNets, Subnets, NSGs, Route Tables, Private Endpoints, and Firewalls
 * from .bicep files using regex-based pattern matching.
 *
 * Microsoft Learn References:
 * - Bicep resource declaration: https://learn.microsoft.com/azure/azure-resource-manager/bicep/resource-declaration
 * - NSG Bicep: https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups
 * - VNet Bicep: https://learn.microsoft.com/azure/templates/microsoft.network/virtualnetworks
 */

import {
  NetworkTopology,
  VirtualNetwork,
  Subnet,
  NetworkSecurityGroup,
  NsgRule,
  RouteTable,
  Route,
  PrivateEndpoint,
  AzureFirewall,
  FirewallRule,
  VNetPeering,
  ApplicationGateway,
  BastionHost,
  VpnGateway,
  RuleDirection,
  RuleAccess,
  RuleProtocol,
} from '../models/networkModel';

// ─── Resource Type Patterns ─────────────────────────────────────────────────

const RESOURCE_PATTERN = /resource\s+(\w+)\s+'(Microsoft\.\w+\/[\w\/]+)@[\d\-]+'\s*=\s*\{/g;

const RESOURCE_TYPES = {
  vnet: 'Microsoft.Network/virtualNetworks',
  subnet: 'Microsoft.Network/virtualNetworks/subnets',
  nsg: 'Microsoft.Network/networkSecurityGroups',
  nsgRule: 'Microsoft.Network/networkSecurityGroups/securityRules',
  routeTable: 'Microsoft.Network/routeTables',
  route: 'Microsoft.Network/routeTables/routes',
  privateEndpoint: 'Microsoft.Network/privateEndpoints',
  firewall: 'Microsoft.Network/azureFirewalls',
  firewallPolicy: 'Microsoft.Network/firewallPolicies',
  peering: 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings',
  applicationGateway: 'Microsoft.Network/applicationGateways',
  bastionHost: 'Microsoft.Network/bastionHosts',
  vpnGateway: 'Microsoft.Network/virtualNetworkGateways',
} as const;

// ─── Parser ─────────────────────────────────────────────────────────────────

export interface BicepParseOptions {
  filePath: string;
}

export function parseBicepFile(content: string, options: BicepParseOptions): Partial<NetworkTopology> {
  const vnets: VirtualNetwork[] = [];
  const nsgs: NetworkSecurityGroup[] = [];
  const routeTables: RouteTable[] = [];
  const privateEndpoints: PrivateEndpoint[] = [];
  const firewalls: AzureFirewall[] = [];
  const applicationGateways: ApplicationGateway[] = [];
  const bastionHosts: BastionHost[] = [];
  const vpnGateways: VpnGateway[] = [];
  const peerings: Array<{ vnetName: string; peering: VNetPeering }> = [];

  const resources = extractResources(content, options.filePath);

  for (const res of resources) {
    switch (res.type) {
      case RESOURCE_TYPES.vnet:
        vnets.push(parseVNet(res));
        break;
      case RESOURCE_TYPES.nsg:
        nsgs.push(parseNsg(res));
        break;
      case RESOURCE_TYPES.routeTable:
        routeTables.push(parseRouteTable(res));
        break;
      case RESOURCE_TYPES.privateEndpoint:
        privateEndpoints.push(parsePrivateEndpoint(res));
        break;
      case RESOURCE_TYPES.firewall:
        firewalls.push(parseFirewall(res));
        break;
      case RESOURCE_TYPES.peering:
        peerings.push(parsePeering(res));
        break;
      case RESOURCE_TYPES.applicationGateway:
        applicationGateways.push(parseApplicationGateway(res));
        break;
      case RESOURCE_TYPES.bastionHost:
        bastionHosts.push(parseBastionHost(res));
        break;
      case RESOURCE_TYPES.vpnGateway:
        vpnGateways.push(parseVpnGateway(res));
        break;
    }
  }

  // Attach standalone peerings to their parent VNets
  for (const { vnetName, peering } of peerings) {
    const vnet = vnets.find(v => v.name === vnetName || v.id === vnetName);
    if (vnet) {
      vnet.peerings.push(peering);
    }
  }

  return {
    vnets,
    nsgs,
    routeTables,
    privateEndpoints,
    firewalls,
    applicationGateways,
    bastionHosts,
    vpnGateways,
    connections: [],
  };
}

// ─── Resource Block Extraction ──────────────────────────────────────────────

interface RawResource {
  symbolicName: string;
  type: string;
  body: string;
  line: number;
  filePath: string;
}

function extractResources(content: string, filePath: string): RawResource[] {
  const resources: RawResource[] = [];
  const lines = content.split('\n');

  let match: RegExpExecArray | null;
  // Reset lastIndex for global regex
  RESOURCE_PATTERN.lastIndex = 0;

  while ((match = RESOURCE_PATTERN.exec(content)) !== null) {
    const symbolicName = match[1];
    const type = match[2];
    const startOffset = match.index;
    const line = content.substring(0, startOffset).split('\n').length;

    // Extract the body by counting braces
    const body = extractBracedBlock(content, startOffset + match[0].length - 1);

    resources.push({
      symbolicName,
      type,
      body,
      line,
      filePath,
    });
  }

  return resources;
}

function extractBracedBlock(content: string, openBraceIndex: number): string {
  let depth = 0;
  let i = openBraceIndex;

  for (; i < content.length; i++) {
    if (content[i] === '{') {
      depth++;
    } else if (content[i] === '}') {
      depth--;
      if (depth === 0) {
        return content.substring(openBraceIndex, i + 1);
      }
    }
  }

  // Return what we have if braces aren't balanced
  return content.substring(openBraceIndex);
}

// ─── Property Extraction Helpers ────────────────────────────────────────────

function extractStringProperty(body: string, propertyName: string): string | undefined {
  // Match: propertyName: 'value' or propertyName: "value"
  const pattern = new RegExp(`${propertyName}\\s*:\\s*'([^']*)'`, 'i');
  const match = body.match(pattern);
  return match?.[1];
}

function extractArrayProperty(body: string, propertyName: string): string[] {
  // Match: propertyName: [ ... ]
  const pattern = new RegExp(`${propertyName}\\s*:\\s*\\[([^\\]]*)\\]`, 'is');
  const match = body.match(pattern);
  if (!match) { return []; }

  const items: string[] = [];
  const stringPattern = /'([^']*)'/g;
  let stringMatch;
  while ((stringMatch = stringPattern.exec(match[1])) !== null) {
    items.push(stringMatch[1]);
  }
  return items;
}

function extractBoolProperty(body: string, propertyName: string): boolean {
  const pattern = new RegExp(`${propertyName}\\s*:\\s*(true|false)`, 'i');
  const match = body.match(pattern);
  return match?.[1] === 'true';
}

function extractIntProperty(body: string, propertyName: string): number | undefined {
  const pattern = new RegExp(`${propertyName}\\s*:\\s*(\\d+)`, 'i');
  const match = body.match(pattern);
  return match ? parseInt(match[1], 10) : undefined;
}

function extractNestedBlocks(body: string, arrayName: string): string[] {
  // Find the array property and extract each { } block within it
  const arrayPattern = new RegExp(`${arrayName}\\s*:\\s*\\[`, 'i');
  const arrayMatch = body.match(arrayPattern);
  if (!arrayMatch || arrayMatch.index === undefined) { return []; }

  const startIndex = arrayMatch.index + arrayMatch[0].length;
  const blocks: string[] = [];
  let i = startIndex;
  let depth = 0;
  let blockStart = -1;

  for (; i < body.length; i++) {
    const char = body[i];
    if (char === '{') {
      if (depth === 0) { blockStart = i; }
      depth++;
    } else if (char === '}') {
      depth--;
      if (depth === 0 && blockStart >= 0) {
        blocks.push(body.substring(blockStart, i + 1));
        blockStart = -1;
      }
    } else if (char === ']' && depth === 0) {
      break;
    }
  }

  return blocks;
}

// ─── VNet Parser ────────────────────────────────────────────────────────────

function parseVNet(res: RawResource): VirtualNetwork {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const location = extractStringProperty(res.body, 'location');
  const addressSpace = extractArrayProperty(res.body, 'addressPrefixes');
  const enableDdosProtection = extractBoolProperty(res.body, 'enableDdosProtection');

  const subnetBlocks = extractNestedBlocks(res.body, 'subnets');
  const subnets: Subnet[] = subnetBlocks.map((block, idx) => parseSubnet(block, `${name}-subnet-${idx}`, res.filePath, res.line));

  return {
    id: res.symbolicName,
    name,
    location,
    addressSpace,
    subnets,
    peerings: [],
    enableDdosProtection: enableDdosProtection || undefined,
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

function parseSubnet(block: string, fallbackId: string, filePath: string, baseLine: number): Subnet {
  const name = extractStringProperty(block, 'name') ?? fallbackId;
  const addressPrefix = extractStringProperty(block, 'addressPrefix') ?? '';
  const nsgId = extractReferenceId(block, 'networkSecurityGroup');
  const routeTableId = extractReferenceId(block, 'routeTable');

  // Extract service endpoints
  const serviceEndpointBlocks = extractNestedBlocks(block, 'serviceEndpoints');
  const serviceEndpoints = serviceEndpointBlocks
    .map(b => extractStringProperty(b, 'service'))
    .filter((s): s is string => s !== undefined);

  // Extract delegations
  const delegationBlocks = extractNestedBlocks(block, 'delegations');
  const delegations = delegationBlocks
    .map(b => extractStringProperty(b, 'serviceName'))
    .filter((s): s is string => s !== undefined);

  return {
    id: name,
    name,
    addressPrefix,
    nsgId,
    routeTableId,
    serviceEndpoints,
    privateEndpoints: [],
    delegations,
    sourceLocation: { filePath, line: baseLine },
  };
}

function extractReferenceId(block: string, propertyName: string): string | undefined {
  // Match property: { id: resource.id } or property: { id: 'some-id' }
  const pattern = new RegExp(`${propertyName}\\s*:\\s*\\{[^}]*id\\s*:\\s*(\\w+)\\.id`, 'i');
  const match = block.match(pattern);
  if (match) { return match[1]; }

  const literalPattern = new RegExp(`${propertyName}\\s*:\\s*\\{[^}]*id\\s*:\\s*'([^']*)'`, 'i');
  const literalMatch = block.match(literalPattern);
  return literalMatch?.[1];
}

// ─── Peering Parser ─────────────────────────────────────────────────────────

function parsePeering(res: RawResource): { vnetName: string; peering: VNetPeering } {
  // Resource name is typically 'vnetName/peeringName'
  const fullName = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const parts = fullName.split('/');
  const vnetName = parts.length > 1 ? parts[0] : '';
  const peeringName = parts.length > 1 ? parts[1] : fullName;

  const remoteVNetId = extractReferenceId(res.body, 'remoteVirtualNetwork') ?? '';

  return {
    vnetName,
    peering: {
      id: res.symbolicName,
      name: peeringName,
      remoteVNetId,
      allowVirtualNetworkAccess: extractBoolProperty(res.body, 'allowVirtualNetworkAccess'),
      allowForwardedTraffic: extractBoolProperty(res.body, 'allowForwardedTraffic'),
      allowGatewayTransit: extractBoolProperty(res.body, 'allowGatewayTransit'),
      useRemoteGateways: extractBoolProperty(res.body, 'useRemoteGateways'),
    },
  };
}

// ─── NSG Parser ─────────────────────────────────────────────────────────────

function parseNsg(res: RawResource): NetworkSecurityGroup {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const location = extractStringProperty(res.body, 'location');

  const ruleBlocks = extractNestedBlocks(res.body, 'securityRules');
  const rules: NsgRule[] = ruleBlocks.map(block => parseNsgRule(block, res.filePath, res.line));

  return {
    id: res.symbolicName,
    name,
    location,
    rules,
    associatedSubnets: [],
    associatedNics: [],
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

function parseNsgRule(block: string, filePath: string, baseLine: number): NsgRule {
  return {
    name: extractStringProperty(block, 'name') ?? 'unnamed-rule',
    priority: extractIntProperty(block, 'priority') ?? 1000,
    direction: (extractStringProperty(block, 'direction') as RuleDirection) ?? 'Inbound',
    access: (extractStringProperty(block, 'access') as RuleAccess) ?? 'Allow',
    protocol: (extractStringProperty(block, 'protocol') as RuleProtocol) ?? '*',
    sourceAddressPrefix: extractStringProperty(block, 'sourceAddressPrefix') ?? '*',
    sourcePortRange: extractStringProperty(block, 'sourcePortRange') ?? '*',
    destinationAddressPrefix: extractStringProperty(block, 'destinationAddressPrefix') ?? '*',
    destinationPortRange: extractStringProperty(block, 'destinationPortRange') ?? '*',
    description: extractStringProperty(block, 'description'),
    sourceLocation: { filePath, line: baseLine },
  };
}

// ─── Route Table Parser ─────────────────────────────────────────────────────

function parseRouteTable(res: RawResource): RouteTable {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const routeBlocks = extractNestedBlocks(res.body, 'routes');
  const routes: Route[] = routeBlocks.map(parseRoute);

  return {
    id: res.symbolicName,
    name,
    routes,
    disableBgpRoutePropagation: extractBoolProperty(res.body, 'disableBgpRoutePropagation'),
    associatedSubnets: [],
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

function parseRoute(block: string): Route {
  return {
    name: extractStringProperty(block, 'name') ?? 'unnamed-route',
    addressPrefix: extractStringProperty(block, 'addressPrefix') ?? '0.0.0.0/0',
    nextHopType: (extractStringProperty(block, 'nextHopType') as Route['nextHopType']) ?? 'None',
    nextHopIpAddress: extractStringProperty(block, 'nextHopIpAddress'),
  };
}

// ─── Private Endpoint Parser ────────────────────────────────────────────────

function parsePrivateEndpoint(res: RawResource): PrivateEndpoint {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const subnetId = extractReferenceId(res.body, 'subnet') ?? '';
  const privateLinkServiceId = extractReferenceId(res.body, 'privateLinkServiceConnection') ?? '';
  const groupIds = extractArrayProperty(res.body, 'groupIds');

  // Check for privateDnsZoneGroups nested resource or property
  const hasDnsZone = res.body.includes('privateDnsZoneGroups') || res.body.includes('privateDnsZone');
  const dnsZoneName = extractStringProperty(res.body, 'privateDnsZoneId') ?? (hasDnsZone ? 'configured' : undefined);

  return {
    id: res.symbolicName,
    name,
    subnetId,
    privateLinkServiceId,
    groupIds,
    privateDnsZoneGroup: dnsZoneName,
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

// ─── Firewall Parser ────────────────────────────────────────────────────────

function parseFirewall(res: RawResource): AzureFirewall {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const skuTier = (extractStringProperty(res.body, 'tier') as AzureFirewall['skuTier']) ?? 'Standard';
  const threatIntelMode = (extractStringProperty(res.body, 'threatIntelMode') as AzureFirewall['threatIntelMode']) ?? 'Alert';
  const firewallPolicyId = extractReferenceId(res.body, 'firewallPolicy');

  return {
    id: res.symbolicName,
    name,
    skuTier,
    threatIntelMode,
    rules: [],
    firewallPolicyId,
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

// ─── Application Gateway Parser ─────────────────────────────────────────────

function parseApplicationGateway(res: RawResource): ApplicationGateway {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const skuTier = extractStringProperty(res.body, 'tier') ?? 'Standard_v2';
  const wafEnabled = extractBoolProperty(res.body, 'enabled');
  const wafMode = extractStringProperty(res.body, 'firewallMode');
  const minProtocolVersion = extractStringProperty(res.body, 'minProtocolVersion');
  const isWafSku = skuTier.toLowerCase().includes('waf');

  return {
    id: res.symbolicName,
    name,
    skuTier,
    wafEnabled: wafEnabled || isWafSku,
    wafMode: wafMode as ApplicationGateway['wafMode'],
    minProtocolVersion,
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

// ─── Bastion Host Parser ────────────────────────────────────────────────────

function parseBastionHost(res: RawResource): BastionHost {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const skuName = extractStringProperty(res.body, 'name') ?? 'Standard';

  return {
    id: res.symbolicName,
    name,
    skuName: skuName as BastionHost['skuName'],
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}

// ─── VPN Gateway Parser ─────────────────────────────────────────────────────

function parseVpnGateway(res: RawResource): VpnGateway {
  const name = extractStringProperty(res.body, 'name') ?? res.symbolicName;
  const skuName = extractStringProperty(res.body, 'name') ?? 'VpnGw1'; // sku.name
  const gatewayType = extractStringProperty(res.body, 'gatewayType') ?? 'Vpn';
  const vpnType = extractStringProperty(res.body, 'vpnType') ?? 'RouteBased';
  const generation = extractStringProperty(res.body, 'vpnGatewayGeneration');
  return {
    id: res.symbolicName, name, skuName, gatewayType, vpnType,
    vpnGatewayGeneration: generation,
    sourceLocation: { filePath: res.filePath, line: res.line },
  };
}
