/**
 * ARM template JSON parser for Azure networking resources.
 * Extracts VNets, Subnets, NSGs, Route Tables, Private Endpoints, and Firewalls
 * from ARM template .json files.
 *
 * Microsoft Learn References:
 * - ARM template structure: https://learn.microsoft.com/azure/azure-resource-manager/templates/syntax
 * - NSG ARM: https://learn.microsoft.com/azure/templates/microsoft.network/networksecuritygroups
 * - VNet ARM: https://learn.microsoft.com/azure/templates/microsoft.network/virtualnetworks
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
  RuleDirection,
  RuleAccess,
  RuleProtocol,
} from '../models/networkModel';

// ─── ARM Template Types ─────────────────────────────────────────────────────

interface ArmTemplate {
  $schema?: string;
  contentVersion?: string;
  resources?: ArmResource[];
  parameters?: Record<string, unknown>;
  variables?: Record<string, unknown>;
}

interface ArmResource {
  type: string;
  apiVersion: string;
  name: string;
  location?: string;
  properties?: Record<string, unknown>;
  resources?: ArmResource[];
  dependsOn?: string[];
}

// ─── Parser ─────────────────────────────────────────────────────────────────

export interface ArmParseOptions {
  filePath: string;
}

export function parseArmTemplate(content: string, options: ArmParseOptions): Partial<NetworkTopology> | null {
  let template: ArmTemplate;
  try {
    template = JSON.parse(content);
  } catch {
    return null;
  }

  // Validate it's an ARM template
  if (!template.$schema || !template.resources) {
    // Check if it's a parameter file or other JSON
    if (!Array.isArray(template.resources)) {
      return null;
    }
  }

  // Build line lookup for resource name positions
  const lineMap = buildLineMap(content);

  const vnets: VirtualNetwork[] = [];
  const nsgs: NetworkSecurityGroup[] = [];
  const routeTables: RouteTable[] = [];
  const privateEndpoints: PrivateEndpoint[] = [];
  const firewalls: AzureFirewall[] = [];

  const allResources = flattenResources(template.resources ?? []);

  for (const resource of allResources) {
    const typeLower = resource.type.toLowerCase();
    const line = findResourceLine(lineMap, resource.name, resource.type);

    if (typeLower === 'microsoft.network/virtualnetworks') {
      vnets.push(parseArmVNet(resource, options.filePath, line));
    } else if (typeLower === 'microsoft.network/networksecuritygroups') {
      nsgs.push(parseArmNsg(resource, options.filePath, line));
    } else if (typeLower === 'microsoft.network/routetables') {
      routeTables.push(parseArmRouteTable(resource, options.filePath, line));
    } else if (typeLower === 'microsoft.network/privateendpoints') {
      privateEndpoints.push(parseArmPrivateEndpoint(resource, options.filePath, line));
    } else if (typeLower === 'microsoft.network/azurefirewalls') {
      firewalls.push(parseArmFirewall(resource, options.filePath, line));
    }
  }

  return {
    vnets,
    nsgs,
    routeTables,
    privateEndpoints,
    firewalls,
    connections: [],
  };
}

/**
 * Checks whether the given JSON content is an ARM template.
 */
export function isArmTemplate(content: string): boolean {
  try {
    const parsed = JSON.parse(content);
    return (
      typeof parsed.$schema === 'string' &&
      parsed.$schema.includes('deploymentTemplate') &&
      Array.isArray(parsed.resources)
    );
  } catch {
    return false;
  }
}

// ─── Flatten Nested Resources ───────────────────────────────────────────────

function flattenResources(resources: ArmResource[]): ArmResource[] {
  const result: ArmResource[] = [];
  for (const r of resources) {
    result.push(r);
    if (r.resources) {
      result.push(...flattenResources(r.resources));
    }
  }
  return result;
}

// ─── Line Number Lookup ─────────────────────────────────────────────────────

function buildLineMap(content: string): string[] {
  return content.split('\n');
}

function findResourceLine(lines: string[], name: string, type: string): number {
  // Search for the resource type string in the JSON to find its approximate line
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${type}"`) || lines[i].includes(`"${name}"`)) {
      return i + 1; // 1-indexed
    }
  }
  return 1;
}

// ─── Safe Property Access ───────────────────────────────────────────────────

function getProp<T>(obj: Record<string, unknown> | undefined, key: string): T | undefined {
  if (!obj) { return undefined; }
  return obj[key] as T | undefined;
}

function getStringProp(obj: Record<string, unknown> | undefined, key: string): string {
  return (getProp<string>(obj, key) ?? '');
}

function getBoolProp(obj: Record<string, unknown> | undefined, key: string): boolean {
  return getProp<boolean>(obj, key) ?? false;
}

// ─── VNet Parser ────────────────────────────────────────────────────────────

function parseArmVNet(resource: ArmResource, filePath: string, line: number): VirtualNetwork {
  const props = resource.properties ?? {};
  const addressSpace = getProp<{ addressPrefixes: string[] }>(props, 'addressSpace');
  const subnetArray = getProp<Array<Record<string, unknown>>>(props, 'subnets') ?? [];

  const subnets: Subnet[] = subnetArray.map((s, idx) => {
    const subProps = s.properties as Record<string, unknown> | undefined;
    const nsgRef = getProp<{ id: string }>(subProps, 'networkSecurityGroup');
    const rtRef = getProp<{ id: string }>(subProps, 'routeTable');

    const seArray = getProp<Array<{ service: string }>>(subProps, 'serviceEndpoints') ?? [];
    const delegArray = getProp<Array<{ name: string; properties: { serviceName: string } }>>(subProps, 'delegations') ?? [];

    return {
      id: (s.name as string) ?? `subnet-${idx}`,
      name: (s.name as string) ?? `subnet-${idx}`,
      addressPrefix: getStringProp(subProps, 'addressPrefix'),
      nsgId: nsgRef?.id,
      routeTableId: rtRef?.id,
      serviceEndpoints: seArray.map(se => se.service),
      privateEndpoints: [],
      delegations: delegArray.map(d => d.properties?.serviceName ?? ''),
      sourceLocation: { filePath, line },
    };
  });

  return {
    id: resource.name,
    name: resource.name,
    location: resource.location,
    addressSpace: addressSpace?.addressPrefixes ?? [],
    subnets,
    peerings: [],
    sourceLocation: { filePath, line },
  };
}

// ─── NSG Parser ─────────────────────────────────────────────────────────────

function parseArmNsg(resource: ArmResource, filePath: string, line: number): NetworkSecurityGroup {
  const props = resource.properties ?? {};
  const ruleArray = getProp<Array<Record<string, unknown>>>(props, 'securityRules') ?? [];

  const rules: NsgRule[] = ruleArray.map(r => {
    const rProps = r.properties as Record<string, unknown> | undefined;
    return {
      name: (r.name as string) ?? 'unnamed-rule',
      priority: (getProp<number>(rProps, 'priority') ?? 1000),
      direction: (getStringProp(rProps, 'direction') as RuleDirection) || 'Inbound',
      access: (getStringProp(rProps, 'access') as RuleAccess) || 'Allow',
      protocol: (getStringProp(rProps, 'protocol') as RuleProtocol) || '*',
      sourceAddressPrefix: getStringProp(rProps, 'sourceAddressPrefix') || '*',
      sourcePortRange: getStringProp(rProps, 'sourcePortRange') || '*',
      destinationAddressPrefix: getStringProp(rProps, 'destinationAddressPrefix') || '*',
      destinationPortRange: getStringProp(rProps, 'destinationPortRange') || '*',
      description: getProp<string>(rProps, 'description'),
      sourceLocation: { filePath, line },
    };
  });

  return {
    id: resource.name,
    name: resource.name,
    location: resource.location,
    rules,
    associatedSubnets: [],
    associatedNics: [],
    sourceLocation: { filePath, line },
  };
}

// ─── Route Table Parser ─────────────────────────────────────────────────────

function parseArmRouteTable(resource: ArmResource, filePath: string, line: number): RouteTable {
  const props = resource.properties ?? {};
  const routeArray = getProp<Array<Record<string, unknown>>>(props, 'routes') ?? [];

  const routes: Route[] = routeArray.map(r => {
    const rProps = r.properties as Record<string, unknown> | undefined;
    return {
      name: (r.name as string) ?? 'unnamed-route',
      addressPrefix: getStringProp(rProps, 'addressPrefix'),
      nextHopType: (getStringProp(rProps, 'nextHopType') as Route['nextHopType']) || 'None',
      nextHopIpAddress: getProp<string>(rProps, 'nextHopIpAddress'),
    };
  });

  return {
    id: resource.name,
    name: resource.name,
    routes,
    disableBgpRoutePropagation: getBoolProp(props, 'disableBgpRoutePropagation'),
    associatedSubnets: [],
    sourceLocation: { filePath, line },
  };
}

// ─── Private Endpoint Parser ────────────────────────────────────────────────

function parseArmPrivateEndpoint(resource: ArmResource, filePath: string, line: number): PrivateEndpoint {
  const props = resource.properties ?? {};
  const subnet = getProp<{ id: string }>(props, 'subnet');
  const plscArray = getProp<Array<Record<string, unknown>>>(props, 'privateLinkServiceConnections') ?? [];

  let privateLinkServiceId = '';
  let groupIds: string[] = [];

  if (plscArray.length > 0) {
    const plscProps = plscArray[0].properties as Record<string, unknown> | undefined;
    privateLinkServiceId = getStringProp(plscProps, 'privateLinkServiceId');
    groupIds = getProp<string[]>(plscProps, 'groupIds') ?? [];
  }

  return {
    id: resource.name,
    name: resource.name,
    subnetId: subnet?.id ?? '',
    privateLinkServiceId,
    groupIds,
    sourceLocation: { filePath, line },
  };
}

// ─── Firewall Parser ────────────────────────────────────────────────────────

function parseArmFirewall(resource: ArmResource, filePath: string, line: number): AzureFirewall {
  const props = resource.properties ?? {};
  const sku = getProp<{ tier: string }>(props, 'sku');
  const threatIntelMode = getStringProp(props, 'threatIntelMode') as AzureFirewall['threatIntelMode'];
  const policyRef = getProp<{ id: string }>(props, 'firewallPolicy');

  return {
    id: resource.name,
    name: resource.name,
    skuTier: (sku?.tier as AzureFirewall['skuTier']) ?? 'Standard',
    threatIntelMode: threatIntelMode || 'Alert',
    rules: [],
    firewallPolicyId: policyRef?.id,
    sourceLocation: { filePath, line },
  };
}
