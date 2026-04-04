/**
 * Live Azure topology fetcher via Azure Resource Graph.
 * Queries network resources across multiple subscriptions and maps them
 * to the existing NetworkTopology model for visualization and analysis.
 *
 * Microsoft Learn References:
 * - Azure Resource Graph: https://learn.microsoft.com/azure/governance/resource-graph/overview
 * - Resource Graph queries: https://learn.microsoft.com/azure/governance/resource-graph/concepts/query-language
 * - Network resource types: https://learn.microsoft.com/azure/templates/microsoft.network/allversions
 */

import { TokenCredential } from '@azure/identity';
import { ResourceGraphClient } from '@azure/arm-resourcegraph';
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
  VNetPeering,
  ApplicationGateway,
  BastionHost,
  RuleDirection,
  RuleAccess,
  RuleProtocol,
} from '../models/networkModel';
import { SubscriptionInfo } from './azureAuth';

// ─── Resource Graph Query ───────────────────────────────────────────────────

const NETWORK_RESOURCE_QUERY = `
Resources
| where type in~ (
    'microsoft.network/virtualnetworks',
    'microsoft.network/networksecuritygroups',
    'microsoft.network/routetables',
    'microsoft.network/privateendpoints',
    'microsoft.network/azurefirewalls',
    'microsoft.network/applicationgateways',
    'microsoft.network/bastionhosts'
  )
| project id, name, type, location, resourceGroup, subscriptionId, properties, tags
| order by type asc, name asc
`;

const PEERING_QUERY = `
Resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand peering = properties.virtualNetworkPeerings
| where isnotnull(peering)
| project
    vnetId = id,
    vnetName = name,
    peeringName = tostring(peering.name),
    remoteVNetId = tostring(peering.properties.remoteVirtualNetwork.id),
    allowVNetAccess = tobool(peering.properties.allowVirtualNetworkAccess),
    allowForwarding = tobool(peering.properties.allowForwardedTraffic),
    allowGatewayTransit = tobool(peering.properties.allowGatewayTransit),
    useRemoteGateways = tobool(peering.properties.useRemoteGateways),
    subscriptionId
`;

// ─── Fetch Live Topology ────────────────────────────────────────────────────

export interface LiveFetchProgress {
  message: string;
}

/**
 * Query Azure Resource Graph for all network resources across the given subscriptions
 * and map them to the existing NetworkTopology model.
 */
export async function fetchLiveTopology(
  credential: TokenCredential,
  subscriptions: SubscriptionInfo[],
  onProgress?: (progress: LiveFetchProgress) => void,
): Promise<NetworkTopology> {
  const subscriptionIds = subscriptions.map(s => s.subscriptionId);
  const client = new ResourceGraphClient(credential);

  onProgress?.({ message: 'Querying network resources...' });

  // Fetch all network resources
  const resourceResult = await client.resources({
    query: NETWORK_RESOURCE_QUERY,
    subscriptions: subscriptionIds,
  });

  const resources = (resourceResult.data as Array<ResourceGraphRow>) ?? [];

  onProgress?.({ message: `Found ${resources.length} network resources. Parsing...` });

  // Fetch peering data
  onProgress?.({ message: 'Querying VNet peerings...' });
  const peeringResult = await client.resources({
    query: PEERING_QUERY,
    subscriptions: subscriptionIds,
  });
  const peeringRows = (peeringResult.data as Array<PeeringRow>) ?? [];

  // Map resources to topology
  const topology = mapResourcesToTopology(resources, peeringRows);

  onProgress?.({
    message: `Topology built: ${topology.vnets.length} VNets, ${topology.nsgs.length} NSGs, ${topology.routeTables.length} route tables`,
  });

  return topology;
}

// ─── Resource Graph Row Types ───────────────────────────────────────────────

interface ResourceGraphRow {
  id: string;
  name: string;
  type: string;
  location: string;
  resourceGroup: string;
  subscriptionId: string;
  properties: Record<string, unknown>;
  tags?: Record<string, string>;
}

interface PeeringRow {
  vnetId: string;
  vnetName: string;
  peeringName: string;
  remoteVNetId: string;
  allowVNetAccess: boolean;
  allowForwarding: boolean;
  allowGatewayTransit: boolean;
  useRemoteGateways: boolean;
  subscriptionId: string;
}

// ─── Mapping Functions ──────────────────────────────────────────────────────

function mapResourcesToTopology(resources: ResourceGraphRow[], peeringRows: PeeringRow[]): NetworkTopology {
  const vnets: VirtualNetwork[] = [];
  const nsgs: NetworkSecurityGroup[] = [];
  const routeTables: RouteTable[] = [];
  const privateEndpoints: PrivateEndpoint[] = [];
  const firewalls: AzureFirewall[] = [];
  const applicationGateways: ApplicationGateway[] = [];
  const bastionHosts: BastionHost[] = [];

  for (const r of resources) {
    try {
      const typeLower = r.type.toLowerCase();

      if (typeLower === 'microsoft.network/virtualnetworks') {
        vnets.push(mapVNet(r, peeringRows));
      } else if (typeLower === 'microsoft.network/networksecuritygroups') {
        nsgs.push(mapNsg(r));
      } else if (typeLower === 'microsoft.network/routetables') {
        routeTables.push(mapRouteTable(r));
      } else if (typeLower === 'microsoft.network/privateendpoints') {
        privateEndpoints.push(mapPrivateEndpoint(r));
      } else if (typeLower === 'microsoft.network/azurefirewalls') {
        firewalls.push(mapFirewall(r));
      } else if (typeLower === 'microsoft.network/applicationgateways') {
        applicationGateways.push(mapAppGateway(r));
      } else if (typeLower === 'microsoft.network/bastionhosts') {
        bastionHosts.push(mapBastionHost(r));
      }
    } catch {
      // Skip malformed resources
    }
  }

  return { vnets, nsgs, routeTables, privateEndpoints, firewalls, applicationGateways, bastionHosts, connections: [] };
}

// ─── Safe Property Helpers ──────────────────────────────────────────────────

function prop<T>(obj: Record<string, unknown> | undefined, key: string): T | undefined {
  if (!obj) { return undefined; }
  return obj[key] as T | undefined;
}

function strProp(obj: Record<string, unknown> | undefined, key: string): string {
  return (prop<string>(obj, key) ?? '');
}

// ─── VNet Mapping ───────────────────────────────────────────────────────────

function mapVNet(r: ResourceGraphRow, peeringRows: PeeringRow[]): VirtualNetwork {
  const props = r.properties;
  const addressSpace = prop<{ addressPrefixes: string[] }>(props, 'addressSpace');
  const subnetArray = prop<Array<Record<string, unknown>>>(props, 'subnets') ?? [];

  const subnets: Subnet[] = subnetArray.map((s, idx) => {
    const subProps = s.properties as Record<string, unknown> | undefined;
    const nsgRef = prop<{ id: string }>(subProps, 'networkSecurityGroup');
    const rtRef = prop<{ id: string }>(subProps, 'routeTable');
    const seArray = prop<Array<{ service: string }>>(subProps, 'serviceEndpoints') ?? [];
    const delegArray = prop<Array<{ name: string; properties: { serviceName: string } }>>(subProps, 'delegations') ?? [];

    return {
      id: (s.id as string) ?? (s.name as string) ?? `subnet-${idx}`,
      name: (s.name as string) ?? `subnet-${idx}`,
      addressPrefix: strProp(subProps, 'addressPrefix'),
      nsgId: nsgRef?.id,
      routeTableId: rtRef?.id,
      serviceEndpoints: seArray.map(se => se.service),
      privateEndpoints: [],
      delegations: delegArray.map(d => d.properties?.serviceName ?? ''),
      sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
    };
  });

  // Attach peerings from the peering query
  const peerings: VNetPeering[] = peeringRows
    .filter(p => p.vnetId.toLowerCase() === r.id.toLowerCase())
    .map(p => ({
      id: `${r.id}/virtualNetworkPeerings/${p.peeringName}`,
      name: p.peeringName,
      remoteVNetId: p.remoteVNetId,
      allowVirtualNetworkAccess: p.allowVNetAccess ?? true,
      allowForwardedTraffic: p.allowForwarding ?? false,
      allowGatewayTransit: p.allowGatewayTransit ?? false,
      useRemoteGateways: p.useRemoteGateways ?? false,
    }));

  return {
    id: r.id,
    name: r.name,
    location: r.location,
    addressSpace: addressSpace?.addressPrefixes ?? [],
    subnets,
    peerings,
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}

// ─── NSG Mapping ────────────────────────────────────────────────────────────

function mapNsg(r: ResourceGraphRow): NetworkSecurityGroup {
  const props = r.properties;
  const ruleArray = prop<Array<Record<string, unknown>>>(props, 'securityRules') ?? [];

  const rules: NsgRule[] = ruleArray.map(rule => {
    const rProps = rule.properties as Record<string, unknown> | undefined;
    return {
      name: (rule.name as string) ?? 'unnamed-rule',
      priority: prop<number>(rProps, 'priority') ?? 1000,
      direction: (strProp(rProps, 'direction') as RuleDirection) || 'Inbound',
      access: (strProp(rProps, 'access') as RuleAccess) || 'Allow',
      protocol: (strProp(rProps, 'protocol') as RuleProtocol) || '*',
      sourceAddressPrefix: strProp(rProps, 'sourceAddressPrefix') || '*',
      sourcePortRange: strProp(rProps, 'sourcePortRange') || '*',
      destinationAddressPrefix: strProp(rProps, 'destinationAddressPrefix') || '*',
      destinationPortRange: strProp(rProps, 'destinationPortRange') || '*',
      description: prop<string>(rProps, 'description'),
      sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
    };
  });

  return {
    id: r.id,
    name: r.name,
    location: r.location,
    rules,
    associatedSubnets: [],
    associatedNics: [],
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}

// ─── Route Table Mapping ────────────────────────────────────────────────────

function mapRouteTable(r: ResourceGraphRow): RouteTable {
  const props = r.properties;
  const routeArray = prop<Array<Record<string, unknown>>>(props, 'routes') ?? [];

  const routes: Route[] = routeArray.map(route => {
    const rProps = route.properties as Record<string, unknown> | undefined;
    return {
      name: (route.name as string) ?? 'unnamed-route',
      addressPrefix: strProp(rProps, 'addressPrefix'),
      nextHopType: (strProp(rProps, 'nextHopType') as Route['nextHopType']) || 'None',
      nextHopIpAddress: prop<string>(rProps, 'nextHopIpAddress'),
    };
  });

  return {
    id: r.id,
    name: r.name,
    routes,
    disableBgpRoutePropagation: (prop<boolean>(props, 'disableBgpRoutePropagation') ?? false),
    associatedSubnets: [],
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}

// ─── Private Endpoint Mapping ───────────────────────────────────────────────

function mapPrivateEndpoint(r: ResourceGraphRow): PrivateEndpoint {
  const props = r.properties;
  const subnet = prop<{ id: string }>(props, 'subnet');
  const plscArray = prop<Array<Record<string, unknown>>>(props, 'privateLinkServiceConnections') ?? [];

  let privateLinkServiceId = '';
  let groupIds: string[] = [];

  if (plscArray.length > 0) {
    const plscProps = plscArray[0].properties as Record<string, unknown> | undefined;
    privateLinkServiceId = strProp(plscProps, 'privateLinkServiceId');
    groupIds = prop<string[]>(plscProps, 'groupIds') ?? [];
  }

  return {
    id: r.id,
    name: r.name,
    subnetId: subnet?.id ?? '',
    privateLinkServiceId,
    groupIds,
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}

// ─── Firewall Mapping ───────────────────────────────────────────────────────

function mapFirewall(r: ResourceGraphRow): AzureFirewall {
  const props = r.properties;
  const sku = prop<{ tier: string }>(props, 'sku');
  const threatIntelMode = strProp(props, 'threatIntelMode') as AzureFirewall['threatIntelMode'];
  const policyRef = prop<{ id: string }>(props, 'firewallPolicy');

  return {
    id: r.id,
    name: r.name,
    skuTier: (sku?.tier as AzureFirewall['skuTier']) ?? 'Standard',
    threatIntelMode: threatIntelMode || 'Alert',
    rules: [],
    firewallPolicyId: policyRef?.id,
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}

// ─── Application Gateway Mapping ────────────────────────────────────────────

function mapAppGateway(r: ResourceGraphRow): ApplicationGateway {
  const props = r.properties;
  const sku = prop<{ tier: string }>(props, 'sku');
  const wafConfig = prop<Record<string, unknown>>(props, 'webApplicationFirewallConfiguration');
  const sslPolicy = prop<Record<string, unknown>>(props, 'sslPolicy');

  const skuTier = (sku?.tier ?? 'Standard_v2') as ApplicationGateway['skuTier'];
  const isWafSku = skuTier.toLowerCase().includes('waf');
  const wafEnabled = wafConfig ? (prop<boolean>(wafConfig, 'enabled') ?? isWafSku) : isWafSku;
  const wafMode = wafConfig ? strProp(wafConfig, 'firewallMode') : undefined;
  const minProtocolVersion = sslPolicy ? strProp(sslPolicy, 'minProtocolVersion') : undefined;

  return {
    id: r.id,
    name: r.name,
    skuTier,
    wafEnabled,
    wafMode: wafMode as ApplicationGateway['wafMode'],
    minProtocolVersion: minProtocolVersion || undefined,
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}

// ─── Bastion Host Mapping ───────────────────────────────────────────────────

function mapBastionHost(r: ResourceGraphRow): BastionHost {
  const props = r.properties;
  const sku = prop<{ name: string }>(props, 'sku');

  return {
    id: r.id,
    name: r.name,
    skuName: (sku?.name ?? 'Standard') as BastionHost['skuName'],
    sourceLocation: { filePath: `azure://${r.subscriptionId}/${r.resourceGroup}/${r.name}`, line: 0 },
  };
}
