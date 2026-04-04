/**
 * Core network topology model types.
 * Represents Azure networking resources parsed from Bicep/ARM templates.
 *
 * Microsoft Learn Reference:
 * - NSG Overview: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview
 * - VNet Concepts: https://learn.microsoft.com/azure/virtual-network/concepts-and-best-practices
 * - Route Tables: https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview
 * - Private Endpoints: https://learn.microsoft.com/azure/private-link/private-endpoint-overview
 * - Azure Firewall: https://learn.microsoft.com/azure/firewall/overview
 */

// ─── Severity Levels ────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'warning' | 'info';

// ─── Security Finding ───────────────────────────────────────────────────────

export interface SecurityFinding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  recommendation: string;
  /** MS Learn documentation link for further reading */
  learnMoreUrl: string;
  resourceId: string;
  resourceType: string;
  resourceName: string;
  /** Line number in source file where the issue was found */
  line?: number;
  /** Source file path */
  filePath?: string;
  /** The specific rule or config that triggered this finding */
  evidence?: string;
}

// ─── NSG Rule ───────────────────────────────────────────────────────────────

export type RuleDirection = 'Inbound' | 'Outbound';
export type RuleAccess = 'Allow' | 'Deny';
export type RuleProtocol = 'Tcp' | 'Udp' | 'Icmp' | '*';

export interface NsgRule {
  name: string;
  priority: number;
  direction: RuleDirection;
  access: RuleAccess;
  protocol: RuleProtocol;
  sourceAddressPrefix: string;
  sourcePortRange: string;
  destinationAddressPrefix: string;
  destinationPortRange: string;
  description?: string;
  /** Source file and line for traceability */
  sourceLocation?: { filePath: string; line: number };
}

export interface NetworkSecurityGroup {
  id: string;
  name: string;
  resourceGroup?: string;
  location?: string;
  rules: NsgRule[];
  /** Subnet IDs this NSG is associated with */
  associatedSubnets: string[];
  /** NIC IDs this NSG is associated with */
  associatedNics: string[];
  sourceLocation?: { filePath: string; line: number };
}

// ─── Subnet ─────────────────────────────────────────────────────────────────

export interface Subnet {
  id: string;
  name: string;
  addressPrefix: string;
  nsgId?: string;
  routeTableId?: string;
  /** Service endpoints configured on this subnet */
  serviceEndpoints: string[];
  /** Private endpoint connections in this subnet */
  privateEndpoints: string[];
  /** Delegation (e.g., Microsoft.Web/serverFarms) */
  delegations: string[];
  sourceLocation?: { filePath: string; line: number };
}

// ─── VNet ───────────────────────────────────────────────────────────────────

export interface VirtualNetwork {
  id: string;
  name: string;
  resourceGroup?: string;
  location?: string;
  addressSpace: string[];
  subnets: Subnet[];
  /** Peering connections */
  peerings: VNetPeering[];
  /** DDoS Protection enabled (Zero Trust: NS-1) */
  enableDdosProtection?: boolean;
  sourceLocation?: { filePath: string; line: number };
}

export interface VNetPeering {
  id: string;
  name: string;
  remoteVNetId: string;
  allowVirtualNetworkAccess: boolean;
  allowForwardedTraffic: boolean;
  allowGatewayTransit: boolean;
  useRemoteGateways: boolean;
}

// ─── Route Table ────────────────────────────────────────────────────────────

export interface Route {
  name: string;
  addressPrefix: string;
  nextHopType: 'VirtualNetworkGateway' | 'VnetLocal' | 'Internet' | 'VirtualAppliance' | 'None';
  nextHopIpAddress?: string;
}

export interface RouteTable {
  id: string;
  name: string;
  routes: Route[];
  /** Disable BGP route propagation */
  disableBgpRoutePropagation: boolean;
  associatedSubnets: string[];
  sourceLocation?: { filePath: string; line: number };
}

// ─── Private Endpoint ───────────────────────────────────────────────────────

export interface PrivateEndpoint {
  id: string;
  name: string;
  subnetId: string;
  /** The resource this PE connects to */
  privateLinkServiceId: string;
  groupIds: string[];
  /** Private DNS zone group */
  privateDnsZoneGroup?: string;
  sourceLocation?: { filePath: string; line: number };
}

// ─── Azure Firewall ─────────────────────────────────────────────────────────

export interface FirewallRule {
  name: string;
  ruleType: 'application' | 'network' | 'nat';
  priority: number;
  action: 'Allow' | 'Deny';
  sourceAddresses: string[];
  destinationAddresses: string[];
  destinationPorts: string[];
  protocols: string[];
}

export interface AzureFirewall {
  id: string;
  name: string;
  skuTier: 'Standard' | 'Premium' | 'Basic';
  threatIntelMode: 'Alert' | 'Deny' | 'Off';
  rules: FirewallRule[];
  /** Firewall policy ID if using Azure Firewall Policy */
  firewallPolicyId?: string;
  sourceLocation?: { filePath: string; line: number };
}

// ─── Application Gateway ────────────────────────────────────────────────────

export interface ApplicationGateway {
  id: string;
  name: string;
  skuTier: 'Standard_v2' | 'WAF_v2' | 'Standard' | 'WAF' | string;
  /** Whether WAF is enabled */
  wafEnabled?: boolean;
  /** WAF mode: Detection or Prevention */
  wafMode?: 'Detection' | 'Prevention' | string;
  /** Minimum TLS version (e.g., 'TLSv1_2') */
  minProtocolVersion?: string;
  sourceLocation?: { filePath: string; line: number };
}

// ─── Azure Bastion Host ─────────────────────────────────────────────────────

export interface BastionHost {
  id: string;
  name: string;
  skuName?: 'Basic' | 'Standard' | 'Developer' | string;
  sourceLocation?: { filePath: string; line: number };
}

// ─── Network Topology (Aggregate) ───────────────────────────────────────────

export interface NetworkTopology {
  vnets: VirtualNetwork[];
  nsgs: NetworkSecurityGroup[];
  routeTables: RouteTable[];
  privateEndpoints: PrivateEndpoint[];
  firewalls: AzureFirewall[];
  /** Application Gateways (WAF, L7 routing) */
  applicationGateways: ApplicationGateway[];
  /** Azure Bastion hosts */
  bastionHosts: BastionHost[];
  /** Cross-references resolved after parsing */
  connections: TopologyConnection[];
}

export interface TopologyConnection {
  sourceId: string;
  targetId: string;
  connectionType: 'subnet-nsg' | 'subnet-routetable' | 'peering' | 'private-endpoint' | 'firewall-route';
  label?: string;
}

// ─── Parse Result ───────────────────────────────────────────────────────────

export interface ParseResult {
  topology: NetworkTopology;
  findings: SecurityFinding[];
  /** Files that were parsed */
  parsedFiles: string[];
  /** Parse errors/warnings */
  parseErrors: Array<{ filePath: string; line: number; message: string }>;
}
