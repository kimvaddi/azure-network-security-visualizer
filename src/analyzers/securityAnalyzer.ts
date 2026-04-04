/**
 * Security rule analyzer engine.
 * Inspects parsed network topology for misconfigurations and security issues.
 *
 * Rules are based on Microsoft Learn best practices:
 * - NSG best practices: https://learn.microsoft.com/azure/security/fundamentals/network-best-practices
 * - Network Security Benchmark: https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-network-security
 * - Secure VNet deployment: https://learn.microsoft.com/azure/virtual-network/secure-virtual-network
 * - Traffic Analytics: https://learn.microsoft.com/azure/network-watcher/traffic-analytics-usage-scenarios
 */

import {
  NetworkTopology,
  SecurityFinding,
  Severity,
  NetworkSecurityGroup,
  NsgRule,
  VirtualNetwork,
  Subnet,
  RouteTable,
  AzureFirewall,
  PrivateEndpoint,
  ApplicationGateway,
} from '../models/networkModel';

// ─── Rule IDs ───────────────────────────────────────────────────────────────

export const RULE_IDS = {
  OPEN_SSH: 'NETSEC-001',
  OPEN_RDP: 'NETSEC-002',
  ANY_TO_ANY_ALLOW: 'NETSEC-003',
  MISSING_DENY_ALL: 'NETSEC-004',
  OVERLY_PERMISSIVE_SOURCE: 'NETSEC-005',
  OVERLY_PERMISSIVE_DEST: 'NETSEC-006',
  SUBNET_NO_NSG: 'NETSEC-007',
  WIDE_PORT_RANGE: 'NETSEC-008',
  LOW_PRIORITY_ALLOW_ALL: 'NETSEC-009',
  FIREWALL_THREAT_INTEL_OFF: 'NETSEC-010',
  MISSING_FLOW_LOGS_HINT: 'NETSEC-011',
  HARDCODED_IP: 'NETSEC-012',
  OVERLAPPING_RULES: 'NETSEC-013',
  DEFAULT_ROUTE_INTERNET: 'NETSEC-014',
  VNET_NO_DDOS: 'NETSEC-015',
  NO_BASTION_SUBNET: 'NETSEC-016',
  PE_NO_DNS_ZONE: 'NETSEC-017',
  APPGW_NO_WAF: 'NETSEC-018',
  APPGW_WAF_DETECTION_ONLY: 'NETSEC-019',
  APPGW_WEAK_TLS: 'NETSEC-020',
  SUBNET_NO_UDR: 'NETSEC-021',
} as const;

// ─── Analyzer ───────────────────────────────────────────────────────────────

export function analyzeTopology(topology: NetworkTopology): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // Analyze each NSG
  for (const nsg of topology.nsgs) {
    findings.push(...analyzeNsg(nsg));
  }

  // Analyze subnets without NSGs
  for (const vnet of topology.vnets) {
    findings.push(...analyzeSubnets(vnet, topology));
  }

  // Analyze route tables
  for (const rt of topology.routeTables) {
    findings.push(...analyzeRouteTable(rt));
  }

  // Analyze firewalls
  for (const fw of topology.firewalls) {
    findings.push(...analyzeFirewall(fw));
  }

  // Zero Trust: Analyze VNets for DDoS and Bastion
  for (const vnet of topology.vnets) {
    findings.push(...analyzeVNetZeroTrust(vnet));
  }

  // Zero Trust: Analyze Private Endpoints for DNS zones
  for (const pe of topology.privateEndpoints) {
    findings.push(...analyzePrivateEndpointDns(pe));
  }

  // Zero Trust: Analyze Application Gateways for WAF + TLS
  for (const appgw of (topology.applicationGateways ?? [])) {
    findings.push(...analyzeApplicationGateway(appgw));
  }

  // Zero Trust: Analyze subnets for forced tunneling (UDR)
  for (const vnet of topology.vnets) {
    findings.push(...analyzeSubnetRouting(vnet, topology));
  }

  // Sort by severity
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, warning: 2, info: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return findings;
}

// ─── NSG Analysis ───────────────────────────────────────────────────────────

function analyzeNsg(nsg: NetworkSecurityGroup): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const rule of nsg.rules) {
    // NETSEC-001: Open SSH (port 22) from any source
    if (isOpenManagementPort(rule, '22')) {
      findings.push({
        id: RULE_IDS.OPEN_SSH,
        severity: 'critical',
        title: 'SSH port 22 open to the internet',
        description: `NSG rule "${rule.name}" allows inbound SSH (port 22) from any source (${rule.sourceAddressPrefix}). This exposes the resource to brute force attacks.`,
        recommendation: 'Use Azure Bastion or Just-in-Time (JIT) VM access instead of opening SSH directly. Ref: https://learn.microsoft.com/azure/bastion/bastion-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/secure-virtual-network#network-security',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | Priority: ${rule.priority} | ${rule.sourceAddressPrefix} → ${rule.destinationAddressPrefix}:${rule.destinationPortRange}`,
      });
    }

    // NETSEC-002: Open RDP (port 3389) from any source
    if (isOpenManagementPort(rule, '3389')) {
      findings.push({
        id: RULE_IDS.OPEN_RDP,
        severity: 'critical',
        title: 'RDP port 3389 open to the internet',
        description: `NSG rule "${rule.name}" allows inbound RDP (port 3389) from any source (${rule.sourceAddressPrefix}). This is a top attack vector.`,
        recommendation: 'Use Azure Bastion or JIT VM access. Never expose RDP directly to the internet. Ref: https://learn.microsoft.com/azure/bastion/bastion-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/defender-for-cloud/enable-just-in-time-access',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | Priority: ${rule.priority} | ${rule.sourceAddressPrefix} → ${rule.destinationAddressPrefix}:${rule.destinationPortRange}`,
      });
    }

    // NETSEC-003: Any-to-any allow rule
    if (isAnyToAnyAllow(rule)) {
      findings.push({
        id: RULE_IDS.ANY_TO_ANY_ALLOW,
        severity: 'high',
        title: 'Any-to-any allow rule detected',
        description: `NSG rule "${rule.name}" allows all traffic from ${rule.sourceAddressPrefix} to ${rule.destinationAddressPrefix} on all ports. This defeats the purpose of the NSG.`,
        recommendation: 'Follow the "deny by default, permit by exception" approach. Define explicit allow rules for required traffic only. Ref: https://learn.microsoft.com/azure/virtual-network/tutorial-filter-network-traffic',
        learnMoreUrl: 'https://learn.microsoft.com/security/benchmark/azure/mcsb-v2-network-security',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | ${rule.access} | ${rule.protocol} | ${rule.sourceAddressPrefix}:${rule.sourcePortRange} → ${rule.destinationAddressPrefix}:${rule.destinationPortRange}`,
      });
    }

    // NETSEC-005: Overly permissive source (0.0.0.0/0 or *)
    if (rule.access === 'Allow' && rule.direction === 'Inbound' && isWildcardAddress(rule.sourceAddressPrefix) && !isAnyToAnyAllow(rule)) {
      findings.push({
        id: RULE_IDS.OVERLY_PERMISSIVE_SOURCE,
        severity: 'high',
        title: 'Inbound rule allows traffic from any source',
        description: `Rule "${rule.name}" allows inbound ${rule.protocol} traffic from ${rule.sourceAddressPrefix}. Consider using Service Tags or specific IP ranges.`,
        recommendation: 'Use Service Tags (e.g., AzureCloud, Internet) instead of broad address ranges. Ref: https://learn.microsoft.com/azure/virtual-network/service-tags-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/service-tags-overview',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | Source: ${rule.sourceAddressPrefix} | Dest Port: ${rule.destinationPortRange}`,
      });
    }

    // NETSEC-006: Overly permissive destination
    if (rule.access === 'Allow' && rule.direction === 'Outbound' && isWildcardAddress(rule.destinationAddressPrefix) && rule.destinationPortRange === '*') {
      findings.push({
        id: RULE_IDS.OVERLY_PERMISSIVE_DEST,
        severity: 'high',
        title: 'Outbound rule allows traffic to any destination on all ports',
        description: `Rule "${rule.name}" allows outbound ${rule.protocol} traffic to ${rule.destinationAddressPrefix} on all ports. This allows unrestricted data exfiltration.`,
        recommendation: 'Restrict outbound traffic to known destinations and required ports. Use Service Tags for Azure services. Ref: https://learn.microsoft.com/azure/virtual-network/service-tags-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/security/fundamentals/network-best-practices#logically-segment-subnets',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | Dest: ${rule.destinationAddressPrefix}:${rule.destinationPortRange}`,
      });
    }

    // NETSEC-008: Wide port range
    if (rule.access === 'Allow' && isWidePortRange(rule.destinationPortRange)) {
      findings.push({
        id: RULE_IDS.WIDE_PORT_RANGE,
        severity: 'warning',
        title: 'Excessively wide port range in allow rule',
        description: `Rule "${rule.name}" allows traffic on ports ${rule.destinationPortRange}. Wide port ranges increase attack surface.`,
        recommendation: 'Specify only the exact ports required by your application.',
        learnMoreUrl: 'https://learn.microsoft.com/azure/security/fundamentals/network-best-practices',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | Port range: ${rule.destinationPortRange}`,
      });
    }

    // NETSEC-009: Low priority allow-all (catch-all allow at high priority number)
    if (rule.access === 'Allow' && rule.priority >= 4000 && isWildcardAddress(rule.sourceAddressPrefix) && rule.destinationPortRange === '*') {
      findings.push({
        id: RULE_IDS.LOW_PRIORITY_ALLOW_ALL,
        severity: 'warning',
        title: 'Low-priority allow-all rule undermines deny-all',
        description: `Rule "${rule.name}" (priority ${rule.priority}) is a catch-all allow rule placed just before the default deny. This negates explicit deny rules and increases risk.`,
        recommendation: 'Remove catch-all allow rules. If broad access is needed temporarily, use a time-bound JIT mechanism instead. Ref: https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-overview',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Rule: ${rule.name} | Priority: ${rule.priority} | ${rule.sourceAddressPrefix} → ${rule.destinationAddressPrefix}:${rule.destinationPortRange}`,
      });
    }

    // NETSEC-012: Hardcoded IP addresses instead of service tags
    if (isHardcodedPublicIp(rule.sourceAddressPrefix) || isHardcodedPublicIp(rule.destinationAddressPrefix)) {
      findings.push({
        id: RULE_IDS.HARDCODED_IP,
        severity: 'info',
        title: 'Hardcoded IP address in NSG rule',
        description: `Rule "${rule.name}" uses hardcoded IP address(es). Consider using service tags for Azure service IPs.`,
        recommendation: 'Replace hardcoded IPs with Service Tags where possible. Microsoft auto-updates service tags as IP ranges change. Ref: https://learn.microsoft.com/azure/virtual-network/service-tags-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/service-tags-overview',
        resourceId: nsg.id,
        resourceType: 'Microsoft.Network/networkSecurityGroups',
        resourceName: nsg.name,
        line: rule.sourceLocation?.line,
        filePath: rule.sourceLocation?.filePath,
        evidence: `Source: ${rule.sourceAddressPrefix} | Destination: ${rule.destinationAddressPrefix}`,
      });
    }
  }

  // NETSEC-013: Overlapping rules (same direction, overlapping source/dest but different actions)
  findings.push(...detectOverlappingRules(nsg));

  // NETSEC-004: Missing explicit deny-all inbound rule
  if (!hasExplicitDenyAll(nsg.rules, 'Inbound')) {
    findings.push({
      id: RULE_IDS.MISSING_DENY_ALL,
      severity: 'warning',
      title: 'No explicit deny-all inbound rule',
      description: `NSG "${nsg.name}" does not have an explicit deny-all inbound rule. While Azure has a default deny, an explicit rule makes the intent clear and aids auditing.`,
      recommendation: 'Add an explicit DenyAllInbound rule with priority 4096. This documents intent and appears in flow logs.',
      learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#default-security-rules',
      resourceId: nsg.id,
      resourceType: 'Microsoft.Network/networkSecurityGroups',
      resourceName: nsg.name,
      line: nsg.sourceLocation?.line,
      filePath: nsg.sourceLocation?.filePath,
    });
  }

  // NETSEC-011: Hint about enabling flow logs
  findings.push({
    id: RULE_IDS.MISSING_FLOW_LOGS_HINT,
    severity: 'info',
    title: 'Ensure NSG Flow Logs are enabled',
    description: `NSG "${nsg.name}" — remember to enable VNet/NSG flow logs with Traffic Analytics for ongoing visibility into traffic patterns. This cannot be detected from Bicep alone.`,
    recommendation: 'Enable VNet flow logs (preferred) or NSG flow logs and feed them into Traffic Analytics. Ref: https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview',
    learnMoreUrl: 'https://learn.microsoft.com/azure/network-watcher/traffic-analytics-usage-scenarios',
    resourceId: nsg.id,
    resourceType: 'Microsoft.Network/networkSecurityGroups',
    resourceName: nsg.name,
  });

  return findings;
}

// ─── Subnet Analysis ────────────────────────────────────────────────────────

function analyzeSubnets(vnet: VirtualNetwork, topology: NetworkTopology): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const subnet of vnet.subnets) {
    // Skip special subnets that don't require NSGs
    const skipSubnets = ['AzureBastionSubnet', 'GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'RouteServerSubnet'];
    if (skipSubnets.some(s => subnet.name.toLowerCase().includes(s.toLowerCase()))) {
      continue;
    }

    // NETSEC-007: Subnet without NSG
    if (!subnet.nsgId) {
      findings.push({
        id: RULE_IDS.SUBNET_NO_NSG,
        severity: 'high',
        title: `Subnet "${subnet.name}" has no NSG attached`,
        description: `Subnet "${subnet.name}" in VNet "${vnet.name}" (${subnet.addressPrefix}) does not have a Network Security Group associated. All traffic is unrestricted.`,
        recommendation: 'Apply an NSG at the subnet level. Use "deny by default, permit by exception". Ref: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview',
        learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/manage-network-security-group',
        resourceId: subnet.id,
        resourceType: 'Microsoft.Network/virtualNetworks/subnets',
        resourceName: subnet.name,
        line: subnet.sourceLocation?.line,
        filePath: subnet.sourceLocation?.filePath,
      });
    }
  }

  return findings;
}

// ─── Route Table Analysis ───────────────────────────────────────────────────

function analyzeRouteTable(rt: RouteTable): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const route of rt.routes) {
    // NETSEC-014: Default route to Internet (0.0.0.0/0 → Internet)
    if (route.addressPrefix === '0.0.0.0/0' && route.nextHopType === 'Internet') {
      findings.push({
        id: RULE_IDS.DEFAULT_ROUTE_INTERNET,
        severity: 'warning',
        title: 'Default route sends all traffic to Internet',
        description: `Route table "${rt.name}" has a default route (0.0.0.0/0) pointing to the Internet. This bypasses any firewall inspection.`,
        recommendation: 'Route traffic through Azure Firewall or an NVA for inspection. Use forced tunneling for compliance. Ref: https://learn.microsoft.com/azure/firewall/forced-tunneling',
        learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview',
        resourceId: rt.id,
        resourceType: 'Microsoft.Network/routeTables',
        resourceName: rt.name,
        line: rt.sourceLocation?.line,
        filePath: rt.sourceLocation?.filePath,
        evidence: `Route: ${route.name} | ${route.addressPrefix} → ${route.nextHopType}`,
      });
    }
  }

  return findings;
}

// ─── Firewall Analysis ──────────────────────────────────────────────────────

function analyzeFirewall(fw: AzureFirewall): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // NETSEC-010: Threat intelligence mode set to Off
  if (fw.threatIntelMode === 'Off') {
    findings.push({
      id: RULE_IDS.FIREWALL_THREAT_INTEL_OFF,
      severity: 'high',
      title: 'Firewall threat intelligence is disabled',
      description: `Azure Firewall "${fw.name}" has threat intelligence mode set to "Off". Traffic from/to known malicious IPs will not be detected or blocked.`,
      recommendation: 'Set threatIntelMode to "Deny" (recommended) or "Alert" to block/alert on known malicious traffic. Ref: https://learn.microsoft.com/azure/firewall/threat-intel',
      learnMoreUrl: 'https://learn.microsoft.com/azure/firewall/threat-intel',
      resourceId: fw.id,
      resourceType: 'Microsoft.Network/azureFirewalls',
      resourceName: fw.name,
      line: fw.sourceLocation?.line,
      filePath: fw.sourceLocation?.filePath,
    });
  }

  return findings;
}

// ─── Zero Trust: VNet Analysis (DDoS + Bastion) ────────────────────────────

function analyzeVNetZeroTrust(vnet: VirtualNetwork): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // NETSEC-015: VNet without DDoS Protection
  if (!vnet.enableDdosProtection) {
    findings.push({
      id: RULE_IDS.VNET_NO_DDOS,
      severity: 'high',
      title: `VNet "${vnet.name}" does not have DDoS Protection enabled`,
      description: `Virtual Network "${vnet.name}" does not have Azure DDoS Protection enabled. Public IP addresses in this VNet are vulnerable to volumetric and protocol DDoS attacks.`,
      recommendation: 'Enable Azure DDoS Network Protection or DDoS IP Protection on this VNet. This is a Zero Trust requirement for all internet-facing workloads. Ref: https://learn.microsoft.com/azure/ddos-protection/manage-ddos-protection',
      learnMoreUrl: 'https://learn.microsoft.com/azure/networking/security/zero-trust-ddos-protection',
      resourceId: vnet.id,
      resourceType: 'Microsoft.Network/virtualNetworks',
      resourceName: vnet.name,
      line: vnet.sourceLocation?.line,
      filePath: vnet.sourceLocation?.filePath,
    });
  }

  // NETSEC-016: No Azure Bastion subnet in VNet
  const hasBastionSubnet = vnet.subnets.some(s => s.name.toLowerCase() === 'azurebastionsubnet');
  if (!hasBastionSubnet && vnet.subnets.length > 0) {
    findings.push({
      id: RULE_IDS.NO_BASTION_SUBNET,
      severity: 'warning',
      title: `VNet "${vnet.name}" has no Azure Bastion subnet`,
      description: `Virtual Network "${vnet.name}" does not contain an AzureBastionSubnet. Without Azure Bastion, VM access requires open SSH/RDP ports (NETSEC-001/002) or a VPN.`,
      recommendation: 'Add an AzureBastionSubnet (minimum /26) and deploy Azure Bastion for secure, browser-based VM access without exposing management ports. Ref: https://learn.microsoft.com/azure/bastion/bastion-overview',
      learnMoreUrl: 'https://learn.microsoft.com/azure/bastion/bastion-overview',
      resourceId: vnet.id,
      resourceType: 'Microsoft.Network/virtualNetworks',
      resourceName: vnet.name,
      line: vnet.sourceLocation?.line,
      filePath: vnet.sourceLocation?.filePath,
    });
  }

  return findings;
}

// ─── Zero Trust: Private Endpoint DNS Analysis ──────────────────────────────

function analyzePrivateEndpointDns(pe: PrivateEndpoint): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // NETSEC-017: Private Endpoint without DNS zone group
  if (!pe.privateDnsZoneGroup) {
    findings.push({
      id: RULE_IDS.PE_NO_DNS_ZONE,
      severity: 'warning',
      title: `Private Endpoint "${pe.name}" has no DNS zone group configured`,
      description: `Private Endpoint "${pe.name}" does not have a Private DNS Zone Group. Without proper DNS configuration, clients may still resolve to the public IP of the service instead of the private endpoint IP.`,
      recommendation: 'Configure a Private DNS Zone Group on this Private Endpoint to ensure DNS resolution points to the private IP. This is critical for Zero Trust — traffic should never leave the VNet. Ref: https://learn.microsoft.com/azure/private-link/private-endpoint-dns',
      learnMoreUrl: 'https://learn.microsoft.com/azure/private-link/private-endpoint-dns',
      resourceId: pe.id,
      resourceType: 'Microsoft.Network/privateEndpoints',
      resourceName: pe.name,
      line: pe.sourceLocation?.line,
      filePath: pe.sourceLocation?.filePath,
    });
  }

  return findings;
}

// ─── Zero Trust: Application Gateway Analysis (WAF + TLS) ──────────────────

function analyzeApplicationGateway(appgw: ApplicationGateway): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // NETSEC-018: Application Gateway without WAF
  if (!appgw.wafEnabled) {
    findings.push({
      id: RULE_IDS.APPGW_NO_WAF,
      severity: 'high',
      title: `Application Gateway "${appgw.name}" does not have WAF enabled`,
      description: `Application Gateway "${appgw.name}" (SKU: ${appgw.skuTier}) does not have Web Application Firewall enabled. Internet-facing web applications are unprotected against OWASP Top 10 attacks (SQL injection, XSS, etc.).`,
      recommendation: 'Upgrade to WAF_v2 SKU and enable WAF in Prevention mode. This is a Zero Trust requirement for all internet-facing web endpoints. Ref: https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview',
      learnMoreUrl: 'https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview',
      resourceId: appgw.id,
      resourceType: 'Microsoft.Network/applicationGateways',
      resourceName: appgw.name,
      line: appgw.sourceLocation?.line,
      filePath: appgw.sourceLocation?.filePath,
    });
  }

  // NETSEC-019: WAF in Detection mode only
  if (appgw.wafEnabled && appgw.wafMode === 'Detection') {
    findings.push({
      id: RULE_IDS.APPGW_WAF_DETECTION_ONLY,
      severity: 'warning',
      title: `WAF on "${appgw.name}" is in Detection mode — not blocking attacks`,
      description: `Application Gateway "${appgw.name}" has WAF enabled but in Detection mode. Attacks are logged but NOT blocked. Traffic still reaches your application.`,
      recommendation: 'Switch WAF to Prevention mode to actively block malicious requests. Detection mode should only be used during initial tuning. Ref: https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview#waf-modes',
      learnMoreUrl: 'https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview',
      resourceId: appgw.id,
      resourceType: 'Microsoft.Network/applicationGateways',
      resourceName: appgw.name,
      line: appgw.sourceLocation?.line,
      filePath: appgw.sourceLocation?.filePath,
    });
  }

  // NETSEC-020: Weak TLS version
  if (appgw.minProtocolVersion && !appgw.minProtocolVersion.includes('1_2') && !appgw.minProtocolVersion.includes('1_3')) {
    findings.push({
      id: RULE_IDS.APPGW_WEAK_TLS,
      severity: 'high',
      title: `Application Gateway "${appgw.name}" allows TLS versions below 1.2`,
      description: `Application Gateway "${appgw.name}" has minProtocolVersion set to "${appgw.minProtocolVersion}". TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.`,
      recommendation: 'Set minProtocolVersion to TLSv1_2 or higher. Zero Trust requires end-to-end encryption with modern TLS. Ref: https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview',
      learnMoreUrl: 'https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview',
      resourceId: appgw.id,
      resourceType: 'Microsoft.Network/applicationGateways',
      resourceName: appgw.name,
      line: appgw.sourceLocation?.line,
      filePath: appgw.sourceLocation?.filePath,
    });
  }

  return findings;
}

// ─── Zero Trust: Subnet Routing Analysis (Forced Tunneling) ─────────────────

function analyzeSubnetRouting(vnet: VirtualNetwork, topology: NetworkTopology): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const skipSubnets = ['AzureBastionSubnet', 'GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'RouteServerSubnet'];

  for (const subnet of vnet.subnets) {
    if (skipSubnets.some(s => subnet.name.toLowerCase().includes(s.toLowerCase()))) {
      continue;
    }

    // NETSEC-021: Subnet without route table (no forced tunneling)
    if (!subnet.routeTableId && topology.firewalls.length > 0) {
      findings.push({
        id: RULE_IDS.SUBNET_NO_UDR,
        severity: 'warning',
        title: `Subnet "${subnet.name}" has no route table — traffic may bypass firewall`,
        description: `Subnet "${subnet.name}" in VNet "${vnet.name}" does not have a User Defined Route (UDR) associated. Since Azure Firewall exists in the topology, this subnet's traffic may bypass firewall inspection.`,
        recommendation: 'Associate a route table with a 0.0.0.0/0 route pointing to the Azure Firewall private IP for forced tunneling. This ensures all outbound traffic is inspected. Ref: https://learn.microsoft.com/azure/firewall/forced-tunneling',
        learnMoreUrl: 'https://learn.microsoft.com/azure/firewall/forced-tunneling',
        resourceId: subnet.id,
        resourceType: 'Microsoft.Network/virtualNetworks/subnets',
        resourceName: subnet.name,
        line: subnet.sourceLocation?.line,
        filePath: subnet.sourceLocation?.filePath,
      });
    }
  }

  return findings;
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function detectOverlappingRules(nsg: NetworkSecurityGroup): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const rules = nsg.rules;

  for (let i = 0; i < rules.length; i++) {
    for (let j = i + 1; j < rules.length; j++) {
      const a = rules[i];
      const b = rules[j];

      // Same direction, different action, overlapping source+dest+port
      if (
        a.direction === b.direction &&
        a.access !== b.access &&
        addressesOverlap(a.sourceAddressPrefix, b.sourceAddressPrefix) &&
        addressesOverlap(a.destinationAddressPrefix, b.destinationAddressPrefix) &&
        portsOverlap(a.destinationPortRange, b.destinationPortRange)
      ) {
        const higher = a.priority < b.priority ? a : b;
        const lower = a.priority < b.priority ? b : a;
        findings.push({
          id: RULE_IDS.OVERLAPPING_RULES,
          severity: 'info',
          title: 'Potentially overlapping NSG rules with conflicting actions',
          description: `Rules "${higher.name}" (priority ${higher.priority}, ${higher.access}) and "${lower.name}" (priority ${lower.priority}, ${lower.access}) overlap on ${a.direction} traffic. The lower-numbered priority rule takes precedence.`,
          recommendation: 'Review these rules to confirm intent. Conflicting rules are hard to audit and may hide misconfigurations. Ref: https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#security-rules',
          learnMoreUrl: 'https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview#security-rules',
          resourceId: nsg.id,
          resourceType: 'Microsoft.Network/networkSecurityGroups',
          resourceName: nsg.name,
          line: higher.sourceLocation?.line,
          filePath: higher.sourceLocation?.filePath,
          evidence: `${higher.name} (${higher.priority}, ${higher.access}) vs ${lower.name} (${lower.priority}, ${lower.access})`,
        });
      }
    }
  }

  return findings;
}

function addressesOverlap(a: string, b: string): boolean {
  // If either is wildcard, they overlap
  if (isWildcardAddress(a) || isWildcardAddress(b)) { return true; }
  // If both are literal and identical, they overlap
  if (a === b) { return true; }
  return false;
}

function portsOverlap(a: string, b: string): boolean {
  // If either is wildcard, they overlap
  if (a === '*' || b === '*') { return true; }
  if (a === b) { return true; }
  // Check if specific port falls in range
  const aRange = a.match(/^(\d+)-(\d+)$/);
  const bRange = b.match(/^(\d+)-(\d+)$/);
  if (aRange && !bRange) {
    const port = parseInt(b, 10);
    return port >= parseInt(aRange[1], 10) && port <= parseInt(aRange[2], 10);
  }
  if (bRange && !aRange) {
    const port = parseInt(a, 10);
    return port >= parseInt(bRange[1], 10) && port <= parseInt(bRange[2], 10);
  }
  if (aRange && bRange) {
    return parseInt(aRange[1], 10) <= parseInt(bRange[2], 10) && parseInt(bRange[1], 10) <= parseInt(aRange[2], 10);
  }
  return false;
}

function isWildcardAddress(address: string): boolean {
  return ['*', '0.0.0.0/0', 'Internet', 'Any'].includes(address);
}

function isOpenManagementPort(rule: NsgRule, port: string): boolean {
  return (
    rule.direction === 'Inbound' &&
    rule.access === 'Allow' &&
    isWildcardAddress(rule.sourceAddressPrefix) &&
    portMatchesSingle(rule.destinationPortRange, port)
  );
}

function portMatchesSingle(portRange: string, targetPort: string): boolean {
  if (portRange === '*') { return true; }
  if (portRange === targetPort) { return true; }

  // Check ranges like "22-25"
  const rangeMatch = portRange.match(/^(\d+)-(\d+)$/);
  if (rangeMatch) {
    const low = parseInt(rangeMatch[1], 10);
    const high = parseInt(rangeMatch[2], 10);
    const target = parseInt(targetPort, 10);
    return target >= low && target <= high;
  }

  return false;
}

function isAnyToAnyAllow(rule: NsgRule): boolean {
  return (
    rule.access === 'Allow' &&
    isWildcardAddress(rule.sourceAddressPrefix) &&
    isWildcardAddress(rule.destinationAddressPrefix) &&
    (rule.destinationPortRange === '*' || rule.sourcePortRange === '*') &&
    rule.protocol === '*'
  );
}

function hasExplicitDenyAll(rules: NsgRule[], direction: NsgRule['direction']): boolean {
  return rules.some(
    r => r.direction === direction && r.access === 'Deny' && isWildcardAddress(r.sourceAddressPrefix) && isWildcardAddress(r.destinationAddressPrefix) && r.destinationPortRange === '*'
  );
}

function isWidePortRange(portRange: string): boolean {
  if (portRange === '*') { return true; }
  const rangeMatch = portRange.match(/^(\d+)-(\d+)$/);
  if (rangeMatch) {
    const span = parseInt(rangeMatch[2], 10) - parseInt(rangeMatch[1], 10);
    return span > 100;
  }
  return false;
}

function isHardcodedPublicIp(address: string): boolean {
  if (!address || isWildcardAddress(address)) { return false; }
  // Check if it looks like a specific public IP (not a private range, not a service tag)
  const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/;
  if (!ipPattern.test(address)) { return false; }

  // Exclude private IP ranges
  const privateRanges = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
    '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.'];

  return !privateRanges.some(prefix => address.startsWith(prefix));
}
