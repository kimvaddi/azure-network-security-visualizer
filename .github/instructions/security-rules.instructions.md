---
description: "Use when creating, modifying, or reviewing security analysis rules (NETSEC-###). Enforces rule ID format, severity conventions, MS Learn links, and finding structure."
applyTo: "src/analyzers/**"
---

# Security Rule Conventions

## Rule IDs

- Format: `NETSEC-###` (zero-padded, sequential)
- Defined in the `RULE_IDS` constant in `securityAnalyzer.ts`
- Key name: `SCREAMING_SNAKE_CASE` describing the issue

## SecurityFinding Requirements

Every finding **must** include:
- `id`: Rule ID from `RULE_IDS`
- `severity`: `'critical' | 'high' | 'warning' | 'info'`
- `title`: Short human-readable label
- `description`: What was found
- `recommendation`: How to fix it
- `learnMoreUrl`: Valid Microsoft Learn URL (never fabricate)
- `resourceId`, `resourceType`, `resourceName`: Identify the offending resource

## Severity Guidelines

| Severity | When |
|----------|------|
| `critical` | Direct exposure to internet — open SSH/RDP, any-to-any allow |
| `high` | Missing controls — no NSG on subnet, no deny-all, permissive source |
| `warning` | Suboptimal config — wide port ranges, hardcoded IPs, threat intel off |
| `info` | Advisory — missing flow logs, overlapping rules |

## Error Handling

- Detection functions return `SecurityFinding[]`
- Wrap in try-catch returning `[]` on error — never throw to the extension host
- Wire new detection functions into `analyzeTopology()`

## Testing

Every new rule needs at least 2 test cases in `securityAnalyzer.test.ts`:
1. Detection — verify the finding is raised
2. Severity — verify the correct severity level
