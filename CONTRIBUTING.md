# Contributing to Azure Network Security Visualizer

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

1. Clone the repository
2. Run `npm install`
3. Open in VS Code and press **F5** to launch the Extension Development Host

## Build & Test

```bash
npm run compile        # Dev build
npm run watch          # Continuous rebuild
npm run test:unit      # Run unit tests (99 tests)
npm run lint           # ESLint
```

**Always run `npm run test:unit` before submitting a PR.**

## Project Structure

| Folder | Purpose |
|--------|---------|
| `src/parsers/` | Bicep/ARM template parsing |
| `src/analyzers/` | Security rule detection (NETSEC-001 through NETSEC-026) |
| `src/webview/` | D3-based topology visualization |
| `src/reports/` | HTML/Markdown/JSON/CSV report export |
| `src/models/` | TypeScript interfaces (pure types, no logic) |
| `src/azure/` | Azure Entra ID authentication and live topology via Resource Graph |

## Conventions

- **Named exports only** — no default exports
- **Rule IDs**: `NETSEC-###` (zero-padded, sequential)
- **Severity**: `'critical' | 'high' | 'warning' | 'info'`
- **Commands**: `azureNetSec.verbNoun` pattern
- **Line numbers**: 1-indexed in the model; subtract 1 for VS Code APIs
- Every `SecurityFinding` must include a `learnMoreUrl` pointing to Microsoft Learn

## Adding a Security Rule

1. Add the ID to `RULE_IDS` in `src/analyzers/securityAnalyzer.ts`
2. Implement detection logic
3. Add a test case in `src/test/suite/securityAnalyzer.test.ts`
4. Update the fixture in `src/test/fixtures/` if needed

## Reporting Issues

Please include:
- VS Code version
- Extension version
- Sample Bicep/ARM file that reproduces the issue (sanitized)
