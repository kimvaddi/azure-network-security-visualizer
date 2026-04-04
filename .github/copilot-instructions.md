# Project Guidelines — Network Security Visualizer

VS Code extension that parses Azure Bicep/ARM templates, analyzes network security posture, and visualizes topology with D3.js.

## Build and Test

```bash
npm run compile        # Dev build → dist/extension.js (esbuild, sourcemaps)
npm run watch          # Continuous rebuild on file change
npm run package        # Production build (minified, no sourcemaps)
npm run test:unit      # Mocha + ts-node — 85 tests across 4 suites
npm run lint           # ESLint on src/**/*.ts
```

Test before every commit: `npm run test:unit`. Tests use `assert` (Node built-in) with fixtures in `src/test/fixtures/`.

Debug: **F5** → "Run Extension" launches an Extension Development Host with esbuild watch.

Publisher ID for marketplace operations: **KimVaddi** (case-sensitive).

## Architecture

```
Bicep/ARM file → Parser → Partial<NetworkTopology> → extension.ts merges →
  → SecurityAnalyzer → SecurityFinding[]
  → TopologyWebviewProvider (D3 visualization)
  → ReportGenerator (HTML/Markdown/JSON export)
  → VS Code Diagnostics (inline warnings)
```

| Module | Role |
|--------|------|
| `src/models/networkModel.ts` | Pure interfaces only — `NetworkTopology`, `SecurityFinding`, `NsgRule`, etc. (18 types, zero logic) |
| `src/parsers/bicepParser.ts` | Regex-based Bicep extraction → `Partial<NetworkTopology>` |
| `src/parsers/armParser.ts` | JSON-based ARM template parsing → `Partial<NetworkTopology>` |
| `src/analyzers/securityAnalyzer.ts` | 14 security rules (NETSEC-001–014) based on MS Security Benchmark |
| `src/reports/reportGenerator.ts` | Exports findings+topology as HTML, Markdown, or JSON |
| `src/webview/webviewProvider.ts` | Interactive D3 topology diagram in webview panel |
| `src/azure/azureAuth.ts` | Entra ID authentication via VS Code session, subscription picker |
| `src/azure/liveTopology.ts` | Azure Resource Graph queries → `NetworkTopology` for live resources |
| `src/extension.ts` | Entry point — commands, multi-file merge, diagnostics, tree views, status bar |

## Conventions

- **Commands**: `azureNetSec.verbNoun` (camelCase, dot-namespaced). Current: `visualize`, `analyzeFile`, `analyzeWorkspace`, `exportReport`, `showEffectiveRules`, `connectAzure`, `visualizeLive`
- **Settings**: `azureNetSec.severityThreshold`, `autoAnalyzeOnSave` (default true), `showInlineDecorations`, `reportFormat` (html/markdown/json/csv)
- **Rule IDs**: `NETSEC-###` (zero-padded, sequential)
- **Severity**: lowercase literal union `'critical' | 'high' | 'warning' | 'info'`
- **Exports**: Named exports only (no default exports). Models are pure interfaces, no classes.
- **Parsers** return `Partial<NetworkTopology>`; `extension.ts` merges results across files.
- **Error handling**: Try-catch returning `null` or `[]`; parse errors collected in `ParseResult.parseErrors`. No thrown exceptions to extension host.
- **Source traceability**: Use `sourceLocation?: { filePath: string; line: number }` on resources and rules. Lines are 1-indexed in the model; convert to 0-indexed for VS Code `Range`/`Position`.
- **MS Learn links**: Every `SecurityFinding` must have a `learnMoreUrl` pointing to Microsoft Learn.
- **Settings**: Check `azureNetSec.*` configuration before hardcoding behavior. Auto-analyze-on-save is on by default.

## Tests

- **Framework**: Mocha + `assert` (Node built-in). No chai, no mocks — tests exercise real code against fixtures.
- **Add tests**: Create `src/test/suite/<module>.test.ts`, use `describe`/`it` blocks, load fixtures via `fs.readFileSync` with paths relative to `__dirname`.
- **Fixtures**: `src/test/fixtures/` — add sample Bicep/ARM files here.
- **Run**: `npm run test:unit` (Mocha + ts-node, no compilation needed).
- **Integration tests**: `npm test` (requires `npm run pretest` → compiles to `out/`, runs via `@vscode/test-electron`).

## Private Files

Tests, runbook, and prompts.txt are `.gitignore`d — they are development-only and not shipped in the .vsix.

## Pitfalls

- **Bicep parser is regex-based** — misses complex expressions, module references, and multi-line comments. Consider `bicep build` for future improvements.
- **ARM parser does not resolve parameters/variables** — literal values only.
- **Line number off-by-one**: Model uses 1-indexed lines; VS Code APIs use 0-indexed. Always subtract 1 when creating `Range`/`Position`.
- **esbuild externals**: `vscode` must stay in the externals list in `esbuild.js`. Do not bundle it.
- **D3 and the Azure SDKs are the only runtime dependencies** — keep it that way. Everything else should be a devDependency.
- **Azure SDKs** (`@azure/identity`, `@azure/arm-resourcegraph`, `@azure/arm-resources-subscriptions`) are runtime deps for live topology. They are lazy-loaded only when the user signs in.
- **TypeScript strict mode** is enabled and intentional. Do not relax it.

## Documentation

- [README.md](../README.md) — User-facing features, commands, configuration, supported resources
- [CHANGELOG.md](../CHANGELOG.md) — Release notes
- [runbook/RUNBOOK.md](../runbook/RUNBOOK.md) — Internal implementation details, test results, known limitations, and audit trail (the authoritative internal reference)
