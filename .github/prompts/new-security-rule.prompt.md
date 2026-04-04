---
description: "Scaffold a new NETSEC security rule: analyzer logic, test case, and fixture update"
agent: "agent"
argument-hint: "Describe the security issue to detect (e.g., 'flag subnets without service endpoints')"
---

Add a new security rule to the Network Security Visualizer extension.

## Steps

1. **Determine the next rule ID**: Read `src/analyzers/securityAnalyzer.ts`, find the last `NETSEC-###` in the `RULE_IDS` constant, and increment by 1 (zero-padded to 3 digits).

2. **Add the rule ID** to the `RULE_IDS` constant in `src/analyzers/securityAnalyzer.ts` with a descriptive key name in SCREAMING_SNAKE_CASE.

3. **Implement the detection function** in `src/analyzers/securityAnalyzer.ts`:
   - Accept the relevant topology type (`NetworkSecurityGroup`, `VirtualNetwork`, `Subnet`, etc.)
   - Return `SecurityFinding[]`
   - Every finding must include:
     - `id`: The new NETSEC ID
     - `severity`: one of `'critical' | 'high' | 'warning' | 'info'`
     - `title`, `description`, `recommendation`
     - `learnMoreUrl`: a valid Microsoft Learn URL
     - `resourceId`, `resourceType`, `resourceName`
   - Wire the function into `analyzeTopology()`

4. **Add a fixture** to `src/test/fixtures/sample-network.bicep` that triggers the new rule (if the existing fixture doesn't already cover the scenario).

5. **Write tests** in `src/test/suite/securityAnalyzer.test.ts`:
   - One `describe` block named after the rule ID and title
   - At least 2 `it` blocks: one for detection, one verifying severity
   - Use `assert.ok()` and `assert.strictEqual()` (Node built-in `assert`)
   - Load fixture via `buildTopologyFromBicep()` helper already in the test file

6. **Run tests**: `npm run test:unit` — all must pass including existing tests.

## Conventions

- Named exports only, no default exports
- Try-catch returning `[]` on errors — never throw to extension host
- Lines are 1-indexed in the model; subtract 1 for VS Code APIs
