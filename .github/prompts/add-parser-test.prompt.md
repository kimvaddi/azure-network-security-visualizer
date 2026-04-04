---
description: "Add a new parser test with a Bicep or ARM fixture file"
agent: "agent"
argument-hint: "Describe the parsing scenario (e.g., 'VNet peering with remote gateway')"
---

Add a new parser test case for the Bicep or ARM parser.

## Steps

1. **Create or update a fixture** in `src/test/fixtures/`:
   - Bicep fixtures: `*.bicep` files with realistic Azure resource declarations
   - ARM fixtures: `*.json` files with valid ARM template structure
   - Keep fixtures minimal — only the resources needed for the test scenario

2. **Add test cases** to the appropriate test file:
   - Bicep: `src/test/suite/bicepParser.test.ts`
   - ARM: `src/test/suite/armParser.test.ts`

3. **Follow existing test patterns**:
   ```typescript
   import * as assert from 'assert';
   import * as fs from 'fs';
   import * as path from 'path';

   const FIXTURES_DIR = path.join(__dirname, '..', '..', '..', 'src', 'test', 'fixtures');

   // Load fixture in before() hook
   before(() => {
     content = fs.readFileSync(path.join(FIXTURES_DIR, 'my-fixture.bicep'), 'utf-8');
   });

   // Call parser with filePath option
   const result = parseBicepFile(content, { filePath: 'test.bicep' });

   // Assert with Node built-in assert
   assert.ok(result.vnets, 'vnets should exist');
   assert.strictEqual(result.vnets!.length, 1);
   ```

4. **Use nested describe blocks**: outer = module name, inner = function name or scenario.

5. **Run tests**: `npm run test:unit` — all must pass.

## Conventions

- No chai, no mocks — tests exercise real code against fixtures
- Use `assert.ok()` for existence, `assert.strictEqual()` for values
- Parsers return `Partial<NetworkTopology>` — always use `!` after null checks
