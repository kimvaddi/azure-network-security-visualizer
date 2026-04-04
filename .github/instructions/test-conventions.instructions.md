---
description: "Use when writing, modifying, or reviewing test files. Enforces Mocha + assert patterns, fixture loading, and no-mock conventions."
applyTo: "src/test/**"
---

# Test Conventions

## Framework

- **Mocha** with `describe`/`it` blocks
- **Node built-in `assert`** — no chai, no sinon, no jest
- Use `assert.ok()` for existence checks, `assert.strictEqual()` for values

## Structure

- File: `src/test/suite/<module>.test.ts`
- Outer `describe`: module name (e.g., `'BicepParser'`)
- Inner `describe`: function or rule being tested
- Each `it` block tests one behavior

## Fixtures

- Location: `src/test/fixtures/`
- Load with `fs.readFileSync` in a `before()` hook
- Path resolution: `path.join(__dirname, '..', '..', '..', 'src', 'test', 'fixtures')`
- Keep fixtures minimal — only resources needed for the scenario

## No Mocks

Tests exercise real code against fixture files. No stubs, mocks, or dependency injection. The parsers and analyzers are pure functions — pass data in, assert on output.

## Running

```bash
npm run test:unit    # Mocha + ts-node, no compilation
npm test             # Integration tests (requires npm run pretest first)
```
