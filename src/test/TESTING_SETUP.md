# Running these tests

## 1. Place the files
Copy all `*.test.ts` files into your repo's `test/` folder (alongside your
existing `customPatterns.test.ts`). Copy `.mocharc.json` to your repo root.

## 2. Install dev dependencies (if not already present)
```bash
npm install --save-dev mocha chai ts-node typescript @types/chai @types/mocha @types/node
```

## 3. Fix the import paths
Every test file has an `ASSUMPTIONS` comment block at the top listing what
it expects to import and why. Your real exports may differ — go through each
file and:

- Fix `import` paths to match your actual `src/` file names
- **Extract inline logic into testable pure functions** where noted — most
  importantly `secureCopyTransform` and `securePasteTransform`. If this logic
  currently lives directly inside the `smartCopy`/`smartPaste` VS Code command
  callbacks in `extension.ts`, pull the core logic (input in, output out —
  no `vscode.*` API calls) into its own file. This is the single most useful
  refactor for testability, and it also makes the logic reusable for AI Mode.
- Adjust method signatures (e.g., if `CryptoService.encrypt` returns an object
  instead of a string, update the assertions accordingly)

## 4. Add the test script to package.json (if not already there)
```json
{
  "scripts": {
    "test": "mocha"
  }
}
```

## 5. Run it
```bash
npm test
```

## 6. Read the benchmark output
`detectionBenchmark.test.ts` prints a precision/recall table to the console —
this always passes as an informational test, but two other tests in that file
will actually **fail the build** if recall drops below 80% or the false-positive
rate exceeds 20%. Treat those thresholds as a starting point; tighten them as
your detection engine matures. Add more labeled samples over time — the file
is intentionally structured so that's a two-line addition, not a refactor.

## What's NOT covered here
- End-to-end tests that drive the actual VS Code UI (status bar clicks,
  real clipboard API, real editor documents). That requires
  `@vscode/test-electron` and is a bigger lift — worth doing before a 1.0
  public release, but the unit-level tests here are the higher-value first step.
- Load/performance testing at real repo scale (thousands of files) —
  the workspace scan tests use small temp directories, not a stress test.
