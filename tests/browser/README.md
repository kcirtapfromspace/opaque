# Real browser acceptance

Build and run the native acceptance binaries:

```sh
CARGO_PROFILE_DEV_DEBUG=0 cargo build --locked -p opaque-web -p opaqued
cd tests/browser
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install --with-deps chromium
npm test
```

The daemon hashes the connecting executable before accepting its handshake.
Disabling DWARF debug symbols keeps that work within the existing production IPC
deadline. The live fixture observes an authenticated dashboard status response
from the real daemon before launching Chromium; token-file creation alone does
not establish readiness.

The pinned Chromium runtime drives actual `opaque-web` and `opaqued` processes
through their loopback HTTP and Unix sockets. Tests do not intercept routes or
replace the DOM. Each test owns its data directory, token, browser and process
groups; they are removed on success or failure. Provider credentials, native
approval UI and the user's existing daemon are not used. Set
`OPAQUE_BROWSER_BINARY_DIR` to select another directory of trusted build binaries.

The three cases cover authentication/lock/reload, literal rendering of hostile
policy text, keyboard tabs and mobile layout, and real daemon loss without
synthetic fallback. They complement the faster Node DOM regressions. This is
Chromium dashboard acceptance, not every browser, customer demo deployment,
visual/accessibility certification, or native human approval qualification.

A separate process regression creates an actual orphaned descendant, verifies
that cleanup removes its owned process group, and retains the cleanup failure.
Requiring forced termination fails acceptance even after the process is removed.
# Dashboard checks in workspace coverage

`collect_critical_coverage.py --acceptance browser` runs the same four Node tests,
including the three actual Chromium dashboard scenarios. The runner copies the
locked browser harness to private runtime output and uses the collector's exact
`opaque-web` and `opaqued` binaries. Each observed Rust process must retain its own
fresh LLVM counters and preserve its binary hash and cleanup result. Browser and
JavaScript code are outside the Rust workspace percentage. macOS and Linux are
qualified separately. `--browser-cache` can select an existing Playwright engine
cache explicitly; otherwise the locked Playwright version installs its engine.
