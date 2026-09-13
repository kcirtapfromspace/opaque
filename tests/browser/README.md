# Real browser acceptance

Build `cargo build --locked -p opaque-web -p opaqued`, then run:

```sh
cd tests/browser
npm ci --ignore-scripts --no-audit --no-fund
npx playwright install --with-deps chromium
npm test
```

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
