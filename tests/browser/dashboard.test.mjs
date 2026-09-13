// Real Chromium, opaque-web, opaqued and their HTTP/Unix sockets. No route mocks.
import assert from 'node:assert/strict';
import {chmod, mkdtemp, readFile, realpath, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import test from 'node:test';
import {setTimeout as delay} from 'node:timers/promises';
import {chromium} from 'playwright';
import {processFixture} from './processes.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const binaries = resolve(process.env.OPAQUE_BROWSER_BINARY_DIR || join(root, 'target/debug'));
const hostileName = '<img src=x onerror="window.opaqueInjected=true">';

async function waitFor(check, description, timeout = 20_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await check()) return;
    await delay(25);
  }
  throw new Error(`Timed out: ${description}`);
}

async function fixture(t, {live = false, viewport} = {}) {
  const directory = await mkdtemp(join(await realpath(tmpdir()), 'oqbrowser-'));
  await chmod(directory, 0o700);
  const cleanup = [() => rm(directory, {recursive: true, force: true})];
  t.after(async () => {
    const errors = [];
    for (const close of cleanup.reverse()) {
      try { await close(); } catch (error) { errors.push(error); }
    }
    if (errors.length) throw new AggregateError(errors, 'owned browser/process cleanup failed');
  });
  const config = join(directory, 'config.toml');
  const socket = join(directory, 'run', 'opaqued.sock');
  await writeFile(config, `data_dir = ${JSON.stringify(directory)}\nenable_task_grants = true\n\n[trust_domain]\nsocket_path = ${JSON.stringify(socket)}\n\n[[rules]]\nname = '${hostileName}'\noperation_pattern = "test.noop"\nallow = false\n`, {mode: 0o600});
  // Only the selected data/config/socket is used. No ambient provider credentials.
  const env = {PATH: process.env.PATH, HOME: directory, LANG: 'C', RUST_LOG: 'info', OPAQUE_CONFIG: config};
  let daemon;
  if (live) {
    daemon = processFixture(join(binaries, 'opaqued'), [], env);
    cleanup.push(() => daemon.stop());
    await waitFor(async () => {
      daemon.alive();
      try { await readFile(join(directory, 'run/daemon.token')); return true; } catch { return false; }
    }, 'real daemon socket/token');
  }
  const web = processFixture(join(binaries, 'opaque-web'), ['--port', '0', '--data-dir', directory, '--config', config, '--socket', socket], env);
  cleanup.push(() => web.stop());
  await waitFor(() => {
    web.alive();
    return /opaque-web listening on http:\/\/127\.0\.0\.1:\d+/.test(web.output);
  }, 'real dashboard listener');
  const url = web.output.match(/opaque-web listening on (http:\/\/127\.0\.0\.1:\d+)/)[1];
  const token = (await readFile(join(directory, 'web.token'), 'utf8')).trim();
  assert.match(token, /^[a-zA-Z0-9_-]+$/);
  const browser = await chromium.launch();
  cleanup.push(() => browser.close());
  const context = await browser.newContext({viewport});
  const page = await context.newPage();
  const pageErrors = [];
  const requests = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  page.on('request', request => requests.push({url: request.url(), method: request.method()}));
  t.after(() => {
    assert.deepEqual(pageErrors, [], 'browser JavaScript errors');
    assert.ok(requests.every(request => request.url.startsWith(url + '/')), 'browser must not contact external services');
    assert.ok(requests.every(request => !request.url.includes(token)), 'owner token must never enter URLs');
  });
  await page.goto(url);
  await page.locator('#unlock-panel').waitFor({state: 'visible'});
  async function unlock(value = token) {
    await page.getByLabel('Owner token', {exact: true}).fill(value);
    await page.getByRole('button', {name: 'Unlock dashboard', exact: true}).click();
    if (value === token) await page.locator('#dashboard-private').waitFor({state: 'visible'});
  }
  return {page, context, token, requests, unlock, daemon, directory};
}

test('owner authentication, lock and reload clear private state in Chromium', {timeout: 60_000}, async t => {
  const {page, context, token, requests, unlock} = await fixture(t);
  assert.equal(requests.filter(request => new URL(request.url).pathname.startsWith('/api/')).length, 0);
  await unlock('wrong-owner-token');
  await page.getByText('The owner token was not accepted.', {exact: false}).waitFor();
  assert.equal(await page.locator('#dashboard-private').isVisible(), false);
  await unlock();
  await page.getByRole('tab', {name: 'Policy', exact: false}).click();
  await page.locator('#policy-rules-list').getByText(hostileName, {exact: true}).waitFor();
  assert.equal(await page.locator('#policy-rules-list img').count(), 0);
  assert.equal(await page.evaluate(() => window.opaqueInjected), undefined);
  const storage = await context.storageState();
  assert.ok(!JSON.stringify(storage).includes(token));
  assert.equal(await page.evaluate(() => sessionStorage.length), 0);
  await page.getByRole('button', {name: 'Lock dashboard', exact: true}).click();
  assert.equal(await page.locator('#dashboard-private').isVisible(), false);
  assert.equal(await page.locator('#policy-rules-list').textContent(), '');
  assert.equal(await page.getByLabel('Owner token', {exact: true}).inputValue(), '');
  await unlock();
  await page.reload();
  await page.locator('#unlock-panel').waitFor({state: 'visible'});
  assert.equal(await page.locator('#dashboard-private').isVisible(), false);
});

test('keyboard tabs and mobile layout work against the real dashboard', {timeout: 60_000}, async t => {
  const {page, unlock} = await fixture(t, {viewport: {width: 390, height: 844}});
  await unlock();
  const tasks = page.locator('#tab-tasks');
  await tasks.focus();
  for (const name of ['audit', 'policy', 'sessions', 'operations']) {
    await page.keyboard.press('ArrowDown');
    assert.equal(await page.locator(`#tab-${name}`).getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator(`#panel-${name}`).isVisible(), true);
    assert.equal(await page.evaluate(() => document.activeElement.id), `tab-${name}`);
  }
  await page.keyboard.press('Home');
  assert.equal(await tasks.getAttribute('aria-selected'), 'true');
  const dimensions = await page.evaluate(() => ({width: document.documentElement.clientWidth, content: document.documentElement.scrollWidth}));
  assert.ok(dimensions.content <= dimensions.width + 1, 'mobile page must not overflow horizontally');
  await page.getByRole('button', {name: 'Switch to paper theme'}).click();
  assert.equal(await page.getByRole('button', {name: 'Switch to dark theme'}).count(), 1);
});

test('live daemon inventory becomes unavailable after process loss without synthetic fallback', {timeout: 60_000}, async t => {
  const {page, unlock, daemon} = await fixture(t, {live: true});
  await unlock();
  await page.locator('#mode-label').getByText('LIVE', {exact: true}).waitFor();
  await page.getByRole('tab', {name: 'Operations', exact: false}).click();
  await page.locator('#operations-content').getByText('test.noop', {exact: true}).waitFor();
  assert.equal(await page.locator('#connection-banner').textContent().then(text => text.includes('Synthetic')), false);
  await daemon.stop();
  await page.getByRole('tab', {name: 'Tasks', exact: false}).click();
  await page.getByRole('tab', {name: 'Operations', exact: false}).click();
  await page.locator('#operations-content').getByText('Daemon disconnected;', {exact: false}).waitFor();
  assert.equal(await page.locator('#operations-content .op-card').count(), 0);
  await page.locator('#mode-label').getByText('DISCONNECTED', {exact: true}).waitFor({timeout: 15_000});
  assert.equal(await page.locator('#connection-banner').textContent().then(text => text.includes('DEMO')), false);
});
