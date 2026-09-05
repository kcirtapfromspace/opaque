import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import worker from '../src/worker.mjs';

test('every routed request returns the same non-cacheable, non-indexable 404', async () => {
  for (const path of [
    '/product',
    '/product/',
    '/product/2026-09-04-organization-consumers/',
    '/dogfood/',
    '/release-dogfood/',
    '/tenant-boundaries/?cache-bust=fixture',
  ]) {
    for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS']) {
      const response = worker.fetch(new Request('https://opaque.info' + path, {method}));
      assert.equal(response.status, 404, method + ' ' + path);
      assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
      assert.equal(response.headers.get('cache-control'), 'no-store');
      assert.equal(response.headers.get('x-robots-tag'), 'noindex, noarchive');
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('location'), null);
      assert.equal(response.headers.get('set-cookie'), null);
      assert.equal(await response.text(), 'Not found.\n');
    }
  }
});

test('request content, bindings and upstream availability cannot affect the response', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('The privacy guard must never contact an upstream'); };
  try {
    const hostile = new Proxy({}, {get() { throw new Error('No request, binding or context access is needed'); }});
    const response = worker.fetch(hostile, hostile, hostile);
    assert.equal(response.status, 404);
    assert.equal(await response.text(), 'Not found.\n');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('routes cover only the requested private documentation paths', () => {
  const config = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');
  const patterns = [...config.matchAll(/^pattern = "([^"]+)"$/gm)].map(match => match[1]);
  assert.deepEqual(patterns, [
    'opaque.info/product/*',
    'opaque.info/product',
    'opaque.info/dogfood*',
    'opaque.info/release-dogfood*',
    'opaque.info/tenant-boundaries*',
    'www.opaque.info/product/*',
    'www.opaque.info/product',
    'www.opaque.info/dogfood*',
    'www.opaque.info/release-dogfood*',
    'www.opaque.info/tenant-boundaries*',
  ]);
  assert.equal([...config.matchAll(/^zone_name = "opaque\.info"$/gm)].length, patterns.length);
  assert.match(config, /^workers_dev = false$/m);
  assert.match(config, /^preview_urls = false$/m);
  assert.doesNotMatch(config, /\[assets\]|\[vars\]|binding\s*=|custom_domain\s*=/);
});
