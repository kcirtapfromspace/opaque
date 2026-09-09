import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { Scheduler } from '../src/scheduler.mjs';
import { LIMITS } from '../src/queue.mjs';

const NOW = 1_800_000_000_000;
const visitor = 'a'.repeat(64);

// Real SQLite verifies committed changes and lease fences; alarm calls model
// the asynchronous storage boundary where concurrent events could interleave.
function fixture(t) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const storage = {
    alarm: null, alarmWrites: [],
    sql: { exec(sql, ...args) { const rows = db.prepare(sql).all(...args); return { toArray: () => rows }; } },
    transactionSync(callback) {
      db.exec('BEGIN IMMEDIATE');
      try { const result = callback(); db.exec('COMMIT'); return result; }
      catch (error) { db.exec('ROLLBACK'); throw error; }
    },
    async getAlarm() { return this.alarm; },
    async setAlarm(time) { this.alarmWrites.push(time); this.alarm = time; },
    async deleteAlarm() { this.alarmWrites.push(null); this.alarm = null; },
  };
  const env = { DEMO_CAPACITY: '1', DEMO_MODEL_IDS: 'gemma4-e2b' };
  const f = { storage, env, now: NOW };
  t.mock.method(Date, 'now', () => f.now);
  f.scheduler = new Scheduler({ storage }, env);
  f.state = () => JSON.parse(db.prepare('SELECT value FROM demo_queue_state WHERE id=1').get().value);
  f.changes = () => db.prepare('SELECT total_changes() AS n').get().n;
  f.send = (action, ...args) => f.scheduler.fetch(new Request('https://scheduler.invalid/', {
    method: 'POST', body: JSON.stringify({ action, args }),
  }));
  f.call = async (action, ...args) => {
    const response = await f.send(action, ...args);
    assert.equal(response.status, 200, await response.clone().text());
    return response.json();
  };
  f.ready = async () => {
    await f.call('admit', visitor, 'b'.repeat(64), 'gemma4-e2b');
    const provision = (await f.call('work')).actions[0];
    f.now++;
    return f.call('report', { kind: 'ready', lease_id: provision.lease_id, slot: provision.slot, generation: provision.generation });
  };
  return f;
}

test('one idle day at thirty-second polling commits one watermark per poll and no alarm writes', async t => {
  const f = fixture(t), baseline = f.changes();
  for (let i = 0; i < 2_880; i++) {
    f.now = NOW + i * 30_000;
    const work = await f.call('work');
    assert.deepEqual(work, { actions: [], next_alarm_at: null, next_poll_at: null });
  }
  assert.equal(f.changes() - baseline, 2_880);
  assert.deepEqual(f.storage.alarmWrites, []);
  assert.equal(f.state().last_now, f.now);
});

test('identical and backwards-time polls skip writes without rolling back the persisted watermark', async t => {
  const f = fixture(t);
  await f.call('work');
  const baseline = f.changes();
  for (let i = 0; i < 3; i++) { f.now--; await f.call('work'); }
  assert.equal(f.changes(), baseline);
  assert.equal(f.state().last_now, NOW);
  f.now = NOW + 1;
  await f.call('work');
  assert.equal(f.changes(), baseline + 1);
});

test('polling and a scheduler restart preserve an existing alarm without rewriting it', async t => {
  const f = fixture(t), lease = await f.ready();
  const alarmWrites = f.storage.alarmWrites.length;
  for (let i = 0; i < 3; i++) {
    f.now += 30_000;
    const baseline = f.changes();
    const work = await f.call('work');
    assert.equal(work.next_alarm_at, lease.expires_at);
    assert.equal(work.next_poll_at, lease.expires_at);
    assert.equal(f.changes() - baseline, 1);
  }
  f.scheduler = new Scheduler({ storage: f.storage }, f.env);
  f.now++;
  await f.call('work');
  assert.equal(f.storage.alarm, lease.expires_at);
  assert.equal(f.storage.alarmWrites.length, alarmWrites);
});

test('expiry alarm fences the lease and keeps cleanup pending until deletion evidence arrives', async t => {
  const f = fixture(t), lease = await f.ready();
  f.now = lease.expires_at;
  f.storage.alarm = null; // A firing alarm is no longer scheduled.
  await f.scheduler.alarm();
  const work = await f.call('work'), cleanup = work.actions[0];
  assert.equal(cleanup.kind, 'cleanup');
  assert.ok(cleanup.generation > lease.generation);
  assert.equal(f.state().tickets[0].state, 'cleaning');
  assert.notEqual((await f.send('authorize', visitor)).status, 200);
  await f.call('report', { kind: 'cleaned', lease_id: cleanup.lease_id, slot: cleanup.slot, generation: cleanup.generation,
    resources_deleted: true, provisioning_stopped: true, execution_stopped: true });
  assert.equal(f.storage.alarm, f.now + LIMITS.historyMs);
  assert.equal(f.state().tickets[0].state, 'expired');
});

test('a firing alarm rearms a future deadline, and history expiry does not leave an alarm loop', async t => {
  const f = fixture(t), lease = await f.ready();
  const writes = f.storage.alarmWrites.length;
  f.storage.alarm = null;
  f.now++;
  await f.scheduler.alarm();
  assert.equal(f.storage.alarm, lease.expires_at);
  assert.equal(f.storage.alarmWrites.length, writes + 1);
  await f.call('cancel', visitor);
  const cleanup = (await f.call('work')).actions[0];
  await f.call('report', { kind: 'cleaned', lease_id: cleanup.lease_id, slot: cleanup.slot, generation: cleanup.generation,
    resources_deleted: true, provisioning_stopped: true, execution_stopped: true });
  f.now = f.storage.alarm;
  f.storage.alarm = null;
  const beforeExpiry = f.storage.alarmWrites.length;
  await f.scheduler.alarm();
  assert.deepEqual(f.state().tickets, []);
  assert.equal(f.storage.alarm, null);
  assert.equal(f.storage.alarmWrites.length, beforeExpiry);
});

test('a delayed alarm read cannot overwrite a concurrent cancellation with the old lease deadline', async t => {
  const f = fixture(t);
  await f.ready();
  let release, entered;
  const reachedRead = new Promise(resolve => { entered = resolve; });
  const heldRead = new Promise(resolve => { release = resolve; });
  const original = f.storage.getAlarm;
  f.storage.getAlarm = async function () {
    this.getAlarm = original;
    entered();
    await heldRead;
    return this.alarm;
  };
  f.now++;
  const poll = f.call('work');
  await reachedRead;
  const cancellation = f.call('cancel', visitor);
  await nextTurn();
  assert.equal(f.state().tickets[0].state, 'ready');
  release();
  await Promise.all([poll, cancellation]);
  assert.equal(f.state().tickets[0].state, 'cleaning');
  assert.equal(f.storage.alarm, null);
  assert.equal((await f.call('work')).actions[0].kind, 'cleanup');
});

test('failed storage access does not poison later requests or lose committed lease fences', async t => {
  const f = fixture(t);
  await f.ready();
  const original = f.storage.getAlarm;
  f.storage.getAlarm = async () => { throw new Error('storage temporarily unavailable'); };
  const response = await f.send('cancel', visitor);
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: 'scheduler_unavailable' });
  assert.equal(f.state().tickets[0].state, 'cleaning');
  f.storage.getAlarm = original;
  assert.equal((await f.call('work')).actions[0].kind, 'cleanup');
  assert.equal(f.storage.alarm, null);
});

test('quarantined cleanup advertises its retry deadline without creating recurring storage alarms', async t => {
  const f = fixture(t);
  await f.ready();
  await f.call('cancel', visitor);
  const cleanup = (await f.call('work')).actions[0];
  await f.call('report', { kind: 'failed', lease_id: cleanup.lease_id, slot: cleanup.slot, generation: cleanup.generation });
  const work = await f.call('work');
  assert.deepEqual(work.actions, []);
  assert.equal(work.next_alarm_at, null);
  assert.equal(work.next_poll_at, f.now + 5_000);
  assert.equal(f.storage.alarm, null);
  f.now = work.next_poll_at;
  assert.equal((await f.call('work')).actions[0].kind, 'cleanup');
});

test('a rejected alarm remains retryable and does not block subsequent controller work', async t => {
  const f = fixture(t), lease = await f.ready();
  const original = f.storage.getAlarm;
  f.storage.getAlarm = async () => { throw new Error('temporary alarm failure'); };
  await assert.rejects(f.scheduler.alarm(), /temporary alarm failure/);
  f.storage.getAlarm = original;
  assert.equal((await f.call('work')).next_alarm_at, lease.expires_at);
  assert.equal(f.state().tickets[0].state, 'ready');
});
