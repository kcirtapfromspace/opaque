import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DemoQueue, SqliteQueueStore, QueueError, LIMITS } from "../src/queue.mjs";

const NOW = 1_800_000_000_000;
const visitor = (number) => number.toString(16).padStart(64, "0");
const throws = (callback, code) => assert.throws(callback, (error) => error instanceof QueueError && error.code === code);

// Exercise real SQLite transactions, not a mock that assumes atomicity. This
// implements only the Cloudflare storage calls used by SqliteQueueStore.
class SqliteHost {
  constructor(path = ":memory:") {
    this.db = new DatabaseSync(path);
    // Cloudflare sql.exec runs immediately, including statements with no rows.
    this.sql = { exec: (sql, ...args) => {
      const rows = this.db.prepare(sql).all(...args);
      return { toArray: () => rows };
    } };
  }
  transactionSync(callback) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = callback();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
  state() { return JSON.parse(this.db.prepare("SELECT value FROM demo_queue_state WHERE id=1").get().value); }
  overwrite(state) { this.db.prepare("UPDATE demo_queue_state SET value=? WHERE id=1").run(typeof state === "string" ? state : JSON.stringify(state)); }
  close() { this.db.close(); }
}

function fixture(t, config = {}, database = ":memory:") {
  const host = new SqliteHost(database);
  const store = new SqliteQueueStore(host);
  let sequence = 0;
  const options = { id: () => (++sequence).toString(16).padStart(32, "0") };
  const queue = new DemoQueue(store, config, options);
  t.after(() => host.close());
  return { host, store, options, queue };
}

function ready(queue, hash, now = NOW, modelId = "gemma4-e2b") {
  queue.join(hash, modelId, now);
  const work = queue.work(now);
  const status = queue.status(hash, now);
  const action = work.actions.find((item) => item.lease_id === status.lease_id);
  assert.equal(action.kind, "provision");
  return queue.report({ kind: "ready", lease_id: action.lease_id, slot: action.slot, generation: action.generation }, now + 1);
}

function clean(queue, view, now, extra = {}) {
  return queue.report({
    kind: "cleaned", lease_id: view.lease_id, slot: view.slot, generation: view.generation,
    resources_deleted: true, provisioning_stopped: true, ...extra,
  }, now);
}

test("100 parallel joins and scheduler pulls reserve only configured slots", async (t) => {
  for (const capacity of [1, 2]) {
    await t.test(`capacity ${capacity}`, async (t) => {
      const { queue, host } = fixture(t, { capacity });
      await Promise.all(Array.from({ length: 100 }, (_, index) => Promise.resolve().then(() => queue.join(visitor(index + 1), "gemma4-e2b", NOW))));
      const pulls = await Promise.all(Array.from({ length: 100 }, () => Promise.resolve().then(() => queue.work(NOW + 1))));
      assert.ok(pulls.every((pull) => pull.actions.length === capacity));
      assert.equal(new Set(pulls.flatMap((pull) => pull.actions.map((item) => item.lease_id))).size, capacity);
      const state = host.state();
      assert.equal(state.tickets.filter((ticket) => ticket.state === "provisioning").length, capacity);
      assert.equal(new Set(state.tickets.filter((ticket) => ticket.lease_id).map((ticket) => ticket.slot)).size, capacity);
    });
  }
});

test("public ordering is FIFO and repeated join cannot elevate priority or extend TTL", (t) => {
  const { queue } = fixture(t);
  const first = queue.join(visitor(1), "gemma4-e2b", NOW);
  queue.join(visitor(2), "gemma4-e2b", NOW + 1);
  const repeated = queue.join(visitor(1), "gemma4-e2b", NOW + 10_000, 1);
  assert.equal(repeated.queued_at, first.queued_at);
  assert.equal(repeated.queue_expires_at, first.queue_expires_at);
  assert.equal(repeated.queue_position, 1);
  queue.join(visitor(3), "gemma4-e2b", NOW + 10_001, 1);
  queue.work(NOW + 10_002);
  assert.equal(queue.status(visitor(3), NOW + 10_002).state, "provisioning");
  assert.equal(queue.status(visitor(1), NOW + 10_002).state, "queued");
});

test("aging prevents a new high-priority visitor from starving an old public visitor", (t) => {
  const { queue } = fixture(t);
  queue.join(visitor(1), "gemma4-e2b", NOW, 0);
  queue.join(visitor(2), "gemma4-e2b", NOW + LIMITS.agingMs, 1);
  assert.equal(queue.status(visitor(1), NOW + LIMITS.agingMs).queue_position, 1);
  queue.work(NOW + LIMITS.agingMs);
  assert.equal(queue.status(visitor(1), NOW + LIMITS.agingMs).state, "provisioning");
});

test("provisioning timeout fences late ready and retains the slot until cleanup acknowledgement", (t) => {
  const { queue } = fixture(t);
  queue.join(visitor(1), "gemma4-e2b", NOW);
  queue.join(visitor(2), "gemma4-e2b", NOW);
  const provision = queue.work(NOW).actions[0];
  assert.equal(provision.expires_at, NOW + LIMITS.provisionMs + LIMITS.leaseMs);
  assert.equal(provision.provision_deadline_at, NOW + LIMITS.provisionMs);
  const due = NOW + LIMITS.provisionMs;
  throws(() => queue.report({ kind: "ready", ...fields(provision) }, due), "stale_lease_generation");
  const cleanup = queue.work(due).actions;
  assert.equal(cleanup.length, 1);
  assert.equal(cleanup[0].kind, "cleanup");
  assert.equal(cleanup[0].lease_id, provision.lease_id);
  assert.equal(cleanup[0].generation, provision.generation + 1);
  assert.equal(queue.status(visitor(2), due).state, "queued");
  throws(() => queue.report({ kind: "cleaned", ...fields(cleanup[0]), resources_deleted: true }, due), "cleanup_evidence_required");
  assert.equal(queue.work(due + 1).actions[0].kind, "cleanup");
  const completed = clean(queue, cleanup[0], due + 2);
  assert.equal(completed.state, "failed");
  assert.equal(queue.work(due + 3).actions[0].kind, "provision");
  assert.notEqual(queue.status(visitor(2), due + 3).lease_id, provision.lease_id);
});

function fields(action) {
  return { lease_id: action.lease_id, slot: action.slot, generation: action.generation };
}

test("ready starts its fixed timer once; expiry denies authorization before an alarm runs", (t) => {
  const { queue } = fixture(t);
  queue.join(visitor(1), "gemma4-e2b", NOW);
  const provision = queue.work(NOW).actions[0];
  const first = queue.report({ kind: "ready", ...fields(provision) }, NOW + 119_000);
  assert.equal(first.expires_at, NOW + 119_000 + LIMITS.leaseMs);
  const duplicate = queue.report({ kind: "ready", ...fields(provision) }, NOW + 150_000);
  assert.equal(duplicate.expires_at, first.expires_at);
  assert.equal(queue.authorize(visitor(1), first.expires_at - 1).lease_id, first.lease_id);
  throws(() => queue.authorize(visitor(1), first.expires_at), "workspace_not_ready");
  assert.equal(queue.status(visitor(1), first.expires_at).state, "cleaning");
  assert.equal(queue.work(first.expires_at).actions[0].kind, "cleanup");
});

test("cancel is idempotent across queued and reserved work and never releases an uncertain slot", (t) => {
  const { queue } = fixture(t);
  queue.join(visitor(1), "gemma4-e2b", NOW);
  const queued = queue.cancel(visitor(1), NOW + 1);
  assert.equal(queued.state, "cancelled");
  assert.equal(queue.work(NOW + 2).actions.length, 0);
  assert.equal(queue.join(visitor(1), "gemma4-e2b", NOW + 3).state, "cancelled");
  ready(queue, visitor(2), NOW + 4);
  const cancelled = queue.cancel(visitor(2), NOW + 10);
  const repeated = queue.cancel(visitor(2), NOW + 11);
  assert.equal(cancelled.state, "cleaning");
  assert.equal(repeated.generation, cancelled.generation);
  throws(() => queue.authorize(visitor(2), NOW + 12), "workspace_not_ready");
  queue.join(visitor(3), "gemma4-e2b", NOW + 12);
  assert.ok(queue.work(NOW + 12).actions.every((action) => action.kind === "cleanup"));
  assert.equal(clean(queue, cancelled, NOW + 13).state, "cancelled");
  assert.equal(clean(queue, cancelled, NOW + 14).state, "cancelled");
  assert.equal(queue.work(NOW + 15).actions[0].kind, "provision");
});

test("cleanup failure quarantines rather than creating false capacity, across restart", (t) => {
  const { queue, store, options } = fixture(t);
  ready(queue, visitor(1));
  queue.join(visitor(2), "gemma4-e2b", NOW + 2);
  const cancelled = queue.cancel(visitor(1), NOW + 3);
  const failure = queue.report({ kind: "failed", ...fields(cancelled) }, NOW + 4);
  assert.equal(failure.state, "quarantined");
  const restarted = new DemoQueue(store, {}, options);
  assert.equal(restarted.work(NOW + 5).actions.length, 0);
  const retry = restarted.work(NOW + 5_004).actions;
  assert.equal(retry.length, 1);
  assert.equal(retry[0].kind, "cleanup");
  assert.equal(retry[0].generation, cancelled.generation);
  assert.equal(restarted.status(visitor(2), NOW + 5_004).state, "queued");
  throws(() => restarted.report({ kind: "cleaned", ...fields(cancelled), slot: 1, resources_deleted: true, provisioning_stopped: true }, NOW + 5_004), "stale_lease_generation");
  clean(restarted, retry[0], NOW + 5_005);
  assert.equal(restarted.work(NOW + 5_006).actions[0].kind, "provision");
});

test("sequential visitors reuse one slot with durable monotonic generations and stale report denial", (t) => {
  const { queue, store, options } = fixture(t);
  const first = ready(queue, visitor(1));
  const firstCleanup = queue.cancel(visitor(1), NOW + 2);
  clean(queue, firstCleanup, NOW + 3);
  const restarted = new DemoQueue(store, {}, options);
  const second = ready(restarted, visitor(2), NOW + 4);
  assert.equal(second.slot, first.slot);
  assert.notEqual(second.lease_id, first.lease_id);
  assert.ok(second.generation > firstCleanup.generation);
  // Old callbacks can only return the old terminal receipt; they never touch
  // the new occupant or resurrect a previously cleaned workspace.
  throws(() => restarted.report({ kind: "ready", ...fields(first) }, NOW + 6), "stale_lease_generation");
  assert.equal(clean(restarted, firstCleanup, NOW + 7).state, "cancelled");
  assert.equal(restarted.authorize(visitor(2), NOW + 8).generation, second.generation);
  const secondCleanup = restarted.cancel(visitor(2), NOW + 9);
  assert.ok(secondCleanup.generation > second.generation);
});

test("active chat survives actual SQLite close and reopen without restoring request budget", () => {
  const directory = mkdtempSync(join(tmpdir(), "opaque-demo-queue-"));
  const path = join(directory, "queue.sqlite");
  let host = new SqliteHost(path);
  try {
    let queue = new DemoQueue(new SqliteQueueStore(host));
    const workspace = ready(queue, visitor(1));
    const reserved = queue.reserveChat(visitor(1), "request-1", NOW + 2);
    host.close();
    host = new SqliteHost(path);
    queue = new DemoQueue(new SqliteQueueStore(host));
    assert.equal(queue.authorize(visitor(1), NOW + 3).lease_id, workspace.lease_id);
    assert.equal(queue.reserveChat(visitor(1), "request-1", NOW + 3).dispatch, false);
    throws(() => queue.reserveChat(visitor(1), "new-token-new-request", NOW + 3), "model_busy");
    assert.equal(queue.status(visitor(1), NOW + 3).questions_remaining, 11);
    queue.finishChat("request-1", reserved.reservation.generation, NOW + 4);
    assert.equal(queue.reserveChat(visitor(1), "request-1", NOW + 5).dispatch, false);
  } finally {
    host.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("one global model fence spans two ready workspaces and has no timeout refund", (t) => {
  const { queue } = fixture(t, { capacity: 2 });
  ready(queue, visitor(1));
  ready(queue, visitor(2), NOW + 2);
  const first = queue.reserveChat(visitor(1), "same-browser-request-id", NOW + 4);
  throws(() => queue.reserveChat(visitor(2), "same-browser-request-id", NOW + 66_000), "model_busy");
  throws(() => queue.finishChat("same-browser-request-id", first.reservation.generation + 99, NOW + 66_001), "chat_reservation_not_found");
  assert.equal(queue.status(visitor(2), NOW + 66_001).questions_remaining, 12);
  queue.finishChat("same-browser-request-id", first.reservation.generation, NOW + 66_002);
  const second = queue.reserveChat(visitor(2), "same-browser-request-id", NOW + 66_003);
  assert.ok(second.reservation.generation > first.reservation.generation);
  queue.finishChat("same-browser-request-id", first.reservation.generation, NOW + 66_004);
  throws(() => queue.reserveChat(visitor(1), "fresh", NOW + 66_005), "model_busy");
});

test("exactly twelve questions can be charged, with no refund or repeated-ID redispatch", (t) => {
  const { queue } = fixture(t);
  ready(queue, visitor(1));
  for (let index = 0; index < 12; index++) {
    const requestId = `request-${index}`;
    const reserved = queue.reserveChat(visitor(1), requestId, NOW + index + 2);
    assert.equal(reserved.dispatch, true);
    assert.equal(queue.reserveChat(visitor(1), requestId, NOW + index + 2).dispatch, false);
    queue.finishChat(requestId, reserved.reservation.generation, NOW + index + 2);
    assert.equal(queue.reserveChat(visitor(1), requestId, NOW + index + 2).dispatch, false);
  }
  assert.equal(queue.status(visitor(1), NOW + 20).questions_remaining, 0);
  throws(() => queue.reserveChat(visitor(1), "thirteenth", NOW + 20), "question_budget_exhausted");
  assert.equal(queue.join(visitor(1), "gemma4-e2b", NOW + 20, 1).questions_remaining, 0);
});

test("cleanup cannot clear uncertain model work without explicit stop evidence", (t) => {
  const { queue } = fixture(t, { capacity: 2 });
  ready(queue, visitor(1));
  ready(queue, visitor(2), NOW + 2);
  const oldChat = queue.reserveChat(visitor(1), "interrupted", NOW + 4);
  const cancelled = queue.cancel(visitor(1), NOW + 5);
  throws(() => clean(queue, cancelled, NOW + 6), "execution_stop_evidence_required");
  assert.equal(queue.status(visitor(1), NOW + 6).state, "quarantined");
  throws(() => queue.reserveChat(visitor(2), "fresh", NOW + 7), "model_busy");
  clean(queue, cancelled, NOW + 8, { execution_stopped: true });
  const next = queue.reserveChat(visitor(2), "fresh", NOW + 9);
  assert.equal(next.dispatch, true);
  assert.equal(queue.finishChat("interrupted", oldChat.reservation.generation, NOW + 10).reservation.state, "stopped");
  assert.equal(queue.status(visitor(2), NOW + 10).chat_busy, true);
});

test("clock rollback cannot resurrect an expired workspace or extend admission", (t) => {
  const { queue } = fixture(t);
  const workspace = ready(queue, visitor(1));
  throws(() => queue.authorize(visitor(1), workspace.expires_at), "workspace_not_ready");
  throws(() => queue.authorize(visitor(1), NOW), "workspace_not_ready");
  assert.equal(queue.status(visitor(1), NOW).state, "cleaning");
});

test("queue bounds, malformed inputs and unsupported controller fields fail closed", (t) => {
  const { queue, store } = fixture(t, { maxQueued: 2 });
  throws(() => new DemoQueue(store, { capacity: 3 }), "invalid_queue_config");
  throws(() => new DemoQueue(store, { ttl: 60_000 }), "invalid_queue_config");
  throws(() => queue.join("raw-browser-secret", "gemma4-e2b", NOW), "invalid_visitor_binding");
  throws(() => queue.join(visitor(1), "gemma4-e2b", NOW, 2), "invalid_priority");
  throws(() => queue.join(visitor(1), "gemma4-e2b", NaN), "invalid_server_time");
  queue.join(visitor(1), "gemma4-e2b", NOW);
  queue.join(visitor(2), "gemma4-e2b", NOW);
  throws(() => queue.join(visitor(3), "gemma4-e2b", NOW), "queue_full");
  const action = queue.work(NOW).actions[0];
  throws(() => queue.report({ kind: "ready", ...fields(action), expires_at: NOW + 86_400_000 }, NOW + 1), "invalid_report");
  throws(() => queue.authorize(visitor(3), NOW + 1), "visitor_not_found");
  assert.equal(queue.report({ kind: "ready", ...fields(action) }, NOW + 1).state, "ready");
});

test("lowering capacity does not allocate a free numbered slot while another slot is occupied", (t) => {
  const { queue, store, options } = fixture(t, { capacity: 2 });
  ready(queue, visitor(1));
  const second = ready(queue, visitor(2), NOW + 2);
  assert.equal(second.slot, 1);
  const cancelled = queue.cancel(visitor(1), NOW + 4);
  clean(queue, cancelled, NOW + 5);
  queue.join(visitor(3), "gemma4-e2b", NOW + 6);
  const reduced = new DemoQueue(store, { capacity: 1 }, options);
  assert.equal(reduced.work(NOW + 7).actions.length, 0);
  assert.equal(reduced.status(visitor(3), NOW + 7).state, "queued");
});

test("expired queued entries free queue capacity but cannot be rearmed before retention", (t) => {
  const { queue } = fixture(t, { maxQueued: 1 });
  queue.join(visitor(1), "gemma4-e2b", NOW);
  assert.equal(queue.status(visitor(1), NOW + LIMITS.queueMs).state, "expired");
  assert.equal(queue.join(visitor(1), "gemma4-e2b", NOW + LIMITS.queueMs + 1).state, "expired");
  queue.join(visitor(2), "gemma4-e2b", NOW + LIMITS.queueMs + 1);
  assert.equal(queue.status(visitor(2), NOW + LIMITS.queueMs + 1).state, "queued");
  assert.equal(queue.join(visitor(1), "gemma4-e2b", NOW + LIMITS.queueMs + LIMITS.historyMs).state, "queued");
});

test("corrupt durable state cannot widen slot, tenant, deadline or budget authority", async (t) => {
  for (const change of [
    (state) => { state.tickets[0].tenant_id = "foreign-tenant"; },
    (state) => { state.tickets[0].expires_at += 1_000; },
    (state) => { state.tickets[0].slot = 2; },
    (state) => { state.next_chat_generation = 0; },
    (state) => { state.tickets[0].ready_at = state.tickets[0].queued_at - 1; state.tickets[0].expires_at = state.tickets[0].ready_at + LIMITS.leaseMs; },
  ]) {
    await t.test("reject corrupted binding", (t) => {
      const { queue, host } = fixture(t);
      ready(queue, visitor(1));
      const state = host.state();
      change(state);
      host.overwrite(state);
      throws(() => queue.authorize(visitor(1), NOW + 2), "queue_state_invalid");
    });
  }
});

test("malformed JSON and interrupted SQLite transaction never become an empty queue", (t) => {
  const { queue, store, host } = fixture(t);
  ready(queue, visitor(1));
  const before = host.state();
  assert.throws(() => store.transaction(() => {
    host.db.prepare("DELETE FROM demo_queue_state").run();
    throw new Error("simulated interrupted transaction");
  }));
  assert.deepEqual(host.state(), before);
  host.overwrite("truncated-json");
  throws(() => queue.work(NOW + 2), "queue_state_invalid");
});

test("a lost persistent state row or JSON null cannot reinitialize outstanding capacity", (t) => {
  const { queue, host } = fixture(t);
  ready(queue, visitor(1));
  host.overwrite("null");
  throws(() => queue.work(NOW + 2), "queue_state_invalid");
  host.db.prepare("DELETE FROM demo_queue_state").run();
  throws(() => queue.work(NOW + 3), "queue_state_invalid");
  throws(() => new SqliteQueueStore(host), "queue_state_invalid");
});

test("public views and controller work omit the visitor capability hash", (t) => {
  const { queue } = fixture(t);
  const hash = visitor(123);
  const joined = queue.join(hash, "gemma4-e2b", NOW);
  const work = queue.work(NOW);
  const approved = queue.report({ kind: "ready", ...fields(work.actions[0]) }, NOW + 1);
  const chat = queue.reserveChat(hash, "safe-id", NOW + 2);
  for (const value of [joined, work, approved, chat, queue.authorize(hash, NOW + 2)]) {
    assert.ok(!JSON.stringify(value).includes(hash));
    assert.ok(!Object.hasOwn(value, "visitor_hash"));
  }
});

test("only enabled canonical aliases can create a ticket, without changing state on rejection", (t) => {
  const { queue, store, host } = fixture(t);
  const before = host.state();
  for (const model of [undefined, null, "", "qwen35-4b", "qwen3-14b", "Gemma4-e2b", "gemma4-e2b ", "https://model.example/"]) {
    throws(() => queue.join(visitor(1), model, NOW), "model_not_available");
    assert.deepEqual(host.state(), before);
  }
  for (const modelIds of [[], ["unknown"], ["gemma4-e2b", "gemma4-e2b"], "gemma4-e2b"]) {
    throws(() => new DemoQueue(store, { modelIds }), "invalid_queue_config");
  }
});

test("chosen model is immutable from queued ticket through provision, authorization and cleanup", (t) => {
  const { queue, store, host, options } = fixture(t, { modelIds: ["gemma4-e2b", "qwen35-4b"] });
  const selected = { id: "qwen35-4b", label: "Qwen3.5 4B" };
  const first = queue.join(visitor(1), selected.id, NOW);
  assert.deepEqual(first.model, selected);
  assert.equal(host.state().tickets[0].model_id, selected.id);
  const before = host.state();
  throws(() => queue.join(visitor(1), "gemma4-e2b", NOW + 1, 1), "model_selection_immutable");
  assert.deepEqual(host.state(), { ...before, last_now: NOW + 1 });
  const restarted = new DemoQueue(store, { modelIds: ["gemma4-e2b"] }, options);
  // Removing a choice gates new admission; it cannot rebind or strand a lease.
  throws(() => restarted.join(visitor(2), selected.id, NOW + 1), "model_not_available");
  const provision = restarted.work(NOW + 1).actions[0];
  assert.equal(provision.model_id, selected.id);
  const active = restarted.report({ kind: "ready", ...fields(provision) }, NOW + 2);
  assert.deepEqual(active.model, selected);
  assert.equal(restarted.authorize(visitor(1), NOW + 3).model_id, selected.id);
  const cancelled = restarted.cancel(visitor(1), NOW + 4);
  const cleanup = restarted.work(NOW + 4).actions[0];
  assert.equal(cleanup.model_id, selected.id);
  assert.deepEqual(clean(restarted, cancelled, NOW + 5).model, selected);
  assert.equal(restarted.status(visitor(1), NOW + 6).model_id, selected.id);
});

test("different model choices share one execution fence and switching cannot replenish question budget", (t) => {
  const { queue } = fixture(t, { capacity: 2, modelIds: ["gemma4-e2b", "qwen35-4b"] });
  ready(queue, visitor(1));
  ready(queue, visitor(2), NOW + 2, "qwen35-4b");
  for (let index = 0; index < 12; index++) {
    const request = `gemma-${index}`;
    const reserved = queue.reserveChat(visitor(1), request, NOW + index + 4);
    throws(() => queue.reserveChat(visitor(2), "qwen-attempt", NOW + index + 4), "model_busy");
    throws(() => queue.join(visitor(1), "qwen35-4b", NOW + index + 4), "model_selection_immutable");
    queue.finishChat(request, reserved.reservation.generation, NOW + index + 4);
  }
  assert.equal(queue.status(visitor(1), NOW + 20).questions_remaining, 0);
  assert.equal(queue.status(visitor(2), NOW + 20).questions_remaining, 12);
  throws(() => queue.reserveChat(visitor(1), "extra", NOW + 20), "question_budget_exhausted");
  const second = queue.reserveChat(visitor(2), "qwen-attempt", NOW + 20);
  assert.equal(second.lease.model_id, "qwen35-4b");
  assert.equal(second.dispatch, true);
});

test("version 2 SQLite migration pins every legacy ticket to Gemma without changing leases or reservations", () => {
  const directory = mkdtempSync(join(tmpdir(), "opaque-demo-model-migration-"));
  const path = join(directory, "queue.sqlite");
  let host = new SqliteHost(path);
  try {
    const oldQueue = new DemoQueue(new SqliteQueueStore(host));
    ready(oldQueue, visitor(1));
    oldQueue.join(visitor(2), "gemma4-e2b", NOW + 2);
    oldQueue.reserveChat(visitor(1), "reserved-before-upgrade", NOW + 3);
    const expected = host.state();
    const legacy = structuredClone(expected);
    legacy.version = 2;
    for (const ticket of legacy.tickets) delete ticket.model_id;
    host.overwrite(legacy);
    host.close();
    host = new SqliteHost(path);
    // The new enabled set/default cannot silently choose a different model
    // for old work, including a queued ticket that has not provisioned yet.
    const upgraded = new DemoQueue(new SqliteQueueStore(host), { modelIds: ["qwen35-4b"] });
    assert.deepEqual(upgraded.status(visitor(1), NOW + 3).model, { id: "gemma4-e2b", label: "Gemma 4 E2B" });
    assert.deepEqual(host.state(), expected);
    assert.equal(upgraded.status(visitor(2), NOW + 3).model_id, "gemma4-e2b");
    assert.equal(upgraded.authorize(visitor(1), NOW + 3).model_id, "gemma4-e2b");
    assert.equal(upgraded.status(visitor(1), NOW + 3).questions_remaining, 11);
    assert.equal(upgraded.reserveChat(visitor(1), "reserved-before-upgrade", NOW + 3).dispatch, false);
    throws(() => upgraded.reserveChat(visitor(1), "another", NOW + 3), "model_busy");
    throws(() => upgraded.join(visitor(3), "gemma4-e2b", NOW + 3), "model_not_available");
    assert.equal(upgraded.join(visitor(3), "qwen35-4b", NOW + 3).model_id, "qwen35-4b");
    const cancelled = upgraded.cancel(visitor(1), NOW + 4);
    assert.equal(upgraded.work(NOW + 4).actions[0].model_id, "gemma4-e2b");
    clean(upgraded, cancelled, NOW + 5, { execution_stopped: true });
    assert.equal(upgraded.work(NOW + 6).actions[0].model_id, "gemma4-e2b");
  } finally {
    host.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("missing current model or a conflicting legacy model is corruption, never fallback authority", async (t) => {
  for (const change of [
    state => { delete state.tickets[0].model_id; },
    state => { state.tickets[0].model_id = "unknown"; },
    state => { state.version = 2; },
    state => { state.version = 2; state.tickets[0].model_id = "qwen35-4b"; },
  ]) {
    await t.test("fail closed without resetting durable state", t => {
      const { queue, host } = fixture(t);
      ready(queue, visitor(1));
      const state = host.state();
      change(state);
      host.overwrite(state);
      throws(() => queue.work(NOW + 2), "queue_state_invalid");
      assert.deepEqual(host.state(), state);
    });
  }
});
