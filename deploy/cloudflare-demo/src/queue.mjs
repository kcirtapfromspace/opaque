/** Durable scheduler for the public synthetic-data demo.
 *
 * Only trusted Worker code invokes these methods. visitorHash is the SHA-256
 * of a server-minted opaque cookie; priority and now are server decisions.
 * This component neither creates cluster resources nor authenticates HTTP.
 * All times are Unix milliseconds. Every method is one synchronous storage
 * transaction: do not put network I/O inside a store transaction.
 */

import { LEGACY_MODEL_ID, isModelId, sessionModel } from './models.mjs';

export const LIMITS = Object.freeze({
  leaseMs: 600_000,
  provisionMs: 120_000,
  queueMs: 1_800_000,
  agingMs: 300_000,
  historyMs: 86_400_000,
  maxRecords: 512,
  maxQuestions: 12,
  modelCallsPerQuestion: 2,
  outputTokensPerModelCall: 192,
  maxWatchSeconds: 30,
});

const HOLDING = new Set(["provisioning", "ready", "cleaning", "quarantined"]);
const TERMINAL = new Set(["expired", "cancelled", "failed"]);
const STATES = new Set(["queued", ...HOLDING, ...TERMINAL]);
const HASH = /^[a-f0-9]{64}$/;
const ID = /^[a-f0-9]{32}$/;
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const safeTime = (value) => Number.isSafeInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER - LIMITS.historyMs;
const nullableTime = (value) => value === null || safeTime(value);

export class QueueError extends Error {
  constructor(code, status = 409) {
    super(code);
    this.name = "QueueError";
    this.code = code;
    this.status = status;
  }
}

/** Adapter for a SQLite-backed Cloudflare Durable Object's storage.
 * The root Worker owns the DurableObject class and passes ctx.storage here.
 * Cloudflare commits synchronous SQLite writes before a response is released.
 * No allowUnconfirmed writes or asynchronous callbacks are used.
 */
export class SqliteQueueStore {
  constructor(storage) {
    if (!storage?.sql?.exec || typeof storage.transactionSync !== "function") {
      throw new QueueError("durable_storage_required", 503);
    }
    this.storage = storage;
    storage.transactionSync(() => {
      const existing = storage.sql.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='demo_queue_state'").toArray();
      if (!existing.length) {
        // DDL and initial state commit together. An existing table with a lost
        // row is corruption, never permission to forget outstanding leases.
        storage.sql.exec("CREATE TABLE demo_queue_state (id INTEGER PRIMARY KEY CHECK (id = 1), value TEXT NOT NULL)");
        storage.sql.exec("INSERT INTO demo_queue_state (id,value) VALUES (1,?)", JSON.stringify(initialState()));
      } else if (storage.sql.exec("SELECT id FROM demo_queue_state").toArray().length !== 1) {
        throw new QueueError("queue_state_invalid", 503);
      }
    });
  }

  transaction(callback) {
    return this.storage.transactionSync(() => {
      const rows = this.storage.sql.exec("SELECT value FROM demo_queue_state WHERE id = 1").toArray();
      if (rows.length !== 1 || typeof rows[0].value !== "string" || rows[0].value.length > 4 * 1024 * 1024) {
        throw new QueueError("queue_state_invalid", 503);
      }
      let previous;
      try { previous = JSON.parse(rows[0].value); }
      catch { throw new QueueError("queue_state_invalid", 503); }
      if (previous === null) throw new QueueError("queue_state_invalid", 503);
      const output = callback(previous);
      if (output && typeof output.then === "function") throw new QueueError("async_transaction_forbidden", 503);
      const encoded = JSON.stringify(output.state);
      if (encoded.length > 4 * 1024 * 1024) throw new QueueError("queue_state_exceeded_limit", 503);
      this.storage.sql.exec("INSERT INTO demo_queue_state (id,value) VALUES (1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", encoded);
      return output.result;
    });
  }
}

export class DemoQueue {
  constructor(store, config = {}, options = {}) {
    if (typeof store?.transaction !== "function") throw new QueueError("durable_storage_required", 503);
    if (Object.keys(config).some((key) => !["capacity", "maxQueued", "modelIds"].includes(key))) throw new QueueError("invalid_queue_config", 500);
    const { capacity = 1, maxQueued = 100, modelIds = [LEGACY_MODEL_ID] } = config;
    if (!Number.isInteger(capacity) || capacity < 1 || capacity > 2 || !Number.isInteger(maxQueued) || maxQueued < 1 || maxQueued > 100) {
      throw new QueueError("invalid_queue_config", 500);
    }
    if (!Array.isArray(modelIds) || !modelIds.length || modelIds.length > 3
      || new Set(modelIds).size !== modelIds.length || modelIds.some(id => !isModelId(id))) throw new QueueError("invalid_queue_config",500);
    this.store = store;
    this.config = { capacity, maxQueued, modelIds:[...modelIds] };
    this.id = options.id ?? (() => crypto.randomUUID().replaceAll("-", ""));
  }

  join(visitorHash, modelId, now, priority = 0) {
    requireVisitor(visitorHash);
    if (!isModelId(modelId) || !this.config.modelIds.includes(modelId)) throw new QueueError("model_not_available",400);
    if (priority !== 0 && priority !== 1) throw new QueueError("invalid_priority", 400);
    return this.change(now, (state, time) => {
      const existing = state.tickets.find((ticket) => ticket.visitor_hash === visitorHash);
      // Rejoining/reloading never changes priority, queue order, TTL or budget.
      if (existing) {
        if (existing.model_id !== modelId) throw new QueueError("model_selection_immutable");
        return view(existing, state, time);
      }
      if (state.tickets.filter((ticket) => ticket.state === "queued").length >= this.config.maxQueued || state.tickets.length >= LIMITS.maxRecords) {
        throw new QueueError("queue_full", 429);
      }
      const ticket = {
        visitor_hash: visitorHash, model_id:modelId, priority, sequence: state.next_sequence++,
        state: "queued", queued_at: time, queue_expires_at: time + LIMITS.queueMs,
        lease_id: null, tenant_id: null, slot: null, generation: 0, provision_generation: null,
        provision_deadline_at: null, hard_expires_at: null, ready_at: null,
        expires_at: null, finished_at: null, cleanup_reason: null,
        cleanup_retry_at: null, chats: [],
      };
      state.tickets.push(ticket);
      return view(ticket, state, time);
    });
  }

  status(visitorHash, now) {
    requireVisitor(visitorHash);
    return this.change(now, (state, time) => view(findVisitor(state, visitorHash), state, time));
  }

  cancel(visitorHash, now) {
    requireVisitor(visitorHash);
    return this.change(now, (state, time) => {
      const ticket = findVisitor(state, visitorHash);
      if (ticket.state === "queued") {
        ticket.state = "cancelled";
        ticket.finished_at = time;
      } else if (ticket.state === "provisioning" || ticket.state === "ready") {
        startCleanup(state, ticket, "cancelled", time);
      }
      return view(ticket, state, time);
    });
  }

  work(now) {
    return this.change(now, (state, time) => {
      const occupied = new Set(state.tickets.filter((ticket) => HOLDING.has(ticket.state)).map((ticket) => ticket.slot));
      const waiting = ordered(state, time);
      for (let slot = 0; slot < this.config.capacity && occupied.size < this.config.capacity && waiting.length; slot++) {
        if (occupied.has(slot)) continue;
        const ticket = waiting.shift();
        let leaseId;
        for (let attempt = 0; attempt < 8; attempt++) {
          const candidate = this.id();
          if (typeof candidate !== "string" || !ID.test(candidate)) throw new QueueError("invalid_id_source", 503);
          if (!state.tickets.some((item) => item.lease_id === candidate)) { leaseId = candidate; break; }
        }
        if (!leaseId) throw new QueueError("id_source_unavailable", 503);
        const generation = ++state.slot_generations[slot];
        Object.assign(ticket, {
          state: "provisioning", lease_id: leaseId, tenant_id: `demo-${leaseId}`,
          slot, generation, provision_generation: generation, provision_deadline_at: time + LIMITS.provisionMs,
          hard_expires_at: time + LIMITS.provisionMs + LIMITS.leaseMs,
          expires_at: time + LIMITS.provisionMs + LIMITS.leaseMs,
        });
        occupied.add(slot);
      }
      return {
        actions: state.tickets.filter((ticket) => ticket.state === "provisioning" || ticket.state === "cleaning" || (ticket.state === "quarantined" && time >= ticket.cleanup_retry_at)).map(action),
        next_alarm_at: nextAlarm(state, time),
      };
    });
  }

  /** Controller-only reports. A cleanup acknowledgement is evidence that the
   * previous provisioning attempt is quiescent and owned resources are gone.
   * A stale controller must never report successful cleanup while another
   * attempt can still create the resource. Cluster idempotency uses lease_id.
   */
  report(payload, now) {
    if (!payload || typeof payload !== "object" || Array.isArray(payload)
      || Object.keys(payload).some((key) => !["kind", "lease_id", "slot", "generation", "resources_deleted", "provisioning_stopped", "execution_stopped"].includes(key))
      || !["ready", "failed", "cleaned"].includes(payload.kind)
      || !ID.test(payload.lease_id) || !Number.isInteger(payload.slot)
      || !Number.isSafeInteger(payload.generation) || payload.generation < 1) {
      throw new QueueError("invalid_report", 400);
    }
    return this.change(now, (state, time) => {
      const ticket = state.tickets.find((item) => item.lease_id === payload.lease_id);
      if (!ticket) throw new QueueError("lease_not_found", 404);
      if (ticket.slot !== payload.slot || ticket.generation !== payload.generation) throw new QueueError("stale_lease_generation");
      if (payload.kind === "ready") {
        if (ticket.state === "ready") return view(ticket, state, time);
        if (ticket.state !== "provisioning") throw new QueueError("lease_not_provisioning");
        Object.assign(ticket, { state: "ready", ready_at: time, expires_at: Math.min(time + LIMITS.leaseMs, ticket.hard_expires_at) });
      } else if (payload.kind === "failed") {
        if (ticket.state === "provisioning") startCleanup(state, ticket, "failed", time);
        else if (ticket.state === "cleaning") {
          ticket.state = "quarantined";
          ticket.cleanup_retry_at = time + 5_000;
        } else if (ticket.state !== "quarantined") throw new QueueError("invalid_lease_transition");
      } else {
        if (payload.resources_deleted !== true || payload.provisioning_stopped !== true) throw new QueueError("cleanup_evidence_required");
        if (TERMINAL.has(ticket.state)) return view(ticket, state, time);
        if (ticket.state !== "cleaning" && ticket.state !== "quarantined") throw new QueueError("lease_not_cleaning");
        if (ticket.chats.some((chat) => chat.state === "reserved") && payload.execution_stopped !== true) {
          ticket.state = "quarantined";
          ticket.cleanup_retry_at ??= time + 5_000;
          throw new QueueError("execution_stop_evidence_required");
        }
        for (const chat of ticket.chats) {
          if (chat.state === "reserved") { chat.state = "stopped"; chat.finished_at = time; }
        }
        ticket.state = ticket.cleanup_reason;
        ticket.finished_at = time;
      }
      return view(ticket, state, time);
    });
  }

  authorize(visitorHash, now) {
    requireVisitor(visitorHash);
    return this.change(now, (state) => lease(requireReady(state, visitorHash)));
  }

  /** Charge before proxying any model-capable chat. Repeated IDs are read-only
   * receipts, not retry authority. The budget survives new cookies/tokens in
   * the workspace, reconnects, worker restarts and ambiguous cancellations.
   */
  reserveChat(visitorHash, requestId, now) {
    requireVisitor(visitorHash);
    requireRequest(requestId);
    return this.change(now, (state, time) => {
      const ticket = requireReady(state, visitorHash);
      const previous = ticket.chats.find((chat) => chat.request_id === requestId);
      if (previous) return { lease: lease(ticket), reservation: { ...previous }, dispatch: false };
      if (state.tickets.some((item) => item.chats.some((chat) => chat.state === "reserved"))) throw new QueueError("model_busy", 429);
      if (ticket.chats.length >= LIMITS.maxQuestions) throw new QueueError("question_budget_exhausted", 429);
      const reservation = {
        request_id: requestId, generation: state.next_chat_generation++,
        state: "reserved", reserved_at: time, finished_at: null,
      };
      ticket.chats.push(reservation);
      return { lease: lease(ticket), reservation: { ...reservation }, dispatch: true };
    });
  }

  /** Trusted completion only: call after the upstream response body has fully
   * finished, or the controller has confirmed execution stopped. Browser
   * cancellation, a timeout, or response headers alone are not completion.
   * generation is the chat fence, not the workspace's lease generation.
   */
  finishChat(requestId, generation, now) {
    requireRequest(requestId);
    if (!Number.isSafeInteger(generation) || generation < 1) throw new QueueError("invalid_chat_generation", 400);
    return this.change(now, (state, time) => {
      for (const ticket of state.tickets) {
        const chat = ticket.chats.find((item) => item.request_id === requestId && item.generation === generation);
        if (!chat) continue;
        if (chat.state === "reserved") { chat.state = "finished"; chat.finished_at = time; }
        return { lease: lease(ticket), reservation: { ...chat }, dispatch: false };
      }
      throw new QueueError("chat_reservation_not_found", 404);
    });
  }

  change(now, operation) {
    if (!safeTime(now)) throw new QueueError("invalid_server_time", 500);
    let failure;
    const result = this.store.transaction((previous) => {
      const state = migrateState(previous ?? initialState());
      validateState(state);
      const time = Math.max(now, state.last_now);
      state.last_now = time;
      sweep(state, time);
      let result;
      try { result = operation(state, time); }
      catch (error) {
        if (!(error instanceof QueueError)) throw error;
        failure = error;
      }
      validateState(state);
      return { state, result };
    });
    if (failure) throw failure;
    return result;
  }
}

function requireVisitor(hash) {
  if (typeof hash !== "string" || !HASH.test(hash)) throw new QueueError("invalid_visitor_binding", 400);
}
function initialState() {
  return { version: 3, next_sequence: 1, next_chat_generation: 1, slot_generations: [0, 0], last_now: 0, tickets: [] };
}
function migrateState(previous) {
  if (previous?.version !== 2) return previous;
  // Validate the old state before adding authority. Never reinterpret corrupt
  // records or pick whichever model happens to be the new deployment default.
  validateState(previous, 2);
  const state = structuredClone(previous);
  state.version = 3;
  for (const ticket of state.tickets) ticket.model_id = LEGACY_MODEL_ID;
  return state;
}
function requireRequest(id) {
  if (typeof id !== "string" || !REQUEST_ID.test(id)) throw new QueueError("invalid_request_id", 400);
}
function findVisitor(state, hash) {
  const ticket = state.tickets.find((item) => item.visitor_hash === hash);
  if (!ticket) throw new QueueError("visitor_not_found", 404);
  return ticket;
}
function requireReady(state, hash) {
  const ticket = findVisitor(state, hash);
  if (ticket.state !== "ready") throw new QueueError("workspace_not_ready", TERMINAL.has(ticket.state) || ticket.state === "cleaning" || ticket.state === "quarantined" ? 410 : 409);
  return ticket;
}
function ordered(state, now) {
  const rank = (ticket) => ticket.priority === 1 || now - ticket.queued_at >= LIMITS.agingMs ? 1 : 0;
  return state.tickets.filter((ticket) => ticket.state === "queued").sort((a, b) => rank(b) - rank(a) || a.sequence - b.sequence);
}
function lease(ticket) {
  return {
    lease_id: ticket.lease_id, tenant_id: ticket.tenant_id, slot: ticket.slot,
    generation: ticket.generation, expires_at: ticket.expires_at, model_id:ticket.model_id,
  };
}
function view(ticket, state, now) {
  return {
    state: ticket.state, queue_position: ticket.state === "queued" ? ordered(state, now).findIndex((item) => item === ticket) + 1 : null,
    queued_at: ticket.queued_at, queue_expires_at: ticket.queue_expires_at,
    ...lease(ticket), model:sessionModel(ticket.model_id), ready_at: ticket.ready_at, finished_at: ticket.finished_at,
    provision_deadline_at: ticket.provision_deadline_at,
    questions_remaining: LIMITS.maxQuestions - ticket.chats.length,
    chat_busy: state.tickets.some((item) => item.chats.some((chat) => chat.state === "reserved")),
  };
}
function action(ticket) {
  return {
    kind: ticket.state === "provisioning" ? "provision" : "cleanup",
    ...lease(ticket), provision_deadline_at: ticket.provision_deadline_at,
  };
}
function startCleanup(state, ticket, reason, now) {
  ticket.state = "cleaning";
  ticket.generation = ++state.slot_generations[ticket.slot];
  ticket.cleanup_reason = reason;
  ticket.cleanup_retry_at = now;
}
function sweep(state, now) {
  for (const ticket of state.tickets) {
    if (ticket.state === "queued" && now >= ticket.queue_expires_at) {
      ticket.state = "expired";
      ticket.finished_at = now;
    } else if (ticket.state === "provisioning" && now >= ticket.provision_deadline_at) {
      startCleanup(state, ticket, "failed", now);
    } else if (ticket.state === "ready" && now >= ticket.expires_at) {
      startCleanup(state, ticket, "expired", now);
    }
  }
  state.tickets = state.tickets.filter((ticket) => !TERMINAL.has(ticket.state) || now - ticket.finished_at < LIMITS.historyMs);
}
function nextAlarm(state, now) {
  const deadlines = [];
  for (const ticket of state.tickets) {
    if (ticket.state === "queued") deadlines.push(ticket.queue_expires_at);
    if (ticket.state === "provisioning") deadlines.push(ticket.provision_deadline_at);
    if (ticket.state === "ready") deadlines.push(ticket.expires_at);
    // Controller pulls retry cleanup; alarms need only persist temporal state.
    if (TERMINAL.has(ticket.state)) deadlines.push(ticket.finished_at + LIMITS.historyMs);
  }
  return deadlines.length ? Math.max(now + 1, Math.min(...deadlines)) : null;
}

function validateState(state, version = 3) {
  const invalid = () => { throw new QueueError("queue_state_invalid", 503); };
  if (!state || state.version !== version || !safeTime(state.last_now)
    || !Number.isSafeInteger(state.next_sequence) || state.next_sequence < 1
    || !Number.isSafeInteger(state.next_chat_generation) || state.next_chat_generation < 1
    || !Array.isArray(state.slot_generations) || state.slot_generations.length !== 2
    || state.slot_generations.some((value) => !Number.isSafeInteger(value) || value < 0)
    || !Array.isArray(state.tickets) || state.tickets.length > LIMITS.maxRecords) invalid();
  const visitors = new Set(), leases = new Set(), slots = new Set(), sequences = new Set(), chatGenerations = new Set();
  let reserved = 0;
  for (const ticket of state.tickets) {
    if (!ticket || (version === 2 ? Object.hasOwn(ticket, 'model_id') : !isModelId(ticket.model_id))
      || !HASH.test(ticket.visitor_hash) || visitors.has(ticket.visitor_hash)
      || ![0, 1].includes(ticket.priority) || !STATES.has(ticket.state)
      || !Number.isSafeInteger(ticket.sequence) || ticket.sequence < 1 || ticket.sequence >= state.next_sequence || sequences.has(ticket.sequence)
      || !safeTime(ticket.queued_at) || ticket.queue_expires_at !== ticket.queued_at + LIMITS.queueMs
      || !nullableTime(ticket.finished_at) || !nullableTime(ticket.ready_at) || !nullableTime(ticket.expires_at)
      || !nullableTime(ticket.provision_deadline_at) || !nullableTime(ticket.hard_expires_at) || !nullableTime(ticket.cleanup_retry_at)
      || !Array.isArray(ticket.chats) || ticket.chats.length > LIMITS.maxQuestions) invalid();
    visitors.add(ticket.visitor_hash); sequences.add(ticket.sequence);
    if (ticket.lease_id === null) {
      if (HOLDING.has(ticket.state) || ticket.tenant_id !== null || ticket.slot !== null || ticket.generation !== 0 || ticket.provision_generation !== null || ticket.chats.length
        || ticket.expires_at !== null || ticket.provision_deadline_at !== null || ticket.hard_expires_at !== null || ticket.ready_at !== null) invalid();
    } else {
      if (!ID.test(ticket.lease_id) || leases.has(ticket.lease_id) || ticket.tenant_id !== `demo-${ticket.lease_id}`
        || !Number.isInteger(ticket.slot) || ticket.slot < 0 || ticket.slot > 1
        || !Number.isSafeInteger(ticket.generation) || ticket.generation < 1
        || !Number.isSafeInteger(ticket.provision_generation) || ticket.provision_generation < 1
        || ticket.generation > state.slot_generations[ticket.slot]
        || ticket.provision_deadline_at === null || ticket.provision_deadline_at < ticket.queued_at + LIMITS.provisionMs
        || ticket.provision_deadline_at >= ticket.queue_expires_at + LIMITS.provisionMs
        || ticket.hard_expires_at !== ticket.provision_deadline_at + LIMITS.leaseMs
        || ticket.expires_at === null || ticket.expires_at > ticket.hard_expires_at || ticket.state === "queued") invalid();
      leases.add(ticket.lease_id);
      if (HOLDING.has(ticket.state)) {
        if (slots.has(ticket.slot) || ticket.generation !== state.slot_generations[ticket.slot]) invalid();
        slots.add(ticket.slot);
      }
      if (ticket.state === "provisioning" && (ticket.generation !== ticket.provision_generation || ticket.ready_at !== null || ticket.expires_at !== ticket.hard_expires_at)) invalid();
      if (ticket.state === "ready" && (ticket.generation !== ticket.provision_generation || ticket.ready_at === null || ticket.ready_at < ticket.provision_deadline_at - LIMITS.provisionMs || ticket.ready_at >= ticket.provision_deadline_at || ticket.expires_at !== ticket.ready_at + LIMITS.leaseMs)) invalid();
      if (["cleaning", "quarantined"].includes(ticket.state) && (ticket.generation !== ticket.provision_generation + 1 || !TERMINAL.has(ticket.cleanup_reason) || ticket.cleanup_retry_at === null)) invalid();
    }
    if (TERMINAL.has(ticket.state) !== (ticket.finished_at !== null)) invalid();
    const requestIds = new Set();
    for (const chat of ticket.chats) {
      if (!chat || !REQUEST_ID.test(chat.request_id) || requestIds.has(chat.request_id)
        || !Number.isSafeInteger(chat.generation) || chat.generation < 1 || chat.generation >= state.next_chat_generation || chatGenerations.has(chat.generation)
        || !["reserved", "finished", "stopped"].includes(chat.state) || !safeTime(chat.reserved_at) || !nullableTime(chat.finished_at)
        || (chat.state === "reserved") !== (chat.finished_at === null)) invalid();
      if (chat.state === "reserved") { reserved++; if (!HOLDING.has(ticket.state)) invalid(); }
      requestIds.add(chat.request_id); chatGenerations.add(chat.generation);
    }
  }
  if (slots.size > 2 || reserved > 1) invalid();
}
