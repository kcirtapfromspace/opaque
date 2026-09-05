// Browser-independent checks of the shipped dashboard script. Real browser
// verification remains part of the release dogfood run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function dashboard() {
  const html = fs.readFileSync(path.join(__dirname, '../static/index.html'), 'utf8');
  const source = html.split('<script>')[1].split('</script>')[0].replace(/\ninit\(\);\s*$/, '');
  const context = vm.createContext({document: {querySelector: () => ({content: 'test-only'})}, URL, console});
  vm.runInContext(source, context);
  context.el = (tag, attrs, children) => ({tag, attrs: attrs || {}, children: [].concat(children || []), appendChild(child) {this.children.push(child);}});
  context.txt = value => String(value);
  return context;
}
function text(node) {
  return typeof node === 'string' ? node : (node.children || []).map(text).join(' ');
}
function task() {
  return {id: 'test-task', state: 'completed', approved_at: 100, approval_mode: 'insecure_test',
    manifest: {actions: [{operation: 'github.dispatch_staging_workflow'}]},
    slots: [{reserved_at: 100, state: 'unknown'}], release_observation: null};
}

test('historical approval provenance is independent of the running backend', () => {
  const ui = dashboard();
  ui.state.approvalBackend = 'native';
  assert.equal(ui.taskApprovalMode(task()), 'INSECURE TEST APPROVAL');
  assert.equal(ui.taskApprovalMode({...task(), approval_mode: null}), 'Approval mode unavailable');
  assert.equal(ui.taskApprovalMode({...task(), approval_mode: 'paired_workstation'}), 'Paired workstation approval');
  ui.state.workstationTestMode = true;
  assert.equal(ui.testApprovalActive(), true);
});

test('a completed dispatch never labels an unchecked workflow successful', () => {
  const ui = dashboard();
  const receipt = task();
  assert.equal(ui.taskStateLabel(receipt), 'Dispatch recorded');
  assert.equal(ui.workflowLabel(receipt.release_observation), 'Not checked');
  const rendered = text(ui.buildWorkflowEvidence(receipt));
  assert.match(rendered, /Not checked/);
  assert.match(rendered, /Checking cannot dispatch or retry/);
  assert.doesNotMatch(rendered, /succeeded|successful/);
});

test('workflow success preserves unknown dispatch wording and explicit correlation', () => {
  const ui = dashboard();
  const receipt = {...task(), release_observation: {state: 'succeeded', code: 'workflow_succeeded', correlation: 'task_title', run_id: 42, run_attempt: 1, checked_at: 200}};
  assert.equal(ui.slotLabel(receipt.slots[0].state, true), 'Unknown — may have dispatched');
  const rendered = text(ui.buildWorkflowEvidence(receipt));
  assert.match(rendered, /Workflow succeeded/);
  assert.match(rendered, /Matched task correlation title/);
  assert.match(rendered, /Attempt 1/);
  assert.match(rendered, /Run 42/);
  assert.equal(receipt.slots[0].state, 'unknown');
  receipt.release_observation.correlation = 'dispatch_response';
  assert.match(text(ui.buildWorkflowEvidence(receipt)), /Run ID from dispatch response/);
});

test('unapproved work has no reconciliation action, failed refresh retains evidence', () => {
  const ui = dashboard();
  const unapproved = {...task(), approved_at: null, slots: [{reserved_at: null}]};
  assert.doesNotMatch(text(ui.buildWorkflowEvidence(unapproved)), /Check workflow/);
  ui.state.reconcileErrors['test-task'] = 'Provider unavailable. Existing evidence is retained; no dispatch was requested.';
  const rendered = text(ui.buildWorkflowEvidence({...task(), release_observation: {state: 'failed', correlation: 'dispatch_response'}}));
  assert.match(rendered, /Workflow failed/);
  assert.match(rendered, /Existing evidence is retained/);
});

test('missing broker audit custody does not create background request retries', async () => {
  const ui = dashboard();
  ui.state.mode = 'live';
  ui.state.auditAvailable = false;
  ui.apiFetch = () => {throw new Error('must not request an unavailable local source');};
  ui.renderAuditList = () => {};
  ui.setStreamStatus = () => {};
  await ui.applyFilters();
  await ui.connectSSE();
  assert.match(ui.state.auditError, /Audit history is unavailable/);
  assert.equal(ui.state.sseRetryTimer, null);
});

function inferenceTask(unknown = false) {
  const actions = [1, 2, 3].map(ordinal => ({operation: 'inference.fixed_completion', ordinal,
    tenant: {tenant_id: 'synthetic-a', broker_id: 'broker-a'}, model_id: 'fixture-model',
    source_id: 'public-fixture', source_snapshot_sha256: 'a'.repeat(64), prompt_sha256: 'b'.repeat(64),
    options: {max_input_tokens: 512, max_output_tokens: 96, deadline_secs: 30}}));
  return {...task(), manifest: {actions}, slots: actions.map((action, i) => ({id: String(i), action,
    reserved_at: unknown && i > 0 ? null : 100,
    state: unknown ? (i === 0 ? 'unknown' : 'rejected') : 'api_accepted',
    outcome: {code: unknown ? 'transport_unknown' : 'api_accepted', inference_receipt: unknown ? null : {
      code: 'completion_observed', input_tokens: 3, reserved_output_tokens: 96,
      observed_output_tokens: 8, output_sha256: 'c'.repeat(64), output_text: '<img src=x onerror=alert(1)>'}}}))};
}

test('inference allowance is charged by reservation and never observed usage', () => {
  const ui = dashboard();
  const receipt = inferenceTask();
  assert.equal(ui.taskStateLabel(receipt), 'Inference receipts recorded');
  const rendered = text(ui.buildInferenceEvidence(receipt));
  assert.match(rendered, /288 \/ 288 output-token allowance reserved/);
  assert.match(rendered, /24 output tokens observed/);
  assert.match(rendered, /does not refund/);
  assert.match(rendered, /Tenant synthetic-a · Broker broker-a/);
  assert.match(rendered, /operator-attested/);
});

test('unknown inference burns only reserved slot and exposes no retry action', () => {
  const ui = dashboard();
  const receipt = inferenceTask(true);
  assert.equal(ui.inferenceSlotLabel(receipt.slots[0]), 'Unknown — allowance consumed');
  assert.match(text(ui.buildInferenceEvidence(receipt)), /96 \/ 288 output-token allowance reserved/);
  assert.doesNotMatch(text(ui.buildTaskDetail(receipt)), /GitHub API|Vault API|Check workflow|may have written/);
});

test('inference output is a text child, not executable HTML', () => {
  const ui = dashboard();
  const detail = ui.buildTaskDetail(inferenceTask());
  const seen = [];
  function visit(node) {if (typeof node === 'object') {seen.push(node); node.children.forEach(visit);}}
  visit(detail);
  assert.ok(seen.some(node => node.tag === 'p' && node.children.includes('<img src=x onerror=alert(1)>')));
  assert.ok(seen.every(node => node.tag !== 'img' && !Object.hasOwn(node.attrs, 'innerHTML')));
  const receiptTable = seen.find(node => node.tag === 'table');
  assert.match(receiptTable.attrs.className, /inference-slots/);
  const cells = seen.filter(node => node.tag === 'td');
  assert.deepEqual(cells.slice(0, 3).map(cell => cell.attrs['data-label']), ['Fixed prompt / pinned source', 'Receipt', 'Evidence']);
});
