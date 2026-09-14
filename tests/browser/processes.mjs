// Each fixture owns the process group created by its detached direct child.
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {basename} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
import {appendFile, readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

function signalGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

export function processFixture(binary, args, env, coverageEvents) {
  const child = spawn(binary, args, {
    env, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  let startupError;
  let stopped = false;
  child.on('error', error => { startupError = error; });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', bytes => { output = (output + bytes.toString()).slice(-32_768); });
  }
  const exited = () => child.exitCode !== null || child.signalCode !== null;
  async function waitForExitAndGroupRemoval(timeout) {
    const deadline = performance.now() + timeout;
    while (performance.now() < deadline) {
      if (!signalGroup(child.pid, 0) && exited()) return true;
      await delay(20);
    }
    return !signalGroup(child.pid, 0) && exited();
  }
  return {
    child,
    get output() { return output; },
    alive() {
      assert.equal(startupError, undefined, `${basename(binary)} could not start`);
      assert.equal(child.exitCode, null, `${basename(binary)} exited before readiness`);
      assert.equal(child.signalCode, null, `${basename(binary)} was killed before readiness`);
    },
    async stop() {
      if (!child.pid || stopped) return;
      // A reaped leader is not proof that its owned descendants stopped.
      // Retire an already orphaned group before reporting that failure.
      const orphaned = exited() && signalGroup(child.pid, 0);
      let forced = orphaned;
      signalGroup(child.pid, orphaned ? 'SIGKILL' : 'SIGINT');
      let removed = await waitForExitAndGroupRemoval(5000);
      if (!removed) {
        forced = true;
        signalGroup(child.pid, 'SIGKILL');
        // Retain control of our direct child even if it changed its group.
        if (!exited()) child.kill('SIGKILL');
        removed = await waitForExitAndGroupRemoval(5000);
      }
      assert.equal(removed, true, 'owned process group survived bounded cleanup');
      stopped = true;
      if (coverageEvents) {
        const sha256 = createHash('sha256').update(await readFile(binary)).digest('hex');
        await appendFile(coverageEvents, JSON.stringify({binary, name: basename(binary), pid: child.pid,
          sha256, exit_code: child.exitCode, signal: child.signalCode, forced_cleanup: forced}) + '\n');
      }
      assert.equal(forced, false, 'owned fixture required forced process-group cleanup');
    },
  };
}
