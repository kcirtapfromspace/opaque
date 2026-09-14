import assert from 'node:assert/strict';
import {once} from 'node:events';
import test from 'node:test';
import {processFixture} from './processes.mjs';

test('cleanup removes an actual orphaned group and preserves the failure', {timeout: 15_000}, async () => {
  const fixture = processFixture(process.execPath, ['-e', `
    const {spawn} = require('node:child_process');
    spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {stdio:'ignore'});
    process.exit(0);
  `], {PATH: process.env.PATH});
  try {
    await once(fixture.child, 'close');
    assert.equal(fixture.child.exitCode, 0);
    // The direct child exited, while its actual descendant remains in the
    // detached group. Cleanup must not stop at the leader's exit status.
    assert.equal(process.kill(-fixture.child.pid, 0), true);
    await assert.rejects(fixture.stop(), /required forced process-group cleanup/);
    assert.throws(() => process.kill(-fixture.child.pid, 0), {code:'ESRCH'});
    await fixture.stop(); // Successful retirement remains idempotent.
  } finally {
    try { process.kill(-fixture.child.pid, 'SIGKILL'); } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
  }
});
