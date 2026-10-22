import assert from 'node:assert/strict';
import { test } from 'node:test';
import { assess, classify, exitCode, mitigations, parseVersion, summarize } from '../src/advisory.js';

test('patched at and above each fixed release', () => {
  for (const v of ['8.5.12', '8.4.27', '8.3.36', '8.2.35', '8.5.13']) {
    assert.equal(classify(parseVersion(v)).status, 'patched', v);
  }
});

test('vulnerable one below each fixed release', () => {
  for (const v of ['8.5.11', '8.4.26', '8.3.35', '8.2.34']) {
    assert.equal(classify(parseVersion(v)).status, 'vulnerable', v);
  }
});

test('older and newer branches', () => {
  assert.equal(classify([8, 1, 30]).status, 'backport-needed');
  assert.equal(classify([7, 4, 33]).status, 'backport-needed');
  assert.equal(classify([7, 3, 0]).status, 'eol');
  assert.equal(classify([5, 4, 0]).status, 'eol');
  assert.equal(classify([9, 0, 0]).status, 'unknown');
});

test('parseVersion handles distro suffixes and headers', () => {
  assert.deepEqual(parseVersion('8.3.36-1ubuntu1'), [8, 3, 36]);
  assert.deepEqual(parseVersion('PHP/8.2.1'), [8, 2, 1]);
  assert.equal(parseVersion('garbage'), null);
});

test('mitigations: applied, missing, unknown, 8.5 extra', () => {
  const ok = mitigations({ memory_limit: '-1', 'session.upload_progress.enabled': '' }, [8, 4, 1]);
  assert.ok(ok.every((m) => m.applied === true));
  const off = mitigations({ memory_limit: '128M', 'session.upload_progress.enabled': 'On' }, [8, 4, 1]);
  assert.ok(off.every((m) => m.applied === false));
  assert.equal(mitigations({}, [8, 5, 1]).length, 3);
  assert.ok(mitigations(null, [8, 4, 1]).every((m) => m.applied === null));
  assert.equal(mitigations({ fatal_error_backtraces: false }, [8, 5, 1])[2].applied, false);
});

test('assess: errors, hidden urls, fixes', () => {
  assert.equal(assess({ target: 'x', source: 'local', error: 'boom' }).status, 'error');
  assert.equal(assess({ target: 'x', source: 'manual', version: 'nope' }).status, 'error');
  const hidden = assess({ target: 'https://e.x', source: 'url', hidden: true });
  assert.equal(hidden.status, 'unknown');
  assert.match(hidden.fix, /expose_php/);
  assert.match(assess({ target: 'img', source: 'docker-image', version: '8.4.1' }).fix, /php:8\.4\.27/);
  assert.equal(assess({ target: 'x', source: 'manual', version: '8.4.27' }).fix, null);
});

test('exit codes and summary', () => {
  const p = assess({ target: 'a', source: 'manual', version: '8.4.27' });
  const v = assess({ target: 'b', source: 'manual', version: '8.4.1' });
  const e = assess({ target: 'c', source: 'manual', error: 'x' });
  assert.equal(exitCode([p]), 0);
  assert.equal(exitCode([p, v]), 1);
  assert.equal(exitCode([p, e]), 2);
  assert.equal(exitCode([]), 2);
  assert.deepEqual(summarize([p, v, e]).counts.vulnerable, 1);
});
