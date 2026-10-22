import assert from 'node:assert/strict';
import { test } from 'node:test';
import { main } from '../src/cli.js';
import { toHtml, toMarkdown } from '../src/report.js';
import { assess } from '../src/advisory.js';

function sink() {
  let buf = '';
  return { write: (s) => (buf += s), get text() { return buf; }, isTTY: false, columns: 100 };
}

async function cli(args) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(args, { stdout, stderr });
  return { code, out: stdout.text, err: stderr.text };
}

test('offline versions: exit codes and plain output', async () => {
  assert.equal((await cli(['8.4.27'])).code, 0);
  const r = await cli(['8.4.1', '--no-color']);
  assert.equal(r.code, 1);
  assert.match(r.out, /\[VULNERABLE\]/);
  assert.doesNotMatch(r.out, /\x1b\[/);
});

test('json output', async () => {
  const r = await cli(['8.3.30', '8.2.35', '--json']);
  const j = JSON.parse(r.out);
  assert.equal(j.summary.total, 2);
  assert.equal(j.results[0].status, 'vulnerable');
  assert.equal(j.fixed['8.4'], '8.4.27');
});

test('--ini feeds offline mitigation checks', async () => {
  const j = JSON.parse((await cli(['8.5.1', '--ini', 'memory_limit=-1', '--json'])).out);
  assert.equal(j.results[0].mitigations[0].applied, true);
  assert.equal(j.results[0].mitigations[1].applied, false);
});

test('bad arguments exit 2', async () => {
  assert.equal((await cli(['nonsense'])).code, 2);
  assert.equal((await cli(['--bogus'])).code, 2);
  assert.equal((await cli(['8.4.1', '--ini', 'novalue'])).code, 2);
});

test('info, help, version', async () => {
  assert.match((await cli(['info', '--no-color'])).out, /8\.4\.27/);
  assert.match((await cli(['--help'])).out, /Usage/);
  assert.match((await cli(['-v'])).out, /^\d+\.\d+\.\d+/);
});

test('reports escape untrusted target names', () => {
  const rs = [assess({ target: '<img src=x onerror=alert(1)>', source: 'manual', version: '8.4.1' })];
  const html = toHtml(rs);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(toMarkdown(rs), /Vulnerable/);
});
