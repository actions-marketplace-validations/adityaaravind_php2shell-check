import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseInventory, parsePhpInfo, parseProbeJson, probeUrl, shortSapi } from '../src/probes.js';

test('parseProbeJson tolerates leading noise', () => {
  const r = parseProbeJson('Warning: x\n{"version":"8.3.1","sapi":"cli","ini":{"memory_limit":"128M"}}');
  assert.equal(r.version, '8.3.1');
  assert.equal(r.sapi, 'cli');
  assert.equal(r.ini.memory_limit, '128M');
});

test('parsePhpInfo text output (php-fpm -i)', () => {
  const r = parsePhpInfo(
    'phpinfo()\nPHP Version => 8.3.30\n\nServer API => FPM/FastCGI\nmemory_limit => 256M => 256M\nsession.upload_progress.enabled => On => On\n',
  );
  assert.deepEqual(r, { version: '8.3.30', sapi: 'fpm', ini: { memory_limit: '256M', 'session.upload_progress.enabled': 'On' } });
});

test('parsePhpInfo HTML output (php-cgi -i)', () => {
  const html =
    '<html><body><h1 class="p">PHP Version 8.2.10</h1><table><tr><td class="e">Server API </td><td class="v">CGI/FastCGI </td></tr>' +
    '<tr><td class="e">memory_limit</td><td class="v">-1</td><td class="v">-1</td></tr></table></body></html>';
  const r = parsePhpInfo(html);
  assert.equal(r.version, '8.2.10');
  assert.equal(r.sapi, 'cgi');
  assert.equal(r.ini.memory_limit, '-1');
});

test('shortSapi', () => {
  assert.equal(shortSapi('apache2handler'), 'apache');
  assert.equal(shortSapi('Command Line Interface'), 'cli');
  assert.equal(shortSapi(null), null);
});

test('parseInventory: csv with header, plain lines, json', () => {
  const csv = parseInventory('name,version\nweb-1,8.3.30\n# comment\nweb-2,8.4.27\n', 'hosts.csv');
  assert.deepEqual(csv.map((x) => [x.target, x.version]), [['web-1', '8.3.30'], ['web-2', '8.4.27']]);
  const plain = parseInventory('8.1.2\n\n8.2.35\n', 'v.txt');
  assert.deepEqual(plain.map((x) => x.target), ['v.txt:1', 'v.txt:3']);
  const json = parseInventory('[{"name":"api","version":"8.5.11","ini":{"memory_limit":"-1"}}]');
  assert.equal(json[0].target, 'api');
  assert.equal(json[0].ini.memory_limit, '-1');
});

const fakeFetch = (headers, status = 200) => async () => ({ status, headers: new Headers(headers), body: null });

test('probeUrl reads X-Powered-By', async () => {
  const r = await probeUrl('https://e.x', fakeFetch({ 'x-powered-by': 'PHP/8.4.26' }));
  assert.equal(r.version, '8.4.26');
  const hidden = await probeUrl('https://e.x', fakeFetch({}));
  assert.equal(hidden.hidden, true);
  const other = await probeUrl('https://e.x', fakeFetch({ 'x-powered-by': 'Express' }));
  assert.match(other.note, /Express/);
});
