// Read-only probes. Each returns a probe object (see advisory.assess) or an array of them.
import { execFile } from 'node:child_process';
import { readdir, readFile, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { VERSION, REPO } from './advisory.js';

const run = promisify(execFile);
const LOCAL_TIMEOUT = 60_000;
const DOCKER_TIMEOUT = 300_000; // first `docker run` may pull the image
const MAX_BUFFER = 8 * 1024 * 1024;

export const INI_KEYS = ['memory_limit', 'session.upload_progress.enabled', 'fatal_error_backtraces'];

export const PROBE_CODE =
  'echo json_encode(["version"=>PHP_VERSION,"sapi"=>PHP_SAPI,"ini"=>[' +
  INI_KEYS.map((k) => `"${k}"=>ini_get("${k}")`).join(',') +
  ']]);';

const BIN_RE = /^php(-fpm|-cgi)?(\d+(\.\d+)?)?$/;
const EXTRA_DIRS = ['/usr/sbin', '/usr/local/sbin', '/usr/local/bin', '/opt/homebrew/bin', '/opt/homebrew/sbin'];

export function shortSapi(s) {
  if (!s) return null;
  if (/fpm/i.test(s)) return 'fpm';
  if (/cli|command line/i.test(s)) return 'cli';
  if (/apache/i.test(s)) return 'apache';
  if (/litespeed/i.test(s)) return 'litespeed';
  if (/frankenphp/i.test(s)) return 'frankenphp';
  if (/cgi/i.test(s)) return 'cgi';
  return s;
}

export function parseProbeJson(stdout) {
  const o = JSON.parse(stdout.slice(stdout.indexOf('{')));
  return { version: o.version, sapi: shortSapi(o.sapi), ini: o.ini ?? null };
}

// Parses `php -i` / `php-fpm -i` output, text or HTML.
export function parsePhpInfo(raw) {
  let t = String(raw);
  if (/<table|<html/i.test(t)) {
    t = t
      .replace(/<\/t[dh]>\s*<t[dh][^>]*>/gi, ' => ')
      .replace(/<\/tr>|<\/h1>|<br\s*\/?>/gi, '\n')
      .replace(/<[^>]+>/g, '')
      .replace(/&nbsp;/g, ' ')
      .replace(/&gt;/g, '>')
      .replace(/&lt;/g, '<')
      .replace(/&amp;/g, '&');
  }
  let version = null;
  let sapi = null;
  const ini = {};
  for (const line of t.split(/\r?\n/)) {
    const parts = line.split(' => ').map((s) => s.trim());
    if (parts[0] === 'PHP Version' && parts[1] && !version) version = parts[1];
    else if (parts[0] === 'Server API' && parts[1]) sapi = parts[1];
    else if (INI_KEYS.includes(parts[0]) && parts.length >= 2) ini[parts[0]] = parts[1];
  }
  if (!version) version = /PHP Version\s+(\d+\.\d+\.\d+\S*)/.exec(t)?.[1] ?? null;
  return { version, sapi: shortSapi(sapi), ini };
}

function shortErr(e) {
  if (!e) return 'unknown error';
  if (e.code === 'ENOENT') return `${e.path ?? 'command'} not found`;
  if (e.killed || e.signal === 'SIGTERM') return 'timed out';
  const line = String(e.stderr || e.message || e).trim().split('\n').find(Boolean) ?? 'failed';
  return line.length > 160 ? line.slice(0, 157) + '...' : line;
}

const defineArgs = (defines = []) => defines.flatMap((d) => ['-d', d]);

// exec(args) runs the PHP binary with extra args. Tries `-r` JSON first, then `-i`.
async function probePhp(exec, { infoOnly = false, defines = [] } = {}) {
  const d = defineArgs(defines);
  let firstErr;
  if (!infoOnly) {
    try {
      return parseProbeJson((await exec([...d, '-r', PROBE_CODE])).stdout);
    } catch (e) {
      firstErr = e;
    }
  }
  try {
    const r = parsePhpInfo((await exec([...d, '-i'])).stdout);
    if (r.version) return r;
  } catch (e) {
    firstErr ??= e;
  }
  throw new Error(shortErr(firstErr));
}

const isFpmOrCgi = (bin) => /fpm|cgi/.test(path.basename(bin));

export async function discoverLocal(envPath = process.env.PATH ?? '') {
  const dirs = [...new Set([...envPath.split(path.delimiter).filter(Boolean), ...EXTRA_DIRS])];
  const seen = new Map();
  for (const dir of dirs) {
    let names;
    try {
      names = await readdir(dir);
    } catch {
      continue;
    }
    for (const name of names.filter((n) => BIN_RE.test(n)).sort()) {
      const full = path.join(dir, name);
      try {
        const real = await realpath(full);
        if ((await stat(real)).isFile() && !seen.has(real)) seen.set(real, full);
      } catch {
        // dangling symlink: skip
      }
    }
  }
  return [...seen.values()];
}

export async function probeLocal(bin, defines) {
  const exec = (args) => run(bin, args, { timeout: LOCAL_TIMEOUT, maxBuffer: MAX_BUFFER });
  const r = await probePhp(exec, { infoOnly: isFpmOrCgi(bin), defines });
  return { target: bin, source: 'local', ...r };
}

export async function probeImage(image, defines) {
  const exec = (args) =>
    run('docker', ['run', '--rm', '--entrypoint', 'php', image, ...args], { timeout: DOCKER_TIMEOUT, maxBuffer: MAX_BUFFER });
  const r = await probePhp(exec, { defines });
  return { target: image, source: 'docker-image', ...r };
}

export async function listContainers(filters = []) {
  const { stdout } = await run('docker', ['ps', '--format', '{{.ID}}\t{{.Names}}\t{{.Image}}'], { timeout: LOCAL_TIMEOUT });
  const rows = stdout
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      const [id, name, image] = l.split('\t');
      return { id, name, image };
    });
  if (!filters.length) return rows;
  return rows.filter((c) => filters.some((f) => c.name === f || c.id.startsWith(f)));
}

const FIND_BINS =
  'for b in php php-fpm $(ls /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* 2>/dev/null); do command -v "$b"; done 2>/dev/null | sort -u';

// Probes every PHP binary inside a running container (CLI and FPM can differ).
export async function probeContainer(c) {
  const dexec = (bin) => (args) =>
    run('docker', ['exec', c.id, bin, ...args], { timeout: LOCAL_TIMEOUT, maxBuffer: MAX_BUFFER });
  let bins;
  try {
    const { stdout } = await run('docker', ['exec', c.id, 'sh', '-c', FIND_BINS], { timeout: LOCAL_TIMEOUT });
    bins = stdout.split('\n').filter(Boolean);
  } catch {
    bins = ['php']; // no shell (distroless): try php directly
  }
  if (!bins.length) return [{ target: c.name, source: 'container', image: c.image, error: 'no PHP binary found' }];
  return Promise.all(
    bins.map(async (bin) => {
      const target = `${c.name}:${path.basename(bin)}`;
      try {
        const r = await probePhp(dexec(bin), { infoOnly: isFpmOrCgi(bin) });
        return { target, source: 'container', image: c.image, ...r };
      } catch (e) {
        return { target, source: 'container', image: c.image, error: e.message };
      }
    }),
  );
}

// Passive fingerprint: one HEAD (or GET) request, reads X-Powered-By only.
export async function probeUrl(url, fetchImpl = fetch) {
  const opts = (method) => ({
    method,
    redirect: 'follow',
    signal: AbortSignal.timeout(15_000),
    headers: { 'user-agent': `php2shell-check/${VERSION} (+${REPO})` },
  });
  let res = await fetchImpl(url, opts('HEAD'));
  if (res.status === 405 || res.status === 501) {
    res = await fetchImpl(url, opts('GET'));
    await res.body?.cancel?.();
  }
  const xp = res.headers.get('x-powered-by');
  const m = xp && /PHP\/(\d+\.\d+\.\d+\S*)/i.exec(xp);
  if (!m) {
    return { target: url, source: 'url', hidden: true, note: xp ? `X-Powered-By: ${xp}` : 'no X-Powered-By header' };
  }
  return { target: url, source: 'url', version: m[1], sapi: 'remote', note: 'from X-Powered-By header; can be stale or spoofed, confirm on the host' };
}

// Inventory: JSON array [{name, version, ini?}], or lines of "version" / "name,version" (CSV or TSV).
export function parseInventory(text, file = 'inventory') {
  const t = String(text).trim();
  if (t.startsWith('[')) {
    return JSON.parse(t).map((o, i) => ({
      target: String(o.name ?? o.host ?? o.target ?? `${path.basename(file)}#${i + 1}`),
      source: 'inventory',
      version: String(o.version ?? ''),
      ini: o.ini ?? null,
    }));
  }
  const out = [];
  t.split(/\r?\n/).forEach((line, i) => {
    const l = line.trim();
    if (!l || l.startsWith('#')) return;
    const cells = l.split(/[,\t]/).map((s) => s.trim());
    if (cells.length === 1) {
      out.push({ target: `${path.basename(file)}:${i + 1}`, source: 'inventory', version: cells[0] });
    } else if (!(out.length === 0 && /version/i.test(cells[1]))) {
      out.push({ target: cells[0], source: 'inventory', version: cells[1] });
    }
  });
  return out;
}

export async function readInventory(file) {
  return parseInventory(await readFile(file, 'utf8'), file);
}
