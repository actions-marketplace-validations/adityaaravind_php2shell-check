import { spawn } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { VERSION, assess, exitCode, parseVersion, sortResults } from './advisory.js';
import { discoverLocal, listContainers, probeContainer, probeImage, probeLocal, probeUrl, readInventory } from './probes.js';
import { colorEnabled, palette, renderInfo, renderScan, spinner } from './render.js';
import { toHtml, toJson, toMarkdown } from './report.js';

const HELP = `php2shell-check v${VERSION}
Read-only exposure scanner for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

Usage
  php2shell-check [targets] [options]
  php2shell-check info                 advisory details, fixed versions, mitigations

Targets (combine freely; with none, PHP binaries on this machine are discovered)
  --local                  discover php, php8.x, php-fpm*, php-cgi* on PATH and sbin dirs
  --php <path>             probe a specific PHP binary (repeatable)
  --docker <image>         probe an image, e.g. php:8.3-fpm (repeatable; may pull)
  --containers             probe every running Docker container (docker exec, read-only)
  --container <name|id>    probe one running container (repeatable)
  --url <url>              passive check of the X-Powered-By header (repeatable)
  --inventory <file>       versions from a file: JSON, CSV/TSV "name,version", or one per line
  <x.y.z>                  check a version string offline (repeatable)

Options
  --ini <key=val>          ini values to assume for offline version checks (repeatable)
  --define <key=val>       pass -d key=val to local/Docker probes: test mitigations before rollout
  --json                   print JSON to stdout instead of the terminal UI
  --html <file>            write an HTML dashboard     --open   open it when done
  --markdown <file>        write a Markdown report (good for PRs and tickets)
  --concurrency <n>        parallel probes (default 4)
  --no-color               disable colors (NO_COLOR is honoured too)
  -h, --help               show this help        -v, --version   show version

Exit codes
  0 all targets patched   1 at least one target needs action   2 errors only / nothing scanned
`;

const OPTIONS = {
  local: { type: 'boolean' },
  php: { type: 'string', multiple: true },
  docker: { type: 'string', multiple: true },
  containers: { type: 'boolean' },
  container: { type: 'string', multiple: true },
  url: { type: 'string', multiple: true },
  inventory: { type: 'string', multiple: true },
  ini: { type: 'string', multiple: true },
  define: { type: 'string', multiple: true },
  json: { type: 'boolean' },
  html: { type: 'string' },
  markdown: { type: 'string' },
  open: { type: 'boolean' },
  concurrency: { type: 'string' },
  'no-color': { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean', short: 'v' },
};

function kv(list = []) {
  return Object.fromEntries(
    list.map((s) => {
      const i = s.indexOf('=');
      if (i < 1) throw new Error(`expected key=value, got "${s}"`);
      return [s.slice(0, i), s.slice(i + 1)];
    }),
  );
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const k = next++;
      out[k] = await fn(items[k]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

function openFile(file) {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', file] : [file];
  spawn(cmd, args, { detached: true, stdio: 'ignore' }).on('error', () => {}).unref();
}

// Each task: {label, source, run: () => probe | probe[]}.
async function buildTasks(v, positionals) {
  const tasks = [];
  const defines = v.define ?? [];
  kv(defines); // validate early
  const versions = positionals.filter((p) => parseVersion(p));
  const unknown = positionals.filter((p) => !parseVersion(p));
  if (unknown.length) throw new Error(`unknown argument(s): ${unknown.join(' ')} (see --help)`);

  const explicit =
    v.php || v.docker || v.containers || v.container || v.url || v.inventory || versions.length;
  if (v.local || !explicit) {
    const bins = await discoverLocal();
    if (!bins.length && !explicit) {
      throw new Error('no PHP binaries found on this machine. Try --docker <image>, --containers, --url, or a version like 8.3.30');
    }
    for (const b of bins) tasks.push({ label: b, source: 'local', run: () => probeLocal(b, defines) });
  }
  for (const b of v.php ?? []) tasks.push({ label: b, source: 'local', run: () => probeLocal(b, defines) });
  for (const img of v.docker ?? []) tasks.push({ label: img, source: 'docker-image', run: () => probeImage(img, defines) });
  if (v.containers || v.container) {
    const list = await listContainers(v.containers ? [] : v.container);
    for (const f of v.container ?? []) {
      if (!list.some((c) => c.name === f || c.id.startsWith(f))) {
        tasks.push({ label: f, source: 'container', run: async () => ({ target: f, source: 'container', error: 'no running container with that name or id' }) });
      }
    }
    for (const c of list) tasks.push({ label: c.name, source: 'container', run: () => probeContainer(c) });
  }
  for (const u of v.url ?? []) tasks.push({ label: u, source: 'url', run: () => probeUrl(u) });
  for (const f of v.inventory ?? []) tasks.push({ label: f, source: 'inventory', run: () => readInventory(f) });
  const ini = v.ini ? kv(v.ini) : null;
  for (const ver of versions) tasks.push({ label: ver, source: 'manual', run: async () => ({ target: ver, source: 'manual', version: ver, ini }) });
  return tasks;
}

export async function main(argv = process.argv.slice(2), io = { stdout: process.stdout, stderr: process.stderr }) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (e) {
    io.stderr.write(`error: ${e.message}\n\n${HELP}`);
    return 2;
  }
  const { values: v, positionals } = parsed;
  const c = palette(!v['no-color'] && !v.json && colorEnabled(io.stdout));

  if (v.help) return io.stdout.write(HELP), 0;
  if (v.version) return io.stdout.write(`${VERSION}\n`), 0;
  if (positionals[0] === 'info') return io.stdout.write(renderInfo(c)), 0;
  if (positionals[0] === 'scan') positionals.shift();

  let tasks;
  try {
    tasks = await buildTasks(v, positionals);
  } catch (e) {
    io.stderr.write(`error: ${e.message}\n`);
    return 2;
  }

  const spin = spinner(io.stderr, palette(colorEnabled(io.stderr)), !v.json && Boolean(io.stderr.isTTY));
  let done = 0;
  spin.start(`Probing ${tasks.length} target${tasks.length === 1 ? '' : 's'}…`);
  const n = Math.max(1, Number(v.concurrency) || 4);
  const nested = await pool(tasks, n, async (t) => {
    spin.update(`Probing ${done + 1}/${tasks.length} · ${t.label}`);
    let out;
    try {
      out = await t.run();
    } catch (e) {
      out = { target: t.label, source: t.source, error: e.message };
    }
    done++;
    return out;
  });
  spin.stop();

  const results = sortResults(nested.flat().map(assess));
  const generatedAt = new Date().toISOString();
  const reports = [];
  try {
    if (v.html) {
      await writeFile(v.html, toHtml(results, generatedAt));
      reports.push(`dashboard  ${path.resolve(v.html)}`);
      if (v.open) openFile(path.resolve(v.html));
    }
    if (v.markdown) {
      await writeFile(v.markdown, toMarkdown(results, generatedAt));
      reports.push(`markdown   ${path.resolve(v.markdown)}`);
    }
  } catch (e) {
    io.stderr.write(`error writing report: ${e.message}\n`);
    return 2;
  }

  if (v.json) io.stdout.write(JSON.stringify(toJson(results, generatedAt), null, 2) + '\n');
  else io.stdout.write(renderScan(c, results, { width: io.stdout.columns, reports }));
  return exitCode(results);
}
