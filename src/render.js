// Terminal UI: banner, results table, findings, summary bar, spinner.
import { CVES, FIXED, SOURCES, STATUSES, VERSION, fmt, summarize } from './advisory.js';

const ANSI = /\x1b\[[0-9;]*m/g;
export const visible = (s) => String(s).replace(ANSI, '').length;
const pad = (s, n) => s + ' '.repeat(Math.max(0, n - visible(s)));
const trunc = (s, n) => (String(s).length <= n ? String(s) : String(s).slice(0, Math.max(1, n - 1)) + '…');

export function colorEnabled(stream = process.stdout, env = process.env) {
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR && env.FORCE_COLOR !== '0') return true;
  return Boolean(stream.isTTY);
}

export function palette(on) {
  const w = (open, close) => (s) => (on ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));
  return {
    on,
    bold: w(1, 22),
    dim: w(2, 22),
    red: w(31, 39),
    green: w(32, 39),
    yellow: w(33, 39),
    blue: w(34, 39),
    magenta: w(35, 39),
    cyan: w(36, 39),
    gray: w(90, 39),
    paint: (code, s) => (on ? `\x1b[${code}m${s}\x1b[0m` : String(s)),
  };
}

export const META = {
  patched: { label: 'PATCHED', icon: '✔', color: 'green', pill: '42;30;1' },
  vulnerable: { label: 'VULNERABLE', icon: '✖', color: 'red', pill: '41;97;1' },
  'backport-needed': { label: 'BACKPORT', icon: '▲', color: 'yellow', pill: '43;30;1' },
  eol: { label: 'EOL', icon: '✖', color: 'magenta', pill: '45;97;1' },
  unknown: { label: 'UNKNOWN', icon: '?', color: 'gray', pill: '100;97;1' },
  error: { label: 'ERROR', icon: '!', color: 'red', pill: '101;30;1' },
};

const PILL_W = Math.max(...Object.values(META).map((m) => m.label.length)) + 2;

function pill(c, status) {
  const m = META[status];
  return c.on ? c.paint(m.pill, ' ' + m.label.padEnd(PILL_W - 2) + ' ') : `[${m.label}]`.padEnd(PILL_W);
}

function box(c, lines, width) {
  const inner = width - 4;
  const top = c.gray('╭' + '─'.repeat(width - 2) + '╮');
  const bot = c.gray('╰' + '─'.repeat(width - 2) + '╯');
  return [top, ...lines.map((l) => c.gray('│ ') + pad(l, inner) + c.gray(' │')), bot].join('\n');
}

export function banner(c) {
  const lines = [
    c.bold('php2shell-check') + c.gray(` v${VERSION}`),
    c.gray('PHP2Shell exposure scanner · read-only · no exploit code'),
    `${c.red('●')} ${CVES.map((x) => c.bold(x.id)).join(c.gray(' + '))} ${c.gray('· CVSS v4.0 9.2')}`,
  ];
  return box(c, lines, Math.max(...lines.map(visible)) + 4);
}

function cols(width) {
  return Math.max(70, Math.min(width || 100, 140));
}

export function table(c, results, width) {
  const W = cols(width);
  const ver = Math.max(7, ...results.map((r) => String(r.version ?? '-').length));
  const sapi = Math.max(4, ...results.map((r) => String(r.sapi ?? '-').length));
  const src = Math.max(6, ...results.map((r) => r.source.length));
  const fixed = PILL_W + ver + sapi + src + 2 + 4 * 2;
  const tgt = Math.max(12, Math.min(Math.max(...results.map((r) => r.target.length)), W - fixed));
  const head = ['STATUS'.padEnd(PILL_W), 'TARGET'.padEnd(tgt), 'VERSION'.padEnd(ver), 'SAPI'.padEnd(sapi), 'SOURCE'];
  const out = ['  ' + c.gray(head.join('  ')), '  ' + c.gray('─'.repeat(PILL_W + tgt + ver + sapi + src + 8))];
  for (const r of results) {
    out.push(
      '  ' +
        [
          pill(c, r.status),
          pad(c.bold(trunc(r.target, tgt)), tgt),
          pad(r.version ? c[META[r.status].color](r.version) : c.gray('-'), ver),
          pad(c.gray(r.sapi ?? '-'), sapi),
          c.gray(r.source),
        ].join('  '),
    );
  }
  return out.join('\n');
}

export function findings(c, results) {
  const out = [];
  for (const r of results.filter((x) => x.status !== 'patched')) {
    const m = META[r.status];
    out.push(`  ${c[m.color](m.icon)} ${c.bold(r.target)}  ${c.gray(r.version && r.version !== r.target ? r.version + ' · ' : '')}${c[m.color](r.detail)}`);
    if (r.image) out.push(`    ${c.gray('image')}  ${r.image}`);
    if (r.fix) out.push(`    ${c.gray('fix  ')}  ${r.fix}`);
    if (r.note) out.push(`    ${c.gray('note ')}  ${c.gray(r.note)}`);
    if (r.mitigations.length) {
      out.push(`    ${c.gray('interim mitigations (reduce exposure, not a fix)')}`);
      const kw = Math.max(...r.mitigations.map((x) => `${x.key}=${x.want}`.length));
      for (const x of r.mitigations) {
        const icon = x.applied === null ? c.gray('?') : x.applied ? c.green('✔') : c.red('✖');
        const now = x.applied === null ? c.gray('not checked') : c.gray(`now ${x.current ?? 'unset'}`);
        out.push(`      ${icon} ${pad(`${x.key}=${x.want}`, kw)}  ${now}`);
      }
    }
    out.push('');
  }
  return out.join('\n').trimEnd();
}

const BAR_ORDER = ['patched', 'backport-needed', 'vulnerable', 'eol', 'unknown', 'error'];

export function summaryBar(c, results, width = 32) {
  const s = summarize(results);
  let bar = '';
  if (s.total) {
    let used = 0;
    BAR_ORDER.forEach((st, i) => {
      const n = s.counts[st];
      if (!n) return;
      const last = BAR_ORDER.slice(i + 1).every((x) => !s.counts[x]);
      const len = last ? width - used : Math.max(1, Math.round((n / s.total) * width));
      used += len;
      bar += c[META[st].color]((c.on || st === 'patched' ? '█' : '░').repeat(len));
    });
  }
  const parts = BAR_ORDER.filter((st) => s.counts[st]).map((st) => c[META[st].color](`${s.counts[st]} ${META[st].label.toLowerCase()}`));
  return `  ${c.bold(String(s.total))} ${s.total === 1 ? 'target ' : 'targets'}  ${bar}  ${parts.join(c.gray(' · '))}`;
}

export function verdict(c, results) {
  const s = summarize(results);
  if (!s.total) return `  ${c.yellow('!')} Nothing was scanned.`;
  if (s.needAction === 0 && s.counts.error === 0) return `  ${c.green('✔')} ${c.bold('All targets patched against PHP2Shell.')}`;
  if (s.needAction === 0) return `  ${c.yellow('!')} ${c.bold(`No exposed targets found, but ${s.counts.error} could not be checked.`)}`;
  return `  ${c.red('✖')} ${c.bold(`${s.needAction} of ${s.total} targets need action.`)} ${c.gray('Patching is the only complete fix.')}`;
}

export function renderScan(c, results, { width, reports = [] } = {}) {
  const parts = [banner(c), '', table(c, results, width)];
  const f = findings(c, results);
  if (f) parts.push('', c.bold('  Findings'), '', f);
  parts.push('', '  ' + c.gray('─'.repeat(60)), summaryBar(c, results), verdict(c, results));
  for (const r of reports) parts.push(`  ${c.cyan('→')} ${r}`);
  parts.push(c.gray(`  php2shell-check info · advisory details    --html report.html · dashboard`), '');
  return parts.join('\n');
}

export function renderInfo(c) {
  const out = [banner(c), ''];
  for (const x of CVES) {
    out.push(`  ${c.red('●')} ${c.bold(x.id)} ${c.gray('·')} ${x.name} ${c.gray(`· CVSS v4.0 ${x.cvss}`)}`);
    out.push(`    ${x.summary}`, '');
  }
  out.push(c.bold('  Fixed releases'));
  for (const [b, v] of Object.entries(FIXED)) out.push(`    ${c.gray(b.padEnd(8))}${c.green(fmt(v))}`);
  out.push(`    ${c.gray('7.4-8.1 ')}${c.yellow('source backports only, no official release')}`);
  out.push(`    ${c.gray('< 7.4   ')}${c.magenta('end-of-life, no fix')}`, '');
  out.push(c.bold('  Interim mitigations') + c.gray(' (reduce exposure, not a fix; restart workers after)'));
  out.push('    memory_limit=-1                    ' + c.gray('CVE-2026-109618, set so apps cannot override'));
  out.push('    session.upload_progress.enabled=0  ' + c.gray('CVE-2026-109619'));
  out.push('    fatal_error_backtraces=0           ' + c.gray('CVE-2026-109619, PHP 8.5 only'), '');
  out.push(c.bold('  Sources'));
  for (const [name, url] of SOURCES) out.push(`    ${name.padEnd(12)}${c.cyan(url)}`);
  out.push('');
  return out.join('\n');
}

export function spinner(stream, c, enabled) {
  const frames = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏';
  let i = 0;
  let text = '';
  let timer = null;
  const draw = () => stream.write(`\r\x1b[2K  ${c.cyan(frames[i++ % frames.length])} ${text}`);
  return {
    start(t) {
      text = t;
      if (enabled) timer = setInterval(draw, 80);
    },
    update(t) {
      text = t;
    },
    log(line) {
      if (enabled) stream.write(`\r\x1b[2K${line}\n`);
    },
    stop() {
      if (timer) clearInterval(timer);
      if (enabled) stream.write('\r\x1b[2K');
    },
  };
}

export { STATUSES };
