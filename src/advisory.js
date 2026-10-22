// Advisory data and pure verdict logic for PHP2Shell. No I/O in this module.
import { readFileSync } from 'node:fs';

export const VERSION = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;

export const REPO = 'https://github.com/adityaaravind/php2shell-check';

export const CVES = [
  {
    id: 'CVE-2026-109618',
    name: 'Out-of-memory handling',
    cvss: '9.2',
    summary:
      'Memory runs out while request data is only partly initialized; the cleanup that follows treats that data as valid.',
  },
  {
    id: 'CVE-2026-109619',
    name: 'Stale request state (use-after-free)',
    cvss: '9.2',
    summary:
      'State left over from one request points at freed memory that a later request on the same worker uses. Memory disclosure is also a confirmed impact.',
  },
];

// Branch -> first fixed official release.
export const FIXED = {
  '8.5': [8, 5, 12],
  '8.4': [8, 4, 27],
  '8.3': [8, 3, 36],
  '8.2': [8, 2, 35],
};

export const SOURCES = [
  ['Tenable FAQ', 'https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote'],
  ['Qualys', 'https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities'],
  ['Rapid7', 'https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/'],
  ['php.net', 'https://www.php.net/'],
];

// Ordered worst-first; used for sorting and summaries.
export const STATUSES = ['vulnerable', 'eol', 'backport-needed', 'unknown', 'error', 'patched'];

export function parseVersion(text) {
  const m = /(?:^|[^\d.])(\d+)\.(\d+)\.(\d+)/.exec(' ' + String(text ?? ''));
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

export const fmt = (v) => v.join('.');

export function cmp(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function classify(v) {
  const fixed = FIXED[`${v[0]}.${v[1]}`];
  if (fixed) {
    return cmp(v, fixed) >= 0
      ? { status: 'patched', detail: `${fmt(v)} >= ${fmt(fixed)}`, fixedIn: fmt(fixed) }
      : { status: 'vulnerable', detail: `upgrade to ${fmt(fixed)} or later`, fixedIn: fmt(fixed) };
  }
  const branch = v[0] * 100 + v[1];
  if (branch >= 704 && branch < 802) {
    return { status: 'backport-needed', detail: 'no official release; apply source backport or verify distro patch', fixedIn: null };
  }
  if (branch < 704) {
    return { status: 'eol', detail: 'end-of-life, no fix; migrate to a supported branch', fixedIn: null };
  }
  return { status: 'unknown', detail: 'branch newer than this tool knows; check php.net', fixedIn: null };
}

const truthy = (v) => ['1', 'on', 'true', 'yes'].includes(String(v).trim().toLowerCase());

// Interim hardening from the PHP advisory. Reduces exposure, does not fix.
// `applied` is true/false, or null when ini values were not available.
export function mitigations(ini, v) {
  const items = [
    { cve: 'CVE-2026-109618', key: 'memory_limit', want: '-1', ok: (x) => String(x).trim() === '-1' },
    { cve: 'CVE-2026-109619', key: 'session.upload_progress.enabled', want: '0', ok: (x) => !truthy(x) },
  ];
  if (v && v[0] === 8 && v[1] === 5) {
    items.push({ cve: 'CVE-2026-109619', key: 'fatal_error_backtraces', want: '0', ok: (x) => !truthy(x) });
  }
  return items.map(({ ok, ...it }) => {
    if (ini == null) return { ...it, current: null, applied: null };
    const cur = ini[it.key];
    const known = cur !== undefined && cur !== null && cur !== false;
    return { ...it, current: known ? String(cur) : null, applied: known ? ok(cur) : false };
  });
}

export function remediation(r) {
  if (r.status === 'patched' || r.status === 'error') return null;
  if (r.status === 'backport-needed') return "apply the PHP security team's source backport (or your vendor's patched build), or move to 8.2+";
  if (r.status === 'eol') return 'migrate to a supported branch (8.2+) at its fixed release; no patch exists';
  if (r.status === 'unknown' && r.source === 'url') return 'fingerprint the host from inside (run this tool there); keep expose_php=Off';
  const target = r.fixedIn ?? '8.4.27+';
  switch (r.source) {
    case 'docker-image':
      return `rebuild on a patched base image (php:${target} or newer, same variant)`;
    case 'container':
      return `rebuild the image on php ${target}+ and redeploy; restart workers`;
    case 'url':
      return `patch the server to PHP ${target}+; also set expose_php=Off`;
    default:
      return r.fixedIn
        ? `upgrade the ${r.version.split('.').slice(0, 2).join('.')} branch to ${r.fixedIn}+ (distro builds may backport under an older version string)`
        : 'move to a supported branch (8.2+) at its fixed release';
  }
}

// Probe -> result. A probe is {target, source, version?, sapi?, ini?, error?, hidden?, note?}.
export function assess(probe) {
  if (probe.error) return { ...probe, status: 'error', detail: probe.error, mitigations: [], fix: null };
  if (probe.hidden) {
    const r = { ...probe, version: null, status: 'unknown', detail: 'PHP version not disclosed; cannot fingerprint remotely', mitigations: [] };
    return { ...r, fix: remediation(r) };
  }
  const v = parseVersion(probe.version);
  if (!v) return { ...probe, status: 'error', detail: `cannot parse PHP version: ${probe.version}`, mitigations: [], fix: null };
  const r = { ...probe, version: fmt(v), rawVersion: String(probe.version), ...classify(v), mitigations: mitigations(probe.ini ?? null, v) };
  return { ...r, fix: remediation(r) };
}

export function summarize(results) {
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  for (const r of results) counts[r.status]++;
  const needAction = results.filter((r) => r.status !== 'patched' && r.status !== 'error').length;
  return { total: results.length, needAction, counts };
}

export function sortResults(results) {
  return [...results].sort((a, b) => STATUSES.indexOf(a.status) - STATUSES.indexOf(b.status));
}

// 0 = everything patched, 1 = something needs action, 2 = only errors / nothing scanned.
export function exitCode(results) {
  const s = summarize(results);
  if (s.needAction > 0) return 1;
  if (s.total === 0 || s.counts.error > 0) return 2;
  return 0;
}
