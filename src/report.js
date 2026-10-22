// Machine and shareable outputs: JSON, Markdown and a self-contained HTML dashboard.
import { CVES, FIXED, REPO, SOURCES, VERSION, fmt, summarize } from './advisory.js';

export function toJson(results, generatedAt = new Date().toISOString()) {
  return {
    tool: 'php2shell-check',
    version: VERSION,
    generatedAt,
    cves: CVES.map((c) => c.id),
    fixed: Object.fromEntries(Object.entries(FIXED).map(([b, v]) => [b, fmt(v)])),
    summary: summarize(results),
    results,
  };
}

const LABEL = {
  patched: 'Patched',
  vulnerable: 'Vulnerable',
  'backport-needed': 'Backport needed',
  eol: 'End-of-life',
  unknown: 'Unknown',
  error: 'Error',
};

const mdCell = (s) => String(s ?? '-').replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function toMarkdown(results, generatedAt = new Date().toISOString()) {
  const s = summarize(results);
  const lines = [
    '# PHP2Shell exposure report',
    '',
    `Generated ${generatedAt} by [php2shell-check](${REPO}) v${VERSION}. Covers ${CVES.map((c) => c.id).join(' and ')}.`,
    '',
    `**${s.needAction} of ${s.total} targets need action.** ` +
      Object.entries(s.counts)
        .filter(([, n]) => n)
        .map(([k, n]) => `${n} ${LABEL[k].toLowerCase()}`)
        .join(', '),
    '',
    '| Status | Target | Version | SAPI | Source | Detail | Fix |',
    '|---|---|---|---|---|---|---|',
    ...results.map((r) =>
      `| ${LABEL[r.status]} | ${mdCell(r.target)} | ${mdCell(r.version)} | ${mdCell(r.sapi)} | ${r.source} | ${mdCell(r.detail)} | ${mdCell(r.fix)} |`,
    ),
    '',
    '> Patching is the only complete fix. Interim mitigations: `memory_limit=-1`, `session.upload_progress.enabled=0`, and on 8.5 `fatal_error_backtraces=0`; restart workers after.',
    '',
  ];
  return lines.join('\n');
}

const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);

export function toHtml(results, generatedAt = new Date().toISOString()) {
  const data = JSON.stringify(toJson(results, generatedAt)).replace(/</g, '\\u003c');
  const fixedRows = Object.entries(FIXED)
    .map(([b, v]) => `<tr><td>${b}</td><td class="ok">${fmt(v)}</td></tr>`)
    .join('');
  const cveCards = CVES.map(
    (c) => `<div class="cve"><div class="cve-id">${esc(c.id)}<span class="cvss">CVSS ${esc(c.cvss)}</span></div><div class="cve-name">${esc(c.name)}</div><p>${esc(c.summary)}</p></div>`,
  ).join('');
  const sources = SOURCES.map(([n, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(n)}</a>`).join(' · ');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP2Shell Exposure Report</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--ink:#14171c;--muted:#5d6672;--line:#e3e6ea;--chip:#eef0f3;
--patched:#1a7f37;--vulnerable:#cf222e;--backport-needed:#b07800;--eol:#8250df;--unknown:#6e7781;--error:#d1242f;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--muted:#8d96a0;--line:#2a313a;--chip:#21262d;
--patched:#3fb950;--vulnerable:#f85149;--backport-needed:#d29922;--eol:#a371f7;--unknown:#8d96a0;--error:#ff7b72;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--muted:#8d96a0;--line:#2a313a;--chip:#21262d;
--patched:#3fb950;--vulnerable:#f85149;--backport-needed:#d29922;--eol:#a371f7;--unknown:#8d96a0;--error:#ff7b72;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1180px;margin:0 auto;padding:28px 16px 48px}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;justify-content:space-between;margin-bottom:20px}
h1{margin:0;font-size:24px;letter-spacing:-.01em}
.sub{color:var(--muted);margin-top:4px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;background:var(--chip);color:var(--muted)}
.badge.crit{background:color-mix(in srgb,var(--vulnerable) 15%,transparent);color:var(--vulnerable)}
button.theme{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:8px;padding:6px 10px;cursor:pointer}
.verdict{border-radius:12px;padding:16px 18px;margin-bottom:18px;font-weight:600;font-size:16px;border:1px solid var(--line);background:var(--panel)}
.verdict.bad{border-color:color-mix(in srgb,var(--vulnerable) 45%,var(--line));background:color-mix(in srgb,var(--vulnerable) 8%,var(--panel))}
.verdict.good{border-color:color-mix(in srgb,var(--patched) 45%,var(--line));background:color-mix(in srgb,var(--patched) 8%,var(--panel))}
.verdict small{display:block;font-weight:400;color:var(--muted);font-size:13px;margin-top:2px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card .n{font-size:28px;font-weight:700;line-height:1.1}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.card.s{border-top:3px solid var(--c)} .card.s .n{color:var(--c)}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:18px}
@media (max-width:900px){.layout{grid-template-columns:minmax(0,1fr)}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.panel h2{font-size:14px;margin:0 0 12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.donut-wrap{display:flex;gap:16px;align-items:center}
.donut{width:120px;height:120px;border-radius:50%;flex:none;position:relative}
.donut::after{content:"";position:absolute;inset:22px;border-radius:50%;background:var(--panel)}
.donut span{position:absolute;inset:0;display:grid;place-items:center;z-index:1;font-weight:700;font-size:22px}
.legend{display:grid;gap:4px;font-size:13px}
.dot{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px;background:var(--c)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.chip{border:1px solid var(--line);background:var(--chip);color:var(--ink);border-radius:999px;padding:4px 12px;cursor:pointer;font-size:13px}
.chip[aria-pressed="true"]{background:var(--ink);color:var(--panel);border-color:var(--ink)}
input[type=search]{flex:1;min-width:160px;border:1px solid var(--line);background:var(--bg);color:var(--ink);border-radius:8px;padding:6px 10px;font:inherit}
.tbl{width:100%;border-collapse:collapse}
.tbl th{text-align:left;font-size:12px;color:var(--muted);font-weight:600;padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
.tbl td{padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
.tbl tr.row{cursor:pointer} .tbl tr.row:hover td{background:color-mix(in srgb,var(--chip) 60%,transparent)}
.pill{display:inline-block;padding:2px 8px;border-radius:6px;font-size:12px;font-weight:700;color:#fff;background:var(--c);white-space:nowrap}
.tgt{font-weight:600;overflow-wrap:anywhere;min-width:180px}
.tbl tr.row td:nth-child(n+3):nth-child(-n+5){white-space:nowrap}
.card.zero{opacity:.5}
.muted{color:var(--muted)}
.detail td{background:color-mix(in srgb,var(--chip) 45%,transparent);font-size:13px}
.detail ul{margin:6px 0 0;padding-left:0;list-style:none}
.detail li{margin:2px 0}
.ok{color:var(--patched)} .bad{color:var(--vulnerable)}
.cve{border-top:1px solid var(--line);padding-top:10px;margin-top:10px}
.cve:first-of-type{border-top:0;margin-top:0;padding-top:0}
.cve-id{font-weight:700;display:flex;justify-content:space-between;gap:8px}
.cvss{color:var(--vulnerable);font-size:12px}
.cve-name{color:var(--muted);font-size:13px}
.cve p{margin:6px 0 0;font-size:13px}
.side{display:grid;gap:18px;align-content:start}
.mini{width:100%;border-collapse:collapse;font-size:13px}
.mini td{padding:4px 0;border-bottom:1px solid var(--line)}
.mini td:last-child{text-align:right;font-weight:600}
.scroll{overflow-x:auto}
footer{margin-top:24px;color:var(--muted);font-size:12px}
footer a,.panel a{color:inherit}
.empty{padding:24px;text-align:center;color:var(--muted)}
@media print{button,.toolbar{display:none}.detail{display:table-row!important}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div>
    <h1>PHP2Shell Exposure Report</h1>
    <div class="sub"><span class="badge crit">CVE-2026-109618</span> <span class="badge crit">CVE-2026-109619</span> <span class="badge">CVSS v4.0 9.2</span> <span class="muted" id="gen"></span></div>
  </div>
  <button class="theme" id="theme" type="button">Toggle theme</button>
</header>
<div class="verdict" id="verdict"></div>
<div class="grid" id="cards"></div>
<div class="layout">
  <section class="panel">
    <h2>Targets</h2>
    <div class="toolbar" id="toolbar"><input type="search" id="q" placeholder="Filter targets…" aria-label="Filter targets"></div>
    <div class="scroll"><table class="tbl"><thead><tr><th>Status</th><th>Target</th><th>Version</th><th>SAPI</th><th>Source</th><th>Detail</th></tr></thead><tbody id="rows"></tbody></table></div>
  </section>
  <aside class="side">
    <section class="panel"><h2>Breakdown</h2><div class="donut-wrap"><div class="donut" id="donut"><span id="donut-n"></span></div><div class="legend" id="legend"></div></div></section>
    <section class="panel"><h2>Fixed releases</h2><table class="mini">${fixedRows}<tr><td>7.4 – 8.1</td><td style="color:var(--backport-needed)">backport only</td></tr><tr><td>&lt; 7.4</td><td style="color:var(--eol)">EOL, no fix</td></tr></table></section>
    <section class="panel"><h2>The vulnerabilities</h2>${cveCards}</section>
    <section class="panel"><h2>Interim mitigations</h2><p class="muted" style="margin-top:0">Reduce exposure only. Patching is the complete fix. Restart workers after.</p><ul style="padding-left:18px;margin:0"><li><code>memory_limit=-1</code></li><li><code>session.upload_progress.enabled=0</code></li><li><code>fatal_error_backtraces=0</code> (8.5)</li></ul></section>
  </aside>
</div>
<footer>Generated by <a href="${REPO}">php2shell-check</a> v${esc(VERSION)} · read-only scan, no exploit code · Sources: ${sources}</footer>
</div>
<script id="data" type="application/json">${data}</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent);
var LABEL=${JSON.stringify(LABEL)};
var ORDER=['vulnerable','eol','backport-needed','unknown','error','patched'];
var root=document.documentElement;
try{var t=localStorage.getItem('p2s-theme');if(t)root.dataset.theme=t;}catch(e){}
document.getElementById('theme').onclick=function(){
  var dark=root.dataset.theme?root.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme=dark?'light':'dark';try{localStorage.setItem('p2s-theme',root.dataset.theme);}catch(e){}
};
function el(tag,attrs,html){var e=document.createElement(tag);for(var k in attrs||{}){if(k==='style')e.style.cssText=attrs[k];else e.setAttribute(k,attrs[k]);}if(html!=null)e.innerHTML=html;return e;}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
var cv=function(s){return 'var(--'+s+')';};
document.getElementById('gen').textContent='· '+new Date(D.generatedAt).toLocaleString();
var S=D.summary,v=document.getElementById('verdict');
if(!S.total){v.textContent='Nothing was scanned.';}
else if(S.needAction===0&&!S.counts.error){v.className+=' good';v.innerHTML='All '+S.total+' targets are patched against PHP2Shell.<small>Keep watching vendor advisories for follow-up releases.</small>';}
else if(S.needAction===0){v.innerHTML='No exposed targets found, but '+S.counts.error+' could not be checked.<small>Re-run with access to those targets.</small>';}
else{v.className+=' bad';v.innerHTML=S.needAction+' of '+S.total+' targets need action.<small>Patching is the only complete fix. Mitigations below only reduce exposure.</small>';}
var cards=document.getElementById('cards');
cards.appendChild(el('div',{'class':'card'},'<div class="n">'+S.total+'</div><div class="l">Targets</div>'));
ORDER.forEach(function(s){cards.appendChild(el('div',{'class':'card s'+(S.counts[s]?'':' zero'),style:'--c:'+cv(s)},'<div class="n">'+S.counts[s]+'</div><div class="l">'+LABEL[s]+'</div>'));});
var acc=0,stops=[];ORDER.forEach(function(s){var n=S.counts[s];if(!n)return;var a=acc/S.total*360;acc+=n;stops.push(cv(s)+' '+a+'deg '+(acc/S.total*360)+'deg');});
document.getElementById('donut').style.background=stops.length?'conic-gradient('+stops.join(',')+')':'var(--chip)';
document.getElementById('donut-n').textContent=S.total;
var lg=document.getElementById('legend');ORDER.forEach(function(s){if(S.counts[s])lg.appendChild(el('div',{},'<span class="dot" style="--c:'+cv(s)+'"></span>'+LABEL[s]+' <b>'+S.counts[s]+'</b>'));});
var active='all',q='';
var tb=document.getElementById('toolbar'),search=document.getElementById('q');
['all'].concat(ORDER).forEach(function(s){if(s!=='all'&&!S.counts[s])return;var b=el('button',{'class':'chip',type:'button','aria-pressed':String(s==='all')},s==='all'?'All':LABEL[s]+' '+S.counts[s]);b.onclick=function(){active=s;[].forEach.call(tb.querySelectorAll('.chip'),function(x){x.setAttribute('aria-pressed','false');});b.setAttribute('aria-pressed','true');draw();};tb.insertBefore(b,search);});
search.oninput=function(){q=search.value.toLowerCase();draw();};
function mit(r){if(!r.mitigations.length)return '';return '<div class="muted" style="margin-top:8px">Interim mitigations</div><ul>'+r.mitigations.map(function(m){var i=m.applied===null?'<span class="muted">?</span>':m.applied?'<span class="ok">✔</span>':'<span class="bad">✖</span>';var now=m.applied===null?'not checked':'now '+(m.current==null?'unset':m.current);return '<li>'+i+' <code>'+esc(m.key+'='+m.want)+'</code> <span class="muted">'+esc(now)+'</span></li>';}).join('')+'</ul>';}
function draw(){
  var rows=document.getElementById('rows');rows.innerHTML='';
  var list=D.results.filter(function(r){return(active==='all'||r.status===active)&&(!q||(r.target+' '+(r.version||'')+' '+(r.image||'')).toLowerCase().indexOf(q)>=0);});
  if(!list.length){rows.appendChild(el('tr',{},'<td colspan="6" class="empty">No targets match.</td>'));return;}
  list.forEach(function(r){
    var tr=el('tr',{'class':'row',tabindex:'0'},'<td><span class="pill" style="--c:'+cv(r.status)+'">'+LABEL[r.status]+'</span></td><td class="tgt mono">'+esc(r.target)+'</td><td class="mono">'+esc(r.version||'-')+'</td><td class="muted">'+esc(r.sapi||'-')+'</td><td class="muted">'+esc(r.source)+'</td><td>'+esc(r.detail)+'</td>');
    var det=el('tr',{'class':'detail',style:'display:none'},'<td></td><td colspan="5">'+(r.image?'<div><span class="muted">Image</span> <code>'+esc(r.image)+'</code></div>':'')+(r.fix?'<div><span class="muted">Fix</span> '+esc(r.fix)+'</div>':'')+(r.note?'<div class="muted">'+esc(r.note)+'</div>':'')+mit(r)+(r.status==='patched'?'<div class="ok">No action needed.</div>':'')+'</td>');
    var toggle=function(){det.style.display=det.style.display==='none'?'table-row':'none';};
    tr.onclick=toggle;tr.onkeydown=function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}};
    rows.appendChild(tr);rows.appendChild(det);
  });
}
draw();
})();
</script>
</body>
</html>
`;
}
