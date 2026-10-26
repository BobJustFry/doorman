const $ = (s) => document.querySelector(s);
const form = $('#form');
let routes = [];
let editingId = null;

async function api(method, url, body) {
  const r = await fetch(url, {
    method,
    headers: {'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { location.href = '/login'; throw new Error('auth'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const d = data.detail;
    throw new Error(typeof d === 'string' ? d : (d && d[0] && d[0].msg) || 'Request failed');
  }
  return data;
}

function banner(msg) {
  const b = $('#banner');
  b.hidden = !msg;
  b.textContent = msg || '';
}

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}

function btn(label, cls, fn) {
  const b = el('button', label, cls);
  b.onclick = fn;
  return b;
}

/* ---------- tabs ---------- */
document.querySelectorAll('#tabs button').forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll('#tabs button').forEach((x) => x.classList.toggle('active', x === b));
    for (const s of ['routes', 'stats', 'system']) $('#tab-' + s).hidden = s !== b.dataset.tab;
    if (b.dataset.tab === 'system') loadSystem();
    if (b.dataset.tab === 'stats') loadStats();
  };
});

/* ---------- routes ---------- */
function renderRows() {
  const q = $('#search').value.trim().toLowerCase();
  const list = routes.filter((r) => !q || (r.domain + ' ' + r.upstream + ' ' + r.note).toLowerCase().includes(q));
  const tbody = $('#rows');
  tbody.replaceChildren();
  $('#empty').hidden = list.length > 0;
  $('#empty').textContent = routes.length ? 'Nothing found.' : 'No routes yet.';
  for (const r of list) {
    const tr = el('tr');
    if (!r.enabled) tr.className = 'off';
    const dotTd = el('td');
    const dot = el('span', undefined, 'dot');
    dot.dataset.id = r.id;
    dotTd.append(dot);
    const domainTd = el('td', r.domain);
    const extra = (r.ports || []).map((p) => ':' + p.port).join('  ');
    if (extra) domainTd.append(el('div', 'ports ' + extra, 'muted'));
    if (r.note) domainTd.append(el('div', r.note, 'muted'));
    const act = el('td', undefined, 'actions');
    act.append(
      btn(r.enabled ? 'Off' : 'On', 'ghost icon', () => save(r.id, {...r, enabled: !r.enabled})),
      ' ',
      btn('Edit', 'ghost icon', () => openDialog(r)),
      ' ',
      btn('✕', 'danger icon', () => remove(r)),
    );
    tr.append(dotTd, domainTd, el('td', (r.upstream_tls ? 'https://' : '') + r.upstream), act);
    tbody.append(tr);
  }
  refreshStatus();
}

async function load() {
  routes = await api('GET', '/api/routes');
  renderRows();
}

async function refreshStatus() {
  try {
    const st = await api('GET', '/api/status');
    document.querySelectorAll('.dot').forEach((d) => {
      const v = st[d.dataset.id];
      d.className = 'dot' + (v === true ? ' up' : v === false ? ' down' : '');
      d.title = v === true ? 'Upstream reachable' : v === false ? 'Upstream unreachable' : 'Disabled';
    });
  } catch (_) { /* ignore */ }
}

function reportApply(res) {
  banner(res.applied ? '' : 'Saved, but config was not applied: ' + res.error);
}

async function save(id, data) {
  const body = {
    domain: data.domain, upstream: data.upstream, upstream_tls: !!data.upstream_tls,
    tls_mode: data.tls_mode, enabled: !!data.enabled, note: data.note || '',
    ports: data.ports || [],
  };
  const res = id ? await api('PUT', '/api/routes/' + id, body) : await api('POST', '/api/routes', body);
  reportApply(res);
  await load();
  loadStats();
}

async function remove(r) {
  if (!confirm('Delete ' + r.domain + '?')) return;
  try { reportApply(await api('DELETE', '/api/routes/' + r.id)); await load(); }
  catch (e) { banner(e.message); }
}

/* ---------- route dialog ---------- */
const dlg = $('#route-dlg');

function openDialog(r, prefillDomain) {
  editingId = r ? r.id : null;
  form.reset();
  $('#dlg-err').textContent = '';
  $('#dlg-title').textContent = r ? 'Edit route' : 'Add route';
  form.dataset.enabled = !r || r.enabled ? '1' : '';
  if (r) {
    form.domain.value = r.domain;
    form.upstream.value = r.upstream;
    form.tls_mode.value = r.tls_mode;
    form.note.value = r.note;
    form.upstream_tls.checked = !!r.upstream_tls;
  }
  $('#ports-list').replaceChildren();
  for (const p of (r && r.ports) || []) addPortRow(p.port, p.tls);
  $('#more').open = !!r && (r.tls_mode !== 'auto' || r.upstream_tls || r.note || (r.ports || []).length > 0);
  if (prefillDomain) form.domain.value = prefillDomain;
  dlg.showModal();
  (prefillDomain ? form.upstream : form.domain).focus();
}

function addPortRow(port, tls) {
  const row = el('div', undefined, 'port-row');
  const num = el('input');
  num.type = 'number';
  num.min = 1;
  num.max = 65535;
  num.placeholder = '8444';
  num.value = port || '';
  const chk = el('input');
  chk.type = 'checkbox';
  chk.checked = !!tls;
  const lbl = el('label', undefined, 'check');
  lbl.append(chk, document.createTextNode(' HTTPS upstream'));
  row.append(num, lbl, btn('✕', 'danger icon', () => row.remove()));
  row.dataset.row = '1';
  $('#ports-list').append(row);
  if (!port) num.focus();
}

function readPorts() {
  return [...document.querySelectorAll('#ports-list [data-row]')]
    .map((r) => ({port: parseInt(r.querySelector('input[type=number]').value, 10),
      tls: r.querySelector('input[type=checkbox]').checked}))
    .filter((p) => Number.isInteger(p.port));
}

$('#add-port').onclick = () => addPortRow('', false);

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await save(editingId, {
      domain: form.domain.value, upstream: form.upstream.value, tls_mode: form.tls_mode.value,
      note: form.note.value, upstream_tls: form.upstream_tls.checked, enabled: !!form.dataset.enabled,
      ports: readPorts(),
    });
    dlg.close();
  } catch (err) { $('#dlg-err').textContent = err.message; }
});

$('#add').onclick = () => openDialog(null);
$('#cancel').onclick = () => dlg.close();
$('#search').addEventListener('input', renderRows);

/* ---------- stats dashboard ---------- */
let statsRange = '24h';
const NS = 'http://www.w3.org/2000/svg';
const COLORS = {ok: 'var(--accent)', r3: '#8aa7f8', c4: '#e0a100', c5: 'var(--bad)'};

function svgEl(tag, attrs, text) {
  const e = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (text !== undefined) e.textContent = text;
  return e;
}

const fmtNum = (n) => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'k' : n.toLocaleString();
const fmtPct = (x) => (x * 100 < 10 && x > 0 ? (x * 100).toFixed(1) : Math.round(x * 100)) + '%';

function fmtBytes(b) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(b < 10 ? 1 : 0) : b) + ' ' + u[i];
}

function fmtTime(ts, range) {
  const d = new Date(ts * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return range === '7d' || range === '30d' ? p(d.getDate()) + '.' + p(d.getMonth() + 1) : p(d.getHours()) + ':' + p(d.getMinutes());
}

function kpi(label, value, sub, cls) {
  const d = el('div', undefined, 'kpi');
  d.append(el('div', label, 'kpi-label'), el('div', value, 'kpi-value' + (cls ? ' ' + cls : '')), el('div', sub, 'kpi-sub'));
  return d;
}

function spark(series) {
  const w = 4, gap = 1, h = 24, max = Math.max(1, ...series);
  const svg = svgEl('svg', {width: series.length * (w + gap), height: h});
  series.forEach((v, i) => {
    const bh = v ? Math.max(2, Math.round((v / max) * h)) : 1;
    svg.append(svgEl('rect', {x: i * (w + gap), y: h - bh, width: w, height: bh, rx: 1, fill: v ? COLORS.ok : 'var(--line)'}));
  });
  return svg;
}

function drawTimeline(d) {
  const W = 640, H = 190, L = 40, B = 22, T = 8;
  const svg = svgEl('svg', {viewBox: `0 0 ${W} ${H}`, class: 'chart', preserveAspectRatio: 'none'});
  const tl = d.timeline;
  const max = Math.max(1, ...tl.map((b) => b.ok + b.c4 + b.c5));
  const nice = (m) => { const p = 10 ** Math.floor(Math.log10(m)); return Math.ceil(m / p) * p; };
  const top = nice(max);
  const ph = H - B - T, pw = W - L;
  [0, 0.5, 1].forEach((f) => {
    const y = T + ph - f * ph;
    svg.append(svgEl('line', {x1: L, x2: W, y1: y, y2: y, stroke: 'var(--line)'}));
    svg.append(svgEl('text', {x: L - 6, y: y + 4, 'text-anchor': 'end', class: 'ax'}, fmtNum(Math.round(top * f))));
  });
  const bw = pw / tl.length;
  tl.forEach((b, i) => {
    const g = svgEl('g');
    let y = T + ph;
    for (const [k, c] of [['ok', COLORS.ok], ['c4', COLORS.c4], ['c5', COLORS.c5]]) {
      const hh = (b[k] / top) * ph;
      if (hh <= 0) continue;
      y -= hh;
      g.append(svgEl('rect', {x: L + i * bw + 1, y, width: Math.max(1, bw - 2), height: hh, fill: c, rx: 1}));
    }
    const hit = svgEl('rect', {x: L + i * bw, y: T, width: bw, height: ph, fill: 'transparent'});
    hit.append(svgEl('title', {}, fmtTime(b.t, d.range) + ': ' + (b.ok + b.c4 + b.c5) + ' requests (4xx: ' + b.c4 + ', 5xx: ' + b.c5 + ')'));
    g.append(hit);
    svg.append(g);
  });
  [0, Math.floor((tl.length - 1) / 2), tl.length - 1].forEach((i, n) => {
    svg.append(svgEl('text', {x: L + i * bw + bw / 2, y: H - 5, 'text-anchor': n === 0 ? 'start' : n === 2 ? 'end' : 'middle', class: 'ax'}, fmtTime(tl[i].t, d.range)));
  });
  $('#timeline').replaceChildren(svg);
}

function drawTop(d) {
  const box = $('#top');
  box.replaceChildren();
  const list = d.hosts.filter((h) => h.requests > 0).slice(0, 8);
  if (!list.length) { box.append(el('p', 'No traffic in this period yet.', 'muted')); return; }
  const max = list[0].requests;
  for (const h of list) {
    const row = el('div', undefined, 'hbar');
    const bar = el('div', undefined, 'hbar-fill');
    bar.style.width = Math.max(2, (h.requests / max) * 100) + '%';
    const label = el('div', undefined, 'hbar-label');
    label.append(el('span', h.host), el('b', fmtNum(h.requests) + ' · ' + fmtPct(h.share)));
    const track = el('div', undefined, 'hbar-track');
    track.append(bar);
    row.append(label, track);
    box.append(row);
  }
}

function drawResponses(d) {
  const t = d.totals, box = $('#resp');
  box.replaceChildren();
  if (!t.requests) { box.append(el('p', 'No traffic in this period yet.', 'muted')); return; }
  const parts = [['2xx success', t.s2, COLORS.ok], ['3xx redirects', t.s3, COLORS.r3],
    ['4xx client errors', t.s4, COLORS.c4], ['5xx server errors', t.s5, COLORS.c5]];
  const stack = el('div', undefined, 'stack');
  for (const [, n, c] of parts) {
    if (!n) continue;
    const s = el('span');
    s.style.width = (n / t.requests) * 100 + '%';
    s.style.background = c;
    stack.append(s);
  }
  box.append(stack);
  for (const [name, n, c] of parts) {
    const r = el('div', undefined, 'legend-row');
    const sw = el('i');
    sw.style.background = c;
    r.append(sw, el('span', name), el('b', n.toLocaleString() + ' · ' + fmtPct(n / t.requests)));
    box.append(r);
  }
}

async function loadStats() {
  if ($('#tab-stats').hidden) return;
  try {
    const d = await api('GET', '/api/stats?range=' + statsRange);
    const t = d.totals;
    $('#kpis').replaceChildren(
      kpi('Requests', fmtNum(t.requests), t.last5 + ' in the last 5 min'),
      kpi('Traffic', fmtBytes(t.bytes), 'sent to clients'),
      kpi('Error rate', t.requests ? fmtPct(t.error_rate) : '–', (t.s4 + t.s5) + ' failed requests',
        t.error_rate > 0.05 ? 'bad' : ''),
      kpi('Active now', t.active_domains + ' / ' + t.domains, 'domains with requests in 5 min'),
    );
    drawTimeline(d);
    drawTop(d);
    drawResponses(d);

    const tbody = $('#stats-rows');
    tbody.replaceChildren();
    $('#stats-empty').hidden = d.hosts.length > 0;
    for (const h of d.hosts) {
      const tr = el('tr');
      const dotTd = el('td');
      const dot = el('span', undefined, 'dot' + (h.active ? ' up' : ''));
      dot.title = h.active ? 'Receiving requests' : 'No requests in the last 5 minutes';
      dotTd.append(dot);
      const domainTd = el('td', h.host);
      if (!h.enabled) domainTd.append(el('div', 'disabled', 'muted'));
      const errTd = el('td', h.errors ? h.errors.toLocaleString() : '–');
      if (h.errors) errTd.style.color = 'var(--bad)';
      const trend = el('td');
      trend.append(spark(h.series));
      tr.append(dotTd, domainTd, el('td', h.requests.toLocaleString()),
        el('td', h.requests ? fmtPct(h.share) : '–'), errTd, el('td', fmtBytes(h.bytes)), trend);
      tbody.append(tr);
    }

    const ub = $('#unknown-rows');
    ub.replaceChildren();
    $('#unknown-empty').hidden = d.unknown.length > 0;
    for (const u of d.unknown) {
      const act = el('td', undefined, 'actions');
      act.append(
        btn('Create route', 'icon', () => openDialog(null, u.host)),
        ' ',
        btn('Dismiss', 'ghost icon', async () => {
          await api('POST', '/api/unknown/dismiss', {host: u.host});
          loadStats();
        }),
      );
      const tr = el('tr');
      tr.append(el('td', u.host), el('td', u.requests ? u.requests.toLocaleString() : '–'),
        el('td', u.attempts ? u.attempts.toLocaleString() : '–'), act);
      ub.append(tr);
    }
  } catch (e) { banner(e.message); }
}

document.querySelectorAll('#range button').forEach((b) => {
  b.onclick = () => {
    statsRange = b.dataset.range;
    document.querySelectorAll('#range button').forEach((x) => x.classList.toggle('active', x === b));
    loadStats();
  };
});

/* ---------- system ---------- */
async function loadSystem() {
  try {
    const s = await api('GET', '/api/system');
    $('#sys-caddy').textContent = s.caddy_ok ? 'running' : 'unreachable';
    $('#sys-routes').textContent = s.routes_enabled + ' active / ' + s.routes_total + ' total';
    $('#sys-admin').textContent = s.admin_domain || 'not set (localhost only)';
    $('#sys-acme').textContent = s.acme_email || 'not set';
  } catch (e) { banner(e.message); }
}

$('#reapply').onclick = async () => {
  try { reportApply(await api('POST', '/api/apply')); loadSystem(); } catch (e) { banner(e.message); }
};
$('#show-config').onclick = async () => {
  $('#config-pre').textContent = JSON.stringify(await api('GET', '/api/config'), null, 2);
  $('#config-dlg').showModal();
};
$('#config-close').onclick = () => $('#config-dlg').close();
$('#logout').onclick = async () => { await api('POST', '/logout'); location.href = '/login'; };

load();
loadStats();
setInterval(refreshStatus, 15000);
setInterval(loadStats, 10000);
