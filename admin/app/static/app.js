const $ = (s) => document.querySelector(s);
const form = $('#form');
let routes = [];
let routesLoaded = false;
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

let bannedIps = new Set();
let lastNotice = {msg: '', at: 0};

/* Messages are dialogs, never inline banners or the browser's alert(). The same message
   coming back from a background refresh is not shown again for half a minute. */
function showNotice(message, title, force) {
  const now = Date.now();
  if (!force && message === lastNotice.msg && now - lastNotice.at < 30000) return;
  lastNotice = {msg: message, at: now};
  const dlg = $('#notice-dlg');
  const box = $('#notice-text');
  if (dlg.open) {
    box.textContent += '\n' + message;
    return;
  }
  $('#notice-title').textContent = title || 'Something went wrong';
  box.textContent = message;
  dlg.showModal();
}

function banner(msg) { if (msg) showNotice(msg); }
const notify = (message, title) => showNotice(message, title, true);
$('#notice-ok').onclick = () => $('#notice-dlg').close();

/* Resolves true after "Confirm", false after "Cancel" or Esc. */
function askConfirm({title, text, yes = 'Confirm', danger = false}) {
  return new Promise((resolve) => {
    const dlg = $('#confirm-dlg');
    $('#confirm-title').textContent = title;
    $('#confirm-text').textContent = text;
    const ok = $('#confirm-yes');
    ok.textContent = yes;
    ok.className = danger ? 'danger-solid' : '';
    let answer = false;
    dlg.addEventListener('close', () => resolve(answer), {once: true});
    ok.onclick = () => { answer = true; dlg.close(); };
    $('#confirm-no').onclick = () => dlg.close();
    dlg.showModal();
  });
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

/* Re-render a block only when its data really changed, so periodic refreshes
   never rebuild (or flicker) parts of the page that look the same. */
const rendered = {};
function renderIf(key, data, fn) {
  const sig = JSON.stringify(data);
  if (rendered[key] === sig) return;
  rendered[key] = sig;
  fn();
}

const activeTab = () => document.querySelector('#tabs button.active').dataset.tab;
const visible = (tab) => !document.hidden && activeTab() === tab;

/* ---------- tabs (data of each tab is loaded lazily, when it is first opened) ---------- */
document.querySelectorAll('#tabs button').forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll('#tabs button').forEach((x) => x.classList.toggle('active', x === b));
    for (const s of ['routes', 'stats', 'system']) $('#tab-' + s).hidden = s !== b.dataset.tab;
    if (b.dataset.tab === 'system') loadSystem();
    if (b.dataset.tab === 'stats') loadStats();
    if (b.dataset.tab === 'routes') loadRoutes();
  };
});

/* ---------- routes ---------- */
function routeRow(r) {
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
  return tr;
}

function renderRows() {
  const q = $('#search').value.trim().toLowerCase();
  const list = routes.filter((r) => !q || (r.domain + ' ' + r.upstream + ' ' + r.note).toLowerCase().includes(q));
  $('#empty').hidden = list.length > 0;
  $('#empty').textContent = routes.length ? 'Nothing found.' : 'No routes yet.';
  $('#rows').replaceChildren(...list.map(routeRow));
  refreshStatus();
}

async function loadRoutes() {
  try {
    const fresh = await api('GET', '/api/routes');
    if (routesLoaded && JSON.stringify(fresh) === JSON.stringify(routes)) return;
    routes = fresh;
    routesLoaded = true;
    renderRows();
  } catch (e) { banner(e.message); }
}

async function refreshStatus() {
  if (!visible('routes')) return;
  try {
    const st = await api('GET', '/api/status');
    document.querySelectorAll('#rows .dot').forEach((d) => {
      const v = st[d.dataset.id];
      const cls = 'dot' + (v === true ? ' up' : v === false ? ' down' : '');
      if (d.className !== cls) {
        d.className = cls;
        d.title = v === true ? 'Upstream reachable' : v === false ? 'Upstream unreachable' : 'Disabled';
      }
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
  routesLoaded = false;
  if (activeTab() === 'routes') await loadRoutes();
  loadStats();
}

async function remove(r) {
  const yes = await askConfirm({
    title: 'Delete ' + r.domain + '?',
    text: 'The route is removed and the domain starts showing the “nobody’s home” page.\nThe service itself is not touched.',
    yes: 'Delete', danger: true,
  });
  if (!yes) return;
  try {
    reportApply(await api('DELETE', '/api/routes/' + r.id));
    routesLoaded = false;
    await loadRoutes();
  } catch (e) { banner(e.message); }
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

/* ---------- dashboard ---------- */
let statsRange = '24h';
let clientsFilter = '';
let lastClients = [];
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
  // requests the browser cancelled itself (499) are counted as requests but are not errors
  const cancelled = t.requests - (t.s2 + t.s3 + t.s4 + t.s5);
  if (cancelled > 0) parts.push(['cancelled by the browser', cancelled, 'var(--muted)']);
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

function hostRow(h) {
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
  return tr;
}

function unknownRow(u) {
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
  const verdictTd = el('td');
  verdictTd.append(verdictBadge(u.verdict));
  const whoTd = el('td');
  for (const s of u.sources || []) {
    const chip = el('button', s.ip + ' · ' + s.requests.toLocaleString(), 'chip link-chip ' + (s.lan ? 'lan' : 'wan'));
    chip.title = (s.lan ? 'Local network' : 'Internet') + (s.probes ? ', asked for scanner-only paths' : '') + ': click for details';
    chip.onclick = () => openIp(s.ip);
    whoTd.append(chip);
  }
  if (u.source_count > (u.sources || []).length) whoTd.append(el('span', '+' + (u.source_count - u.sources.length), 'chip'));
  if (!(u.sources || []).length) whoTd.append(el('span', 'no address seen', 'muted'));
  tr.append(el('td', u.host), verdictTd, whoTd, el('td', u.requests ? u.requests.toLocaleString() : '–'),
    el('td', u.attempts ? u.attempts.toLocaleString() : '–'), act);
  return tr;
}

const VERDICTS = {
  scanner: ['Scanner', 'bad', 'Asked for paths only scanners request (/.env, /.git, ...)'],
  suspicious: ['Suspicious', 'warn', 'Several internet addresses or many requests for a name that does not exist'],
  internal: ['Internal', 'ok', 'Only your local network asks for it: probably a forgotten route'],
  unknown: ['Unknown', '', 'Not enough information'],
};

function verdictBadge(v) {
  const [label, cls, hint] = VERDICTS[v] || VERDICTS.unknown;
  const b = el('span', label, 'badge ' + cls);
  b.title = hint;
  return b;
}

/* Clients: "who knocked", per IP, for routed and unrouted domains alike. */
function drawClients() {
  const hosts = [...new Set(lastClients.map((c) => c.host))].sort();
  const sel = $('#clients-filter');
  renderIf('clients-hosts', hosts, () => {
    sel.replaceChildren(new Option('All domains', ''), ...hosts.map((h) => new Option(h, h)));
  });
  if (clientsFilter && !hosts.includes(clientsFilter)) clientsFilter = '';
  sel.value = clientsFilter;

  const byIp = new Map();
  for (const c of lastClients) {
    if (clientsFilter && c.host !== clientsFilter) continue;
    const e = byIp.get(c.ip) || {ip: c.ip, lan: c.lan, requests: 0, errors: 0, probes: 0, stubs: 0, domains: []};
    e.requests += c.requests;
    e.errors += c.errors;
    e.probes += c.probes || 0;
    e.stubs += c.stubs || 0;
    e.domains.push(c);
    byIp.set(c.ip, e);
  }
  const rows = [...byIp.values()].sort((a, b) => b.requests - a.requests).slice(0, 30);
  $('#clients-empty').hidden = rows.length > 0;
  $('#clients-rows').replaceChildren(...rows.map((c) => {
    const tr = el('tr');
    const net = el('span', c.lan ? 'LAN' : 'Internet', 'badge ' + (c.lan ? 'lan' : 'wan'));
    const netTd = el('td');
    netTd.append(net);
    const domTd = el('td');
    for (const d of c.domains.sort((a, b) => b.requests - a.requests).slice(0, 4)) {
      const chip = el('span', d.host + ' · ' + d.requests.toLocaleString(), 'chip' + (d.routed ? '' : ' unrouted'));
      if (!d.routed) chip.title = 'No route for this domain';
      domTd.append(chip);
    }
    if (c.domains.length > 4) domTd.append(el('span', '+' + (c.domains.length - 4), 'chip'));
    const errTd = el('td', c.errors ? c.errors.toLocaleString() : '–');
    if (c.errors) errTd.style.color = 'var(--bad)';
    const flagTd = el('td');
    if (c.probes) {
      const b = el('span', 'Scanner', 'badge bad');
      b.title = c.probes + ' request(s) for scanner-only paths';
      flagTd.append(b);
    } else if (c.stubs >= 10 && !c.lan) {
      const b = el('span', 'Suspicious', 'badge warn');
      b.title = c.stubs + ' requests for names that do not exist';
      flagTd.append(b);
    }
    if (bannedIps.has(c.ip)) {
      const b = el('span', 'Blocked', 'badge dark');
      b.title = 'Blocked by fail2ban on the server';
      flagTd.append(b);
    }
    const ipTd = el('td');
    const ipBtn = el('button', c.ip, 'link');
    ipBtn.title = 'Why is it listed? Click for the conclusion';
    ipBtn.onclick = () => openIp(c.ip);
    ipTd.append(ipBtn);
    tr.append(ipTd, netTd, domTd, el('td', c.requests.toLocaleString()), errTd, flagTd);
    return tr;
  }));
}

async function loadStats() {
  if (!visible('stats')) return;
  try {
    const d = await api('GET', '/api/stats?range=' + statsRange);
    const t = d.totals;
    await refreshBans();
    renderIf('kpis', t, () => $('#kpis').replaceChildren(
      kpi('Requests', fmtNum(t.requests), t.last5 + ' in the last 5 min'),
      kpi('Traffic', fmtBytes(t.bytes), 'sent to clients'),
      kpi('Error rate', t.requests ? fmtPct(t.error_rate) : '–', (t.s4 + t.s5) + ' failed requests',
        t.error_rate > 0.05 ? 'bad' : ''),
      kpi('Active now', t.active_domains + ' / ' + t.domains, 'domains with requests in 5 min'),
    ));
    renderIf('timeline', [d.range, d.timeline.map((b) => [b.ok, b.c4, b.c5])], () => drawTimeline(d));
    renderIf('top', d.hosts.map((h) => [h.host, h.requests]), () => drawTop(d));
    renderIf('resp', t, () => drawResponses(d));
    renderIf('hosts', d.hosts, () => {
      $('#stats-empty').hidden = d.hosts.length > 0;
      $('#stats-rows').replaceChildren(...d.hosts.map(hostRow));
    });
    renderIf('unknown', d.unknown, () => {
      $('#unknown-empty').hidden = d.unknown.length > 0;
      $('#unknown-rows').replaceChildren(...d.unknown.map(unknownRow));
    });
    renderIf('clients', [d.clients, [...bannedIps]], () => { lastClients = d.clients; drawClients(); });
  } catch (e) { banner(e.message); }
}

document.querySelectorAll('#range button').forEach((b) => {
  b.onclick = () => {
    statsRange = b.dataset.range;
    document.querySelectorAll('#range button').forEach((x) => x.classList.toggle('active', x === b));
    loadStats();
  };
});

$('#clients-filter').onchange = (e) => { clientsFilter = e.target.value; drawClients(); };

/* ---------- system ---------- */
async function loadSystem() {
  try {
    const s = await api('GET', '/api/system');
    $('#sys-caddy').textContent = s.caddy_ok ? 'running' : 'unreachable';
    $('#sys-routes').textContent = s.routes_enabled + ' active / ' + s.routes_total + ' total';
    $('#sys-admin').textContent = s.admin_domain || 'not set (localhost only)';
    $('#sys-acme').textContent = s.acme_email || 'not set';
    loadBans();
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

/* ---------- blocked addresses (fail2ban) ---------- */
async function refreshBans() {
  try {
    const d = await api('GET', '/api/bans');
    bannedIps = new Set([...Object.values(d.jails).flat(), ...d.manual.filter((m) => m.state !== 'none').map((m) => m.ip)]);
    return d;
  } catch (_) { return null; }
}

async function loadBans() {
  const d = await refreshBans();
  if (!d) return;
  $('#bans-helper').textContent = d.helper_alive ? 'host helper: active' : 'host helper: not installed (see README)';
  const rows = new Map();
  for (const [jail, ips] of Object.entries(d.jails)) for (const ip of ips) (rows.get(ip) || rows.set(ip, []).get(ip)).push(jail);
  for (const m of d.manual) if (!rows.has(m.ip)) rows.set(m.ip, ['waiting for the helper']);
  $('#bans-empty').hidden = rows.size > 0;
  $('#bans-rows').replaceChildren(...[...rows].map(([ip, jails]) => {
    const tr = el('tr');
    const ipTd = el('td');
    const open = el('button', ip, 'link');
    open.onclick = () => openIp(ip);
    ipTd.append(open);
    const act = el('td', undefined, 'actions');
    act.append(btn('Unblock…', 'ghost icon', () => unblock(ip)));
    tr.append(ipTd, el('td', jails.join(', ')), act);
    return tr;
  }));
}

async function unblock(ip) {
  const yes = await askConfirm({
    title: 'Unblock ' + ip + '?',
    text: 'The address will be able to reach your services again. If it keeps misbehaving it will be blocked again automatically.',
    yes: 'Unblock',
  });
  if (!yes) return;
  try {
    await api('DELETE', '/api/bans?ip=' + encodeURIComponent(ip));
    notify('The request was sent. The host helper removes the block within a few seconds.', 'Unblocking ' + ip);
    setTimeout(() => { loadBans(); loadStats(); }, 4000);
  } catch (e) { banner(e.message); }
}

/* ---------- the conclusion about one address ---------- */
const ipDlg = $('#ip-dlg');
let ipCurrent = null;

const LEVELS = {
  scanner: ['Scanner', 'bad'], suspicious: ['Suspicious', 'warn'], clean: ['No suspicious activity', 'ok'],
};

async function openIp(ip) {
  try {
    renderIp(await api('GET', '/api/ip?ip=' + encodeURIComponent(ip)));
    if (!ipDlg.open) ipDlg.showModal();
  } catch (e) { banner(e.message); }
}

function renderIp(d) {
  ipCurrent = d;
  $('#ip-title').textContent = d.ip;
  const [label, cls] = LEVELS[d.level] || LEVELS.clean;
  const badges = $('#ip-badges');
  badges.replaceChildren(el('span', d.lan ? 'LAN' : 'Internet', 'badge ' + (d.lan ? 'lan' : 'wan')), ' ', el('span', label, 'badge ' + cls));
  $('#ip-summary').textContent = d.requests.toLocaleString() + ' request(s), ' + d.errors.toLocaleString() + ' error(s) in the last 31 days.';
  $('#ip-reasons').replaceChildren(...d.reasons.map((r) => el('li', r)));
  $('#ip-domains').replaceChildren(...d.domains.map((x) => {
    const tr = el('tr');
    const dom = el('td', x.host);
    if (!x.routed) dom.append(el('div', 'no route here', 'muted'));
    tr.append(dom, el('td', x.requests.toLocaleString()), el('td', x.errors ? x.errors.toLocaleString() : '–'));
    return tr;
  }));
  const b = d.ban;
  let line = '';
  if (b.state === 'banned') line = 'Blocked by fail2ban (' + b.jails.join(', ') + ').';
  else if (b.state === 'queued') {
    line = 'Block requested: the helper on the server applies it within a few seconds.';
    if (!b.helper_alive) line += ' The helper is not answering: install it with “sudo bash deploy/install-fail2ban.sh”.';
  } else if (!d.can_ban) line = 'Addresses of your own network cannot be blocked from here.';
  $('#ip-ban-line').textContent = line;
  $('#ip-ban').hidden = !(d.can_ban && b.state === 'none');
  $('#ip-unban').hidden = b.state === 'none';
}

$('#ip-close').onclick = () => ipDlg.close();

$('#ip-ban').onclick = async () => {
  const d = ipCurrent;
  const why = d.level === 'clean' ? 'Nothing hostile was recorded for it.' : d.reasons.join('\n');
  const yes = await askConfirm({
    title: 'Block ' + d.ip + '?',
    text: 'It will be blocked on every port of the server for 30 days (fail2ban + firewall). It will not reach any of your services or this panel.\n\n' + why,
    yes: 'Block', danger: true,
  });
  if (!yes) return;
  try {
    await api('POST', '/api/bans', {ip: d.ip, note: 'from the dashboard'});
    await openIp(d.ip);
    setTimeout(() => { if (ipDlg.open && ipCurrent && ipCurrent.ip === d.ip) openIp(d.ip); loadStats(); }, 4000);
  } catch (e) { banner(e.message); }
};

$('#ip-unban').onclick = async () => {
  const ip = ipCurrent.ip;
  await unblock(ip);
  if (ipDlg.open) setTimeout(() => { if (ipDlg.open && ipCurrent && ipCurrent.ip === ip) openIp(ip); }, 4500);
};

/* ---------- reset statistics ---------- */
const RESET_TEXT = {
  counters: ['counters', 'All numbers go back to zero: requests, errors, traffic, charts, the Clients table and the evidence behind scanner verdicts.'],
  lists: ['lists', 'The “Unrouted domains” list is emptied and the names you dismissed are forgotten.'],
  all: ['counters and lists', 'All numbers go back to zero, the “Unrouted domains” list is emptied and dismissed names are forgotten.'],
};

$('#reset-open').onclick = () => $('#reset-dlg').showModal();
$('#reset-cancel').onclick = () => $('#reset-dlg').close();
$('#reset-go').onclick = async () => {
  const scope = document.querySelector('#reset-dlg input[name=scope]:checked').value;
  $('#reset-dlg').close();
  const [name, text] = RESET_TEXT[scope];
  const yes = await askConfirm({
    title: 'Reset ' + name + '?',
    text: text + '\n\nRoutes, certificates and blocked addresses are not touched. This cannot be undone.',
    yes: 'Reset', danger: true,
  });
  if (!yes) return;
  try {
    await api('POST', '/api/stats/reset', {scope});
    for (const k of Object.keys(rendered)) delete rendered[k];
    await loadStats();
    notify('Statistics were reset (' + name + ').', 'Done');
  } catch (e) { banner(e.message); }
};

/* Only the dashboard is fetched on page load; other tabs load when opened. */
loadStats();
setInterval(loadStats, 10000);
setInterval(refreshStatus, 15000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) loadStats(); });
