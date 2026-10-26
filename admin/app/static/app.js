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
  };
  const res = id ? await api('PUT', '/api/routes/' + id, body) : await api('POST', '/api/routes', body);
  reportApply(res);
  await load();
}

async function remove(r) {
  if (!confirm('Delete ' + r.domain + '?')) return;
  try { reportApply(await api('DELETE', '/api/routes/' + r.id)); await load(); }
  catch (e) { banner(e.message); }
}

/* ---------- route dialog ---------- */
const dlg = $('#route-dlg');

function openDialog(r) {
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
  $('#more').open = !!r && (r.tls_mode !== 'auto' || r.upstream_tls || r.note);
  dlg.showModal();
  form.domain.focus();
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await save(editingId, {
      domain: form.domain.value, upstream: form.upstream.value, tls_mode: form.tls_mode.value,
      note: form.note.value, upstream_tls: form.upstream_tls.checked, enabled: !!form.dataset.enabled,
    });
    dlg.close();
  } catch (err) { $('#dlg-err').textContent = err.message; }
});

$('#add').onclick = () => openDialog(null);
$('#cancel').onclick = () => dlg.close();
$('#search').addEventListener('input', renderRows);

/* ---------- stats ---------- */
let statsRange = '24h';

function ago(ts, now) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.round(now - ts));
  if (s < 60) return s + ' s ago';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
}

function spark(series) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  const w = 4, gap = 1, h = 24, max = Math.max(1, ...series);
  svg.setAttribute('width', series.length * (w + gap));
  svg.setAttribute('height', h);
  series.forEach((v, i) => {
    const bar = document.createElementNS(NS, 'rect');
    const bh = v ? Math.max(2, Math.round((v / max) * h)) : 1;
    bar.setAttribute('x', i * (w + gap));
    bar.setAttribute('y', h - bh);
    bar.setAttribute('width', w);
    bar.setAttribute('height', bh);
    bar.setAttribute('rx', 1);
    bar.setAttribute('fill', v ? 'var(--accent)' : 'var(--line)');
    svg.append(bar);
  });
  return svg;
}

async function loadStats() {
  if ($('#tab-stats').hidden) return;
  try {
    const d = await api('GET', '/api/stats?range=' + statsRange);
    const tbody = $('#stats-rows');
    tbody.replaceChildren();
    $('#stats-empty').hidden = d.hosts.length > 0;
    for (const h of d.hosts) {
      const tr = el('tr');
      tr.style.cursor = 'pointer';
      tr.onclick = () => showRecent(h.host);
      const dotTd = el('td');
      const dot = el('span', undefined, 'dot' + (h.active_5m ? ' up' : ''));
      dot.title = h.active_5m ? h.active_5m + ' requests in the last 5 minutes' : 'No requests in the last 5 minutes';
      dotTd.append(dot);
      const domainTd = el('td', h.host);
      if (!h.routed) domainTd.append(el('div', 'no route configured', 'muted'));
      else if (!h.enabled) domainTd.append(el('div', 'disabled', 'muted'));
      const errs = h.client_errors + h.server_errors;
      const errTd = el('td', errs ? String(errs) : '–');
      if (h.server_errors) errTd.style.color = 'var(--bad)';
      errTd.title = '4xx: ' + h.client_errors + ', 5xx: ' + h.server_errors;
      const trend = el('td');
      trend.append(spark(h.series));
      tr.append(dotTd, domainTd, el('td', h.requests.toLocaleString()), errTd,
        el('td', ago(h.last_seen, d.now)), trend);
      tbody.append(tr);
    }
  } catch (e) { banner(e.message); }
}

async function showRecent(host) {
  $('#recent-title').textContent = host;
  const list = await api('GET', '/api/stats/recent?host=' + encodeURIComponent(host));
  const tbody = $('#recent-rows');
  tbody.replaceChildren();
  $('#recent-empty').hidden = list.length > 0;
  for (const r of list) {
    const st = el('td', String(r.status));
    if (r.status >= 500) st.style.color = 'var(--bad)';
    else if (r.status >= 400) st.style.color = '#c98a00';
    const tr = el('tr');
    tr.append(el('td', new Date(r.ts * 1000).toLocaleTimeString()), el('td', r.ip),
      el('td', r.method + ' ' + r.uri), st);
    tbody.append(tr);
  }
  $('#recent-dlg').showModal();
}

document.querySelectorAll('#range button').forEach((b) => {
  b.onclick = () => {
    statsRange = b.dataset.range;
    document.querySelectorAll('#range button').forEach((x) => x.classList.toggle('active', x === b));
    loadStats();
  };
});
$('#recent-close').onclick = () => $('#recent-dlg').close();

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
setInterval(refreshStatus, 15000);
setInterval(loadStats, 10000);
