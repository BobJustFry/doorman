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

function cell(text, cls) {
  const td = document.createElement('td');
  td.textContent = text;
  if (cls) td.className = cls;
  return td;
}

function btn(label, cls, fn) {
  const b = document.createElement('button');
  b.textContent = label;
  b.className = cls;
  b.onclick = fn;
  return b;
}

async function render() {
  routes = await api('GET', '/api/routes');
  const tbody = $('#rows');
  tbody.replaceChildren();
  $('#empty').hidden = routes.length > 0;
  for (const r of routes) {
    const tr = document.createElement('tr');
    const dotTd = document.createElement('td');
    const dot = document.createElement('span');
    dot.className = 'dot';
    dot.dataset.id = r.id;
    dotTd.append(dot);
    const act = document.createElement('td');
    act.className = 'actions';
    act.append(
      btn(r.enabled ? 'Disable' : 'Enable', 'ghost', () => save(r.id, {...r, enabled: !r.enabled})),
      ' ',
      btn('Edit', 'ghost', () => edit(r)),
      ' ',
      btn('Delete', 'danger', () => remove(r)),
    );
    tr.append(
      dotTd,
      cell(r.domain + (r.enabled ? '' : ' (disabled)')),
      cell((r.upstream_tls ? 'https://' : 'http://') + r.upstream),
      cell(r.tls_mode === 'internal' ? 'internal' : 'public'),
      cell(r.note, 'muted'),
      act,
    );
    tbody.append(tr);
  }
  refreshStatus();
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
  try {
    const body = {
      domain: data.domain, upstream: data.upstream, upstream_tls: !!data.upstream_tls,
      tls_mode: data.tls_mode, enabled: !!data.enabled, note: data.note || '',
    };
    const res = id ? await api('PUT', '/api/routes/' + id, body) : await api('POST', '/api/routes', body);
    reportApply(res);
    resetForm();
    render();
  } catch (e) { banner(e.message); }
}

function edit(r) {
  editingId = r.id;
  form.domain.value = r.domain;
  form.upstream.value = r.upstream;
  form.tls_mode.value = r.tls_mode;
  form.note.value = r.note;
  form.upstream_tls.checked = !!r.upstream_tls;
  form.dataset.enabled = r.enabled ? '1' : '';
  $('#submit').textContent = 'Save changes';
  form.domain.focus();
}

function resetForm() {
  editingId = null;
  form.reset();
  delete form.dataset.enabled;
  $('#submit').textContent = 'Add route';
}

async function remove(r) {
  if (!confirm('Delete ' + r.domain + '?')) return;
  try { reportApply(await api('DELETE', '/api/routes/' + r.id)); render(); }
  catch (e) { banner(e.message); }
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  save(editingId, {
    domain: form.domain.value, upstream: form.upstream.value, tls_mode: form.tls_mode.value,
    note: form.note.value, upstream_tls: form.upstream_tls.checked,
    enabled: editingId ? !!form.dataset.enabled : true,
  });
});

$('#reapply').onclick = async () => {
  try { reportApply(await api('POST', '/api/apply')); } catch (e) { banner(e.message); }
};
$('#logout').onclick = async () => { await api('POST', '/logout'); location.href = '/login'; };

render();
setInterval(refreshStatus, 15000);
