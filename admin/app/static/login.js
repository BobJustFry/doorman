document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = document.getElementById('err');
  try {
    const r = await fetch('/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: document.getElementById('pw').value}),
    });
    if (r.ok) { location.href = '/'; return; }
    const data = await r.json().catch(() => ({}));
    err.textContent = data.detail || 'Error';
  } catch (_) {
    err.textContent = 'Cannot reach the server';
  }
});
