/* Colour theme: follow the system (auto) or force light/dark. Loaded in <head> so the page
   never flashes the wrong theme. The choice is kept in this browser only. */
(function () {
  const KEY = 'doorman-theme';
  const ORDER = ['auto', 'light', 'dark'];
  function get() {
    try { const v = localStorage.getItem(KEY); return ORDER.includes(v) ? v : 'auto'; } catch (_) { return 'auto'; }
  }
  function apply(t) {
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
  }
  apply(get());
  window.doormanTheme = {
    get,
    next() {
      const n = ORDER[(ORDER.indexOf(get()) + 1) % ORDER.length];
      try { localStorage.setItem(KEY, n); } catch (_) { /* private mode: works until reload */ }
      apply(n);
      return n;
    },
  };
})();
