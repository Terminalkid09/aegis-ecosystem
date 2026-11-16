(async () => {
  const statusEl = document.getElementById('sso-status');
  const raw = window.location.hash.startsWith('#token=')
    ? decodeURIComponent(window.location.hash.slice(7))
    : '';
  // Keep the assertion out of history/referrer even on failure.
  history.replaceState(null, '', window.location.pathname);
  if (!raw) {
    statusEl.textContent = 'Missing sign-in assertion. Open Kraken from the Aegis console.';
    return;
  }
  try {
    const res = await fetch('api/v1/auth/sso', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: raw }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      statusEl.textContent = data.detail || 'Delegated sign-in failed.';
      return;
    }
    const { access_token } = await res.json();
    if (access_token) localStorage.setItem('kraken_token', access_token);
    window.location.replace('./');
  } catch {
    statusEl.textContent = 'Connection error. Is Kraken running?';
  }
})();
