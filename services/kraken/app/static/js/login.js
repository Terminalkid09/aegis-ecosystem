async function doLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const errorEl = document.getElementById('error-msg');
  const btn = document.getElementById('login-btn');

  errorEl.classList.add('hidden');
  if (!username || !password) {
    errorEl.textContent = 'Please enter username and password.';
    errorEl.classList.remove('hidden');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in…';

  try {
    const res = await fetch('api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      errorEl.textContent = data.detail || 'Invalid credentials.';
      errorEl.classList.remove('hidden');
      return;
    }
    const { access_token } = await res.json();
    localStorage.setItem('kraken_token', access_token);
    window.location.href = './';
  } catch {
    errorEl.textContent = 'Connection error. Is the server running?';
    errorEl.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Sign In';
  }
}

document.getElementById('login-btn').addEventListener('click', doLogin);
document.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
if (localStorage.getItem('kraken_token')) window.location.href = './';
