/* Shared Kraken UI helpers. Loaded from 'self' so the Caddy CSP can keep
   script-src 'self' (no inline scripts or inline event handlers). */
if (window.tailwind) {
  window.tailwind.config = {
    darkMode: 'class',
    theme: { extend: { colors: { brand: '#6366f1' } } },
  };
}
if (localStorage.getItem('theme') !== 'light') {
  document.documentElement.classList.add('dark');
} else {
  document.documentElement.classList.remove('dark');
}

function escapeHtml(str) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function toggleTheme() {
  const isDark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
}

function logout() {
  fetch('api/v1/auth/logout', { method: 'POST', credentials: 'include' })
    .finally(() => {
      localStorage.removeItem('kraken_token');
      window.location.href = 'login';
    });
}

function requireAuth() {
  if (!localStorage.getItem('kraken_token')) window.location.href = 'login';
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('theme-toggle')?.addEventListener('click', toggleTheme);
  document.getElementById('logout-btn')?.addEventListener('click', logout);
});
