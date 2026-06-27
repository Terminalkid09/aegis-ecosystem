import React, { useState } from 'react';
import { setAuthToken, authAPI } from '../services/api';

export default function LoginModal({ open, onClose }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isRegister, setIsRegister] = useState(false);

  if (!open) return null;

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const payload = { email, username: email.split('@')[0], password };
      const res = isRegister ? await authAPI.register(payload) : await authAPI.login(email, password);
      // authAPI.login uses axios and returns full response
      const body = res.data || res;
      const token = body.access_token || body.accessToken || body.token;
      const user = body.user || body;
      if (token) {
        setAuthToken(token);
      }
      if (body.user) {
        try { localStorage.setItem('aegis_user', JSON.stringify(body.user)); } catch(e){}
      }
      // notify other components
      window.dispatchEvent(new Event('aegis-auth-changed'));
      onClose();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60" onClick={onClose}></div>
      <div className="relative w-full max-w-md p-6 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl text-slate-100">
        <h3 className="text-lg font-bold mb-4">{isRegister ? 'Register' : 'Login'}</h3>
        {error && <div className="mb-3 text-sm text-red-400">{error}</div>}
        <form onSubmit={submit} className="space-y-3">
          <input type="email" placeholder="you@example.com" required value={email} onChange={(e)=>setEmail(e.target.value)} className="w-full p-2 rounded bg-slate-800 border border-slate-700" />
          <input type="password" placeholder="Password" required value={password} onChange={(e)=>setPassword(e.target.value)} className="w-full p-2 rounded bg-slate-800 border border-slate-700" />

          <div className="flex items-center justify-between mt-2">
            <button type="submit" disabled={loading} className="px-4 py-2 bg-purple-600 rounded font-bold disabled:opacity-60">
              {loading ? 'Please wait...' : (isRegister ? 'Create account' : 'Sign in')}
            </button>
            <button type="button" onClick={()=>setIsRegister(!isRegister)} className="text-sm text-slate-400 underline">
              {isRegister ? 'Have an account? Login' : 'New user? Register'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
