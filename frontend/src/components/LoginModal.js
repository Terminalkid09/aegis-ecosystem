import React, { useState } from 'react';
import { authAPI, setAuthToken } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function LoginModal({ open, onClose }) {
  const { login, checkAuth } = useDashboard();
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
      if (isRegister) {
        const res = await authAPI.register({ email, username: email.split('@')[0], password });
        const body = res.data || res;
        const token = body.access_token || body.accessToken || body.token;
        if (token) setAuthToken(token);
        // cookie is set by backend; re-fetch user state
        await checkAuth();
      } else {
        await login(email, password);
      }
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
