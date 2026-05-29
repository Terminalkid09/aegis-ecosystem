import React, { useEffect, useState } from 'react';
import LoginModal from './LoginModal';
import { setAuthToken } from '../services/api';

export default function AuthButton() {
  const [open, setOpen] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const load = () => {
      try {
        const u = JSON.parse(localStorage.getItem('aegis_user'));
        setUser(u);
      } catch {
        setUser(null);
      }
    };
    load();
    window.addEventListener('storage', load);
    window.addEventListener('aegis-auth-changed', load);
    return () => {
      window.removeEventListener('storage', load);
      window.removeEventListener('aegis-auth-changed', load);
    };
  }, []);

  const logout = () => {
    setAuthToken(null);
    try { localStorage.removeItem('aegis_user'); } catch(e){}
    window.dispatchEvent(new Event('aegis-auth-changed'));
  };

  return (
    <div className="flex items-center gap-3">
      {user ? (
        <>
          <div className="text-xs text-slate-300">{user.username}</div>
          <button onClick={logout} className="px-3 py-1 bg-red-700 rounded text-xs font-bold">Logout</button>
        </>
      ) : (
        <>
          <button onClick={()=>setOpen(true)} className="px-3 py-1 bg-cyan-600 rounded text-xs font-bold">Login</button>
          <LoginModal open={open} onClose={()=>setOpen(false)} />
        </>
      )}
    </div>
  );
}
