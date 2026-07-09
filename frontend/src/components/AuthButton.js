import React, { useState } from 'react';
import LoginModal from './LoginModal';
import { useDashboard } from '../context/DashboardContext';

export default function AuthButton() {
  const [open, setOpen] = useState(false);
  const { user, logout } = useDashboard();

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
