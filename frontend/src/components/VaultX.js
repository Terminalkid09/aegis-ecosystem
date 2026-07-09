import React, { useState, useEffect } from 'react';
import { Lock, Plus, Trash2, ShieldCheck, Tag, Loader2, AlertCircle } from 'lucide-react';
import { vaultAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function VaultX() {
    const { settings } = useDashboard();
    const [notes, setNotes] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [newNote, setNewNote] = useState({ title: '', content: '', mood: '', tags: '' });
    const [creating, setCreating] = useState(false);

    useEffect(() => {
        fetchNotes();
    }, []);

    const fetchNotes = async () => {
        try {
            setLoading(true);
            const res = await vaultAPI.getNotes();
            setNotes(res.data || []);
            setError(null);
        } catch (err) {
            console.error("Failed to load notes", err);
            const status = err?.response?.status;
            if (status === 401) {
                setError('Not authenticated. Please log in to access your encrypted notes.');
            } else if (status === 500) {
                setError('Server encryption error. Check MASTER_KEY_B64 and user DEK configuration.');
            } else {
                setError('Could not retrieve encrypted vault. Ensure you are logged in.');
            }
        } finally {
            setLoading(false);
        }
    };

    const handleCreate = async (e) => {
        e.preventDefault();
        if (!newNote.title || !newNote.content) return;

        try {
            setCreating(true);
            const payload = { 
                title: newNote.title,
                content: newNote.content,
                mood: newNote.mood || null,
                tags: newNote.tags ? newNote.tags.split(',').map(t => t.trim()).filter(t => t) : []
            };
            
            const res = await vaultAPI.createNote(payload);
            if (res.status === 200 || res.status === 201) {
                setNewNote({ title: '', content: '', mood: '', tags: '' });
                await fetchNotes();
            }
        } catch (err) {
            console.error("Failed to create note", err);
            alert("Encryption failed. Database connection might be busy.");
        } finally {
            setCreating(false);
        }
    };

    const handleDelete = async (id) => {
        if (!window.confirm("Permanently delete this encrypted note?")) return;
        try {
            await vaultAPI.deleteNote(id);
            await fetchNotes();
        } catch (err) {
            console.error("Delete failed", err);
        }
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-3xl font-bold flex items-center gap-3">
                        <Lock className="text-cyan-500" /> VaultX Secure Storage
                    </h2>
                    <p className="text-slate-400 mt-1">End-to-end encrypted notes with AES-256-GCM Envelope Encryption</p>
                </div>
                <div className="flex items-center gap-2 px-3 py-1 bg-cyan-900/20 border border-cyan-800 rounded text-cyan-400 text-xs font-bold uppercase tracking-widest">
                    <ShieldCheck size={14}/> AES-256-GCM Encrypted
                </div>
            </div>

            {error && (
                <div className="bg-red-900/20 border border-red-800 text-red-400 p-4 rounded-lg flex items-center gap-3">
                    <AlertCircle size={20}/> {error}
                </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Form */}
                <div className={`p-6 rounded-xl border h-fit sticky top-8 ${settings.darkMode ? 'bg-slate-900 border-slate-700 shadow-2xl' : 'bg-white border-slate-200 shadow-lg'}`}>
                    <h3 className="font-bold mb-6 flex items-center gap-2 italic text-cyan-400 uppercase tracking-tighter">
                        <Plus size={18}/> New Secure Entry
                    </h3>
                    <form onSubmit={handleCreate} className="space-y-4">
                        <div className="space-y-1">
                            <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Note Title</label>
                            <input 
                                type="text" 
                                placeholder="Classification level..." 
                                className="w-full bg-slate-800 border-none rounded-lg px-4 py-2.5 text-sm focus:ring-1 focus:ring-cyan-500 outline-none"
                                value={newNote.title}
                                onChange={(e) => setNewNote({...newNote, title: e.target.value})}
                                required
                            />
                        </div>
                        <div className="space-y-1">
                            <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Payload Content</label>
                            <textarea 
                                placeholder="Confidential data..." 
                                className="w-full bg-slate-800 border-none rounded-lg px-4 py-2.5 text-sm h-40 focus:ring-1 focus:ring-cyan-500 outline-none resize-none"
                                value={newNote.content}
                                onChange={(e) => setNewNote({...newNote, content: e.target.value})}
                                required
                            />
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-1">
                                <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Mood</label>
                                <input 
                                    type="text" 
                                    placeholder="Neutral" 
                                    className="bg-slate-800 border-none rounded-lg px-4 py-2 text-xs focus:ring-1 focus:ring-cyan-500 outline-none"
                                    value={newNote.mood}
                                    onChange={(e) => setNewNote({...newNote, mood: e.target.value})}
                                />
                            </div>
                            <div className="space-y-1">
                                <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Tags (csv)</label>
                                <input 
                                    type="text" 
                                    placeholder="intel, ops" 
                                    className="bg-slate-800 border-none rounded-lg px-4 py-2 text-xs focus:ring-1 focus:ring-cyan-500 outline-none"
                                    value={newNote.tags}
                                    onChange={(e) => setNewNote({...newNote, tags: e.target.value})}
                                />
                            </div>
                        </div>
                        <button 
                            type="submit" 
                            disabled={creating}
                            className="w-full bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-black py-3 rounded-lg hover:shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all flex items-center justify-center gap-2 mt-4"
                        >
                            {creating ? <Loader2 size={18} className="animate-spin"/> : <Lock size={18}/>}
                            {creating ? 'EXECUTING ENCRYPTION...' : 'ENCRYPT & PERSIST'}
                        </button>
                    </form>
                </div>

                {/* Notes List */}
                <div className="lg:col-span-2 space-y-4">
                    {loading ? (
                        <div className="h-64 flex flex-col items-center justify-center text-slate-500 italic gap-4">
                            <Loader2 size={32} className="animate-spin text-cyan-500"/>
                            Decrypting secure enclave...
                        </div>
                    ) : notes.length === 0 ? (
                        <div className="h-64 border-2 border-dashed border-slate-800 rounded-xl flex flex-col items-center justify-center text-slate-600 gap-2">
                            <Lock size={48} className="opacity-10"/>
                            <p className="font-bold uppercase tracking-widest text-xs">Secure Storage Empty</p>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {notes.map(note => (
                                <div key={note.id} className="bg-slate-900/40 border border-slate-800 rounded-xl p-6 relative group hover:border-cyan-500/50 transition-all duration-300 shadow-xl">
                                    <button 
                                        onClick={() => handleDelete(note.id)}
                                        className="absolute top-4 right-4 text-slate-600 hover:text-red-500 transition-colors opacity-0 group-hover:opacity-100"
                                    >
                                        <Trash2 size={16}/>
                                    </button>
                                    <h4 className="font-black text-slate-100 mb-3 pr-8 uppercase tracking-tight border-b border-slate-800 pb-2">{note.title}</h4>
                                    <div className="bg-slate-950/50 rounded-lg p-3 mb-4">
                                        <p className="text-xs text-slate-400 line-clamp-4 leading-relaxed font-mono">{note.content}</p>
                                    </div>
                                    <div className="flex flex-wrap gap-2">
                                        {note.mood && (
                                            <span className="px-2 py-0.5 bg-slate-800 text-slate-400 rounded-md text-[9px] font-black uppercase tracking-tighter">MOOD: {note.mood}</span>
                                        )}
                                        {note.tags?.map(tag => (
                                            <span key={tag} className="flex items-center gap-1 px-2 py-0.5 bg-cyan-900/20 text-cyan-500 border border-cyan-900/50 rounded-md text-[9px] font-black uppercase tracking-tighter">
                                                <Tag size={8}/>{tag}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
