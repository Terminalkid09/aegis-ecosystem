import React, { useEffect, useState, useRef } from 'react';
import { Bot, Send, Eraser, User, MessageSquare, Plus, LogIn, Trash2 } from 'lucide-react';
import { aiAPI, invalidateCache } from '../services/api';
import { useDashboard } from '../context/DashboardContext';
import LoginModal from './LoginModal';

export default function AIChat() {
    const { aiChatHistory: messages, setAiChatHistory: setMessages, user } = useDashboard();
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [threads, setThreads] = useState([]);
    const [activeThreadId, setActiveThreadId] = useState(() => {
        try { const t = localStorage.getItem('aegis-active-thread'); return t ? Number(t) : null; } catch { return null; }
    });
    const [authOpen, setAuthOpen] = useState(false);
    const [status, setStatus] = useState(null);
    const initialLoadDone = useRef(false);

    const [isAuthenticated, setIsAuthenticated] = useState(false);

    useEffect(() => {
        setIsAuthenticated(!!user);
    }, [user]);

    useEffect(() => {
        if (user) loadThreads();
    }, [user]);

    // Restore active thread on mount
    useEffect(() => {
        if (activeThreadId && !initialLoadDone.current) {
            initialLoadDone.current = true;
            loadMessages(activeThreadId);
        }
    }, [activeThreadId]);

    // Persist active thread
    useEffect(() => {
        try {
            if (activeThreadId) localStorage.setItem('aegis-active-thread', String(activeThreadId));
            else localStorage.removeItem('aegis-active-thread');
        } catch {}
    }, [activeThreadId]);

    const loadThreads = async () => {
        if (!isAuthenticated) {
            setThreads([]);
            setActiveThreadId(null);
            setStatus('Login required before using the AI analyst.');
            return;
        }
        try {
            const res = await aiAPI.getThreads();
            setThreads(res.data || []);
            setStatus(null);
        } catch (err) {
            setStatus('Could not load AI threads. Please log in again.');
        }
    };

    const loadMessages = async (threadId) => {
        setActiveThreadId(threadId);
        try {
            const res = await aiAPI.getMessages(threadId);
            const loaded = (res.data || []).map(m => ({ role: m.role, content: m.content, model: m.model }));
            setMessages([
                { role: 'system', content: 'Aegis AI Security Analyst initialized.' },
                ...loaded
            ]);
        } catch (err) {
            setStatus('Could not load this investigation thread.');
        }
    };

    const newThread = () => {
        setActiveThreadId(null);
        setMessages([{ role: 'system', content: 'Aegis AI Security Analyst initialized. How can I assist with your forensic investigation?' }]);
        setStatus(null);
    };

    const handleSend = async (e) => {
        e.preventDefault();
        if (!input.trim() || loading) return;
        if (!isAuthenticated) {
            setAuthOpen(true);
            setStatus('Login required before using the AI analyst.');
            return;
        }

        const userMsg = { role: 'user', content: input };
        setMessages(prev => [...prev, userMsg]);
        setInput('');
        setLoading(true);

        try {
            const res = await aiAPI.chat(input, null, activeThreadId);
            if (!activeThreadId && res.data.thread_id) {
                setActiveThreadId(res.data.thread_id);
                invalidateCache('ai-threads');
                loadThreads();
            }
            const aiMsg = {
                role: 'ai',
                content: res.data.answer || "I've analyzed the request, but the model returned an empty response.",
                model: res.data.model_used || res.data.model
            };
            setMessages(prev => [...prev, aiMsg]);
        } catch (err) {
            const status = err?.response?.status;
            const detail = err?.response?.data?.detail;
            let message = 'Connection to AI Engine failed. Check your Ollama configuration.';
            if (status === 401 || status === 422) {
                message = 'Please log in before using the AI Security Analyst.';
            } else if (status === 403) {
                message = typeof detail === 'string' ? detail : 'Prompt blocked by AI safety policy.';
            } else if (status === 429) {
                message = 'AI rate limit exceeded. Please wait a moment before trying again.';
            } else if (status === 502) {
                message = 'The AI provider failed to respond. Check Ollama model availability and backend logs.';
            }
            setMessages(prev => [...prev, { role: 'error', content: message }]);
            setStatus(message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="h-[calc(100vh-160px)] flex flex-col gap-6">
            <div className="flex justify-between items-center">
                <div>
                    <h2 className="text-3xl font-bold flex items-center gap-3">
                        <Bot className="text-purple-500" /> AI Security Analyst
                    </h2>
                    <p className="text-slate-400 mt-1">Intelligent log analysis and threat remediation advice</p>
                </div>
                <div className="flex gap-2">
                    {!isAuthenticated && (
                        <button onClick={() => setAuthOpen(true)} className="inline-flex items-center gap-2 px-3 py-2 bg-cyan-700 hover:bg-cyan-600 rounded-lg text-xs font-bold">
                            <LogIn size={16}/> Login
                        </button>
                    )}
                    <button onClick={newThread} className="inline-flex items-center gap-1.5 px-3 py-2 bg-purple-700/40 hover:bg-purple-700/60 border border-purple-700/50 rounded-lg text-xs font-bold text-purple-300 transition-all" title="Start a new investigation">
                        <Plus size={16}/> New Chat
                    </button>
                    <button onClick={() => setMessages(messages.length ? [messages[0]] : [])} className="inline-flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs font-bold text-slate-400 transition-all" title="Clear current conversation messages">
                        <Eraser size={16}/> Clear
                    </button>
                </div>
            </div>
            {status && (
                <div className="bg-amber-950/40 border border-amber-800 text-amber-300 rounded-lg px-4 py-3 text-sm">
                    {status}
                </div>
            )}
            <LoginModal open={authOpen} onClose={() => { setAuthOpen(false); loadThreads(); }} />
            <div className="flex-1 bg-slate-900/50 border border-slate-800 rounded-xl grid grid-cols-[260px_1fr] overflow-hidden shadow-2xl">
                <aside className="border-r border-slate-800 bg-slate-950/40 p-4 overflow-y-auto">
                    <div className="text-[10px] text-slate-500 font-black uppercase tracking-widest mb-3">Investigations</div>
                    <div className="space-y-2">
                        {threads.map(thread => (
                            <div key={thread.id} className={`group flex items-center rounded-lg border transition-all ${activeThreadId === thread.id ? 'bg-purple-950/40 border-purple-700' : 'bg-slate-900 border-slate-800 hover:border-slate-700'}`}>
                                <button
                                    onClick={() => loadMessages(thread.id)}
                                    className="flex-1 text-left p-3 min-w-0"
                                >
                                    <div className="flex items-center gap-2 text-xs font-bold text-slate-400 group-hover:text-white transition-colors">
                                        <MessageSquare size={14} className="shrink-0"/>{thread.title}
                                    </div>
                                </button>
                                <button
                                    onClick={async (e) => { e.stopPropagation(); try { await aiAPI.deleteThread(thread.id); loadThreads(); if (activeThreadId === thread.id) newThread(); } catch {} }}
                                    className="p-2 mr-1 text-slate-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all"
                                    title="Delete investigation"
                                >
                                    <Trash2 size={14}/>
                                </button>
                            </div>
                        ))}
                        {threads.length === 0 && (
                            <div className="text-xs text-slate-600 italic">No saved investigations yet.</div>
                        )}
                    </div>
                </aside>
                <div className="flex flex-col overflow-hidden">
                {/* Chat Window */}
                <div className="flex-1 overflow-y-auto p-6 space-y-6">
                    {messages.map((m, i) => (
                        <div key={i} className={`flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                            <div className={`max-w-[80%] flex gap-4 ${m.role === 'user' ? 'flex-row-reverse' : ''}`}>
                                <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                                    m.role === 'user' ? 'bg-cyan-600' : m.role === 'ai' ? 'bg-purple-600' : 'bg-slate-700'
                                }`}>
                                    {m.role === 'user' ? <User size={16}/> : <Bot size={16}/>}
                                </div>
                                <div className={`p-4 rounded-2xl text-sm leading-relaxed ${
                                    m.role === 'user' 
                                        ? 'bg-cyan-900/40 border border-cyan-800 rounded-tr-none text-slate-100' 
                                        : m.role === 'error'
                                            ? 'bg-red-900/20 border border-red-800 text-red-400'
                                            : 'bg-slate-800 border border-slate-700 rounded-tl-none text-slate-300'
                                }`}>
                                    {m.content}
                                    {m.model && (
                                        <div className="mt-2 pt-2 border-t border-slate-700 text-[10px] font-mono text-slate-500 uppercase">
                                            Model: {m.model}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    ))}
                    {loading && (
                        <div className="flex justify-start">
                            <div className="bg-slate-800 border border-slate-700 p-4 rounded-2xl rounded-tl-none flex items-center gap-3">
                                <div className="flex gap-1">
                                    <div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}/>
                                    <div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}/>
                                    <div className="w-1.5 h-1.5 bg-purple-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}/>
                                </div>
                                <span className="text-xs text-slate-500 italic uppercase tracking-widest">Reasoning...</span>
                            </div>
                        </div>
                    )}
                </div>

                {/* Input Area */}
                <form onSubmit={handleSend} className="p-4 bg-slate-900 border-t border-slate-800 flex gap-4">
                    <input 
                        type="text"
                        placeholder="Ask about an alert or paste logs for analysis..."
                        className="flex-1 bg-slate-800 border-none rounded-lg px-4 py-3 text-sm focus:ring-1 focus:ring-purple-500 transition-all outline-none"
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        disabled={loading}
                    />
                    <button 
                        type="submit"
                        disabled={loading || !input.trim()}
                        className="bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white p-3 rounded-lg transition-all"
                    >
                        <Send size={20}/>
                    </button>
                </form>
                </div>
            </div>
        </div>
    );
}
