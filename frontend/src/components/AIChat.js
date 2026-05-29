import React, { useEffect, useState } from 'react';
import { Bot, Send, Eraser, User, MessageSquare, Plus, LogIn } from 'lucide-react';
import { aiAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';
import LoginModal from './LoginModal';

export default function AIChat() {
    const { aiChatHistory: messages, setAiChatHistory: setMessages } = useDashboard();
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [threads, setThreads] = useState([]);
    const [activeThreadId, setActiveThreadId] = useState(null);
    const [authOpen, setAuthOpen] = useState(false);
    const [status, setStatus] = useState(null);

    const isAuthenticated = () => !!localStorage.getItem('aegis_token');

    useEffect(() => {
        loadThreads();
        const onAuth = () => loadThreads();
        window.addEventListener('aegis-auth-changed', onAuth);
        return () => window.removeEventListener('aegis-auth-changed', onAuth);
    }, []);

    const loadThreads = async () => {
        if (!isAuthenticated()) {
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
        if (!isAuthenticated()) {
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
                    {!isAuthenticated() && (
                        <button onClick={() => setAuthOpen(true)} className="inline-flex items-center gap-2 px-3 py-2 bg-cyan-700 hover:bg-cyan-600 rounded-lg text-xs font-bold">
                            <LogIn size={16}/> Login
                        </button>
                    )}
                    <button onClick={newThread} className="p-2 text-slate-500 hover:text-white transition-colors">
                        <Plus size={20}/>
                    </button>
                    <button onClick={() => setMessages(messages.length ? [messages[0]] : [])} className="p-2 text-slate-500 hover:text-white transition-colors">
                        <Eraser size={20}/>
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
                            <button
                                key={thread.id}
                                onClick={() => loadMessages(thread.id)}
                                className={`w-full text-left p-3 rounded-lg border transition-all ${activeThreadId === thread.id ? 'bg-purple-950/40 border-purple-700 text-white' : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-white'}`}
                            >
                                <div className="flex items-center gap-2 text-xs font-bold">
                                    <MessageSquare size={14}/>{thread.title}
                                </div>
                            </button>
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
