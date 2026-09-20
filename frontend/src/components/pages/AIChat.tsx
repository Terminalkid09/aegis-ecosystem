import { useEffect, useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bot, Send, Eraser, User, MessageSquare, Plus, LogIn, Trash2, AlertCircle } from 'lucide-react'
import { aiAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'
import { cn } from '@/lib/utils'

export default function AIChat() {
  const qc = useQueryClient()
  const { user, currentPage, setCurrentPage } = useAppStore()
  
  const [messages, setMessages] = useState<any[]>([{ role: 'system', content: 'Aegis AI Security Analyst initialized. How can I assist with your forensic investigation?' }])
  const [input, setInput] = useState('')
  const [activeThreadId, setActiveThreadId] = useState<number | null>(() => {
    try { const t = localStorage.getItem('aegis-active-thread'); return t ? Number(t) : null } catch { return null }
  })
  const [statusMsg, setStatusMsg] = useState<string | null>(null)
  
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const initialLoadDone = useRef(false)

  // Auto-scroll
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // Persist active thread
  useEffect(() => {
    try {
      if (activeThreadId) localStorage.setItem('aegis-active-thread', String(activeThreadId))
      else localStorage.removeItem('aegis-active-thread')
    } catch {}
  }, [activeThreadId])

  const { data: threads = [] } = useQuery({
    queryKey: ['ai-threads'],
    queryFn: () => aiAPI.getThreads().then(r => r.data || []),
    enabled: !!user,
  })

  // Load messages when thread changes
  useEffect(() => {
    if (activeThreadId && user && !initialLoadDone.current) {
      initialLoadDone.current = true
      loadMessagesMut.mutate(activeThreadId)
    }
  }, [activeThreadId, user])

  const loadMessagesMut = useMutation({
    mutationFn: (threadId: number) => aiAPI.getMessages(threadId),
    onSuccess: (res, threadId) => {
      setActiveThreadId(threadId)
      const loaded = (res.data || []).map((m: any) => ({ role: m.role, content: m.content, model: m.model }))
      setMessages([{ role: 'system', content: 'Aegis AI Security Analyst initialized.' }, ...loaded])
      setStatusMsg(null)
    },
    onError: () => setStatusMsg('Could not load this investigation thread.')
  })

  const newThread = () => {
    setActiveThreadId(null)
    setMessages([{ role: 'system', content: 'Aegis AI Security Analyst initialized. How can I assist with your forensic investigation?' }])
    setStatusMsg(null)
  }

  const deleteThreadMut = useMutation({
    mutationFn: (id: number) => aiAPI.deleteThread(id),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ['ai-threads'] })
      if (activeThreadId === id) newThread()
    }
  })

  const chatMut = useMutation({
    mutationFn: (msg: string) => aiAPI.chat(msg, undefined, activeThreadId),
    onSuccess: (res) => {
      if (!activeThreadId && res.data.thread_id) {
        setActiveThreadId(res.data.thread_id)
        qc.invalidateQueries({ queryKey: ['ai-threads'] })
      }
      const aiMsg = {
        role: 'ai',
        content: res.data.answer || "I've analyzed the request, but the model returned an empty response.",
        model: res.data.model_used || res.data.model
      }
      setMessages(prev => [...prev, aiMsg])
    },
    onError: (err: any) => {
      const status = err?.response?.status
      const detail = err?.response?.data?.detail
      let msg = 'Connection to AI Engine failed. Check your configuration.'
      if (status === 401 || status === 422) msg = 'Please log in before using the AI Security Analyst.'
      else if (status === 403) msg = typeof detail === 'string' ? detail : 'Prompt blocked by AI safety policy.'
      else if (status === 429) msg = 'AI rate limit exceeded. Please wait a moment before trying again.'
      else if (status === 502) msg = 'The AI provider failed to respond. Check backend logs.'
      
      setMessages(prev => [...prev, { role: 'error', content: msg }])
      setStatusMsg(msg)
    }
  })

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || chatMut.isPending) return
    if (!user) {
      setStatusMsg('Login required before using the AI analyst.')
      return
    }

    setMessages(prev => [...prev, { role: 'user', content: input }])
    setInput('')
    setStatusMsg(null)
    chatMut.mutate(input)
  }

  return (
    <div className="h-[calc(100vh-120px)] flex flex-col gap-6 animate-slide-in">
      <div className="flex justify-between items-end shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Bot className="text-purple-400" /> AI Security Analyst
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">Intelligent log analysis and threat remediation advice</p>
        </div>
        <div className="flex items-center gap-2">
          {!user && (
            <button onClick={() => setCurrentPage('settings')} className="btn btn-primary bg-cyan-600 hover:bg-cyan-500 py-1.5 px-3 text-xs">
              <LogIn size={14} /> Login
            </button>
          )}
          <button onClick={newThread} className="btn btn-primary bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20 py-1.5 px-3 text-xs">
            <Plus size={14} /> New Chat
          </button>
          <button onClick={() => setMessages(messages.length ? [messages[0]] : [])} className="btn btn-ghost py-1.5 px-3 text-xs border border-[hsl(var(--border))]">
            <Eraser size={14} /> Clear
          </button>
        </div>
      </div>

      {statusMsg && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400 flex items-center gap-2 animate-fade-in shrink-0">
          <AlertCircle size={16} /> {statusMsg}
        </div>
      )}

      <div className="flex-1 card grid grid-cols-1 lg:grid-cols-[260px_1fr] overflow-hidden">
        {/* Sidebar */}
        <aside className="border-r border-[hsl(var(--border))] bg-[hsl(var(--secondary)/0.5)] p-4 overflow-y-auto hidden lg:block">
          <div className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-3">Investigations</div>
          <div className="space-y-1">
            {threads.map((thread: any) => (
              <div key={thread.id} className={cn('group flex items-center rounded-lg border transition-all cursor-pointer', activeThreadId === thread.id ? 'bg-[hsl(var(--primary)/0.1)] border-[hsl(var(--primary)/0.3)] text-white' : 'bg-[hsl(var(--secondary))] border-transparent hover:border-[hsl(var(--border))] text-[hsl(var(--muted-foreground))] hover:text-white')} onClick={() => loadMessagesMut.mutate(thread.id)}>
                <div className="flex-1 p-2.5 min-w-0 flex items-center gap-2 text-xs font-medium">
                  <MessageSquare size={14} className="shrink-0" />
                  <span className="truncate">{thread.title}</span>
                </div>
                <button onClick={(e) => { e.stopPropagation(); deleteThreadMut.mutate(thread.id) }} className="p-2 opacity-0 group-hover:opacity-100 text-[hsl(var(--muted-foreground))] hover:text-red-400 transition-colors" title="Delete">
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
            {threads.length === 0 && <div className="text-xs text-[hsl(var(--muted-foreground))] italic p-2">No saved investigations yet.</div>}
          </div>
        </aside>

        {/* Chat Area */}
        <div className="flex flex-col overflow-hidden bg-[hsl(var(--background))]">
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {messages.map((m, i) => (
              <div key={i} className={cn('flex', m.role === 'user' ? 'justify-end' : 'justify-start')}>
                <div className={cn('max-w-[85%] flex gap-4', m.role === 'user' ? 'flex-row-reverse' : '')}>
                  
                  <div className={cn('w-8 h-8 rounded-xl flex items-center justify-center shrink-0 shadow-lg', m.role === 'user' ? 'bg-cyan-600 text-white' : m.role === 'ai' || m.role === 'system' ? 'bg-purple-600 text-white' : 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))]')}>
                    {m.role === 'user' ? <User size={16} /> : <Bot size={16} />}
                  </div>
                  
                  <div className={cn('p-4 rounded-2xl text-sm leading-relaxed shadow-sm',
                    m.role === 'user' ? 'bg-cyan-900/30 border border-cyan-800 rounded-tr-none text-cyan-50' : 
                    m.role === 'error' ? 'bg-red-900/20 border border-red-800 text-red-400 rounded-tl-none' : 
                    'bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] rounded-tl-none text-slate-200'
                  )}>
                    <div className="whitespace-pre-wrap">{m.content}</div>
                    {m.model && (
                      <div className="mt-3 pt-3 border-t border-[hsl(var(--border))] text-[10px] font-mono text-[hsl(var(--muted-foreground))] uppercase tracking-wider">
                        Model: {m.model}
                      </div>
                    )}
                  </div>

                </div>
              </div>
            ))}

            {chatMut.isPending && (
              <div className="flex justify-start">
                <div className="flex gap-4 max-w-[85%]">
                  <div className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0 shadow-lg bg-purple-600 text-white">
                    <Bot size={16} />
                  </div>
                  <div className="p-4 rounded-2xl rounded-tl-none bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] shadow-sm flex items-center gap-3">
                    <div className="flex gap-1.5">
                      <div className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}/>
                      <div className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}/>
                      <div className="w-1.5 h-1.5 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}/>
                    </div>
                    <span className="text-[10px] text-[hsl(var(--muted-foreground))] uppercase font-bold tracking-widest">Reasoning...</span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <form onSubmit={handleSend} className="p-4 bg-[hsl(var(--secondary))] border-t border-[hsl(var(--border))] flex gap-3">
            <input
              type="text"
              placeholder={user ? "Ask about an alert or paste logs for analysis..." : "Login required to chat..."}
              className="input flex-1 bg-[hsl(var(--background))]"
              value={input}
              onChange={e => setInput(e.target.value)}
              disabled={chatMut.isPending || !user}
            />
            <button
              type="submit"
              disabled={chatMut.isPending || !input.trim() || !user}
              className="btn btn-primary bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20 px-4"
            >
              <Send size={18} />
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
