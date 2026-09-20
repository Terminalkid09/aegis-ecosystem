import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Lock, Plus, Trash2, ShieldCheck, Tag, Loader2, AlertCircle } from 'lucide-react'
import { vaultAPI } from '@/services/api'
import { useAppStore } from '@/store/appStore'

export default function VaultX() {
  const qc = useQueryClient()
  const { user } = useAppStore()

  const [newNote, setNewNote] = useState({ title: '', content: '', mood: '', tags: '' })
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const { data: notes = [], isLoading } = useQuery({
    queryKey: ['vault-notes'],
    queryFn: () => vaultAPI.getNotes().then(r => {
      setErrorMsg(null)
      return r.data || []
    }),
    enabled: !!user,
  })

  // Handle auth states
  if (!user && !errorMsg) {
    setErrorMsg('Not authenticated. Please log in to access your encrypted notes.')
  }

  const createMut = useMutation({
    mutationFn: (payload: any) => vaultAPI.createNote(payload),
    onSuccess: () => {
      setNewNote({ title: '', content: '', mood: '', tags: '' })
      qc.invalidateQueries({ queryKey: ['vault-notes'] })
    },
    onError: () => {
      alert("Encryption failed. Database connection might be busy.")
    }
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => vaultAPI.deleteNote(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vault-notes'] })
  })

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault()
    if (!newNote.title || !newNote.content || createMut.isPending) return

    createMut.mutate({
      title: newNote.title,
      content: newNote.content,
      mood: newNote.mood || null,
      tags: newNote.tags ? newNote.tags.split(',').map(t => t.trim()).filter(t => t) : []
    })
  }

  const handleDelete = (id: string) => {
    if (confirm("Permanently delete this encrypted note?")) {
      deleteMut.mutate(id)
    }
  }

  return (
    <div className="space-y-8 animate-slide-in">
      <div className="flex flex-col sm:flex-row justify-between sm:items-end gap-4 shrink-0">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
            <Lock className="text-cyan-400" /> VaultX Secure Storage
          </h1>
          <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">End-to-end encrypted notes with AES-256-GCM Envelope Encryption</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500/10 border border-cyan-500/20 rounded-lg text-cyan-400 text-xs font-bold uppercase tracking-widest shadow-sm">
          <ShieldCheck size={14}/> AES-256-GCM Encrypted
        </div>
      </div>

      {errorMsg && (
        <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-4 rounded-lg flex items-center gap-3 shadow-sm">
          <AlertCircle size={20}/> {errorMsg}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form Panel */}
        <div className="card p-6 h-fit sticky top-6 shadow-2xl">
          <h3 className="font-black mb-6 flex items-center gap-2 text-cyan-400 uppercase tracking-widest text-sm border-b border-[hsl(var(--border))] pb-3">
            <Plus size={18}/> New Secure Entry
          </h3>
          <form onSubmit={handleCreate} className="space-y-5">
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Note Title</label>
              <input 
                type="text" 
                placeholder="Classification level..." 
                className="input bg-[hsl(var(--background))]"
                value={newNote.title}
                onChange={(e) => setNewNote({...newNote, title: e.target.value})}
                required
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Payload Content</label>
              <textarea 
                placeholder="Confidential data..." 
                className="input h-32 resize-none bg-[hsl(var(--background))]"
                value={newNote.content}
                onChange={(e) => setNewNote({...newNote, content: e.target.value})}
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Mood</label>
                <input 
                  type="text" 
                  placeholder="Neutral" 
                  className="input bg-[hsl(var(--background))]"
                  value={newNote.mood}
                  onChange={(e) => setNewNote({...newNote, mood: e.target.value})}
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase tracking-widest">Tags (csv)</label>
                <input 
                  type="text" 
                  placeholder="intel, ops" 
                  className="input bg-[hsl(var(--background))]"
                  value={newNote.tags}
                  onChange={(e) => setNewNote({...newNote, tags: e.target.value})}
                />
              </div>
            </div>
            <button 
              type="submit" 
              disabled={createMut.isPending || !user}
              className="btn btn-primary w-full bg-cyan-600 hover:bg-cyan-500 border-cyan-500 shadow-cyan-500/20 py-2.5 justify-center mt-2"
            >
              {createMut.isPending ? <Loader2 size={16} className="animate-spin"/> : <Lock size={16}/>}
              {createMut.isPending ? 'ENCRYPTING...' : 'ENCRYPT & PERSIST'}
            </button>
          </form>
        </div>

        {/* Notes List */}
        <div className="lg:col-span-2 space-y-4">
          {isLoading && user ? (
            <div className="h-64 flex flex-col items-center justify-center text-[hsl(var(--muted-foreground))] italic gap-4 bg-[hsl(var(--secondary)/0.3)] rounded-xl border border-[hsl(var(--border))]">
              <Loader2 size={32} className="animate-spin text-cyan-500"/>
              Decrypting secure enclave...
            </div>
          ) : notes.length === 0 ? (
            <div className="h-64 border-2 border-dashed border-[hsl(var(--border))] rounded-xl flex flex-col items-center justify-center text-[hsl(var(--muted-foreground))] gap-3 bg-[hsl(var(--secondary)/0.3)]">
              <Lock size={48} className="opacity-20 text-cyan-400"/>
              <p className="font-bold uppercase tracking-widest text-xs">Secure Storage Empty</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {notes.map((note: any) => (
                <div key={note.id} className="card p-5 relative group hover:border-cyan-500/50 transition-all duration-300 shadow-lg">
                  <button 
                    onClick={() => handleDelete(note.id)}
                    className="absolute top-4 right-4 text-[hsl(var(--muted-foreground))] hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100 p-1 bg-[hsl(var(--background))] rounded-md border border-[hsl(var(--border))]"
                    title="Delete Note"
                  >
                    <Trash2 size={14}/>
                  </button>
                  <h4 className="font-black text-white mb-3 pr-8 uppercase tracking-widest border-b border-[hsl(var(--border))] pb-2 text-sm">{note.title}</h4>
                  <div className="bg-[hsl(var(--background))] border border-[hsl(var(--border))] rounded-lg p-3 mb-4">
                    <p className="text-xs text-[hsl(var(--muted-foreground))] line-clamp-4 leading-relaxed font-mono whitespace-pre-wrap">{note.content}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {note.mood && (
                      <span className="px-2.5 py-1 bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border border-[hsl(var(--border))] rounded-md text-[9px] font-black uppercase tracking-widest">
                        MOOD: <span className="text-white">{note.mood}</span>
                      </span>
                    )}
                    {note.tags?.map((tag: string) => (
                      <span key={tag} className="flex items-center gap-1.5 px-2.5 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded-md text-[9px] font-black uppercase tracking-widest">
                        <Tag size={10}/>{tag}
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
  )
}
