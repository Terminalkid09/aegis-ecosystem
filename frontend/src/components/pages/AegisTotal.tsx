import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { FileSearch, Upload, ShieldAlert, ShieldCheck, FileText, Package, AlertTriangle, Eye, X } from 'lucide-react'
import { totalAPI } from '@/services/api'
import { cn } from '@/lib/utils'

function verdictBadge(v: string) {
  if (v === 'malicious') return 'bg-red-500/10 text-red-400 border border-red-500/20'
  if (v === 'suspicious') return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
  if (v === 'clean') return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
  return 'bg-[hsl(var(--secondary))] text-[hsl(var(--muted-foreground))] border border-[hsl(var(--border))]'
}

export default function AegisTotal() {
  const qc = useQueryClient()
  
  const [accepted, setAccepted] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [selectedReport, setSelectedReport] = useState<any>(null)
  const [activePath, setActivePath] = useState('')
  const [msg, setMsg] = useState('')

  const { data: disclaimer = '' } = useQuery({
    queryKey: ['aegis-total-disclaimer'],
    queryFn: () => totalAPI.getDisclaimer().then(r => r.data.disclaimer).catch(() => 'By uploading, you confirm you have rights to this file. Defensive analysis only. Scans are recorded.'),
  })

  const { data: reports = [] } = useQuery({
    queryKey: ['aegis-total-reports'],
    queryFn: () => totalAPI.listReports().then(r => r.data.items || []),
  })

  // Lista formati accettati letta dal backend: nessun formato è rifiutato,
  // ma la UI deve dire la verità su cosa viene analizzato e come.
  const { data: formatInfo } = useQuery({
    queryKey: ['aegis-total-formats'],
    queryFn: () => totalAPI.getFormats().then(r => r.data).catch(() => null),
    staleTime: 5 * 60 * 1000,
  })
  const [showFormats, setShowFormats] = useState(false)

  const uploadMut = useMutation({
    mutationFn: () => totalAPI.upload(file as File, true),
    onSuccess: async (r) => {
      setMsg(`Analysis complete: ${r.data.verdict} (score ${r.data.score}). ${r.data.cached ? 'Loaded from cache.' : ''}`)
      qc.invalidateQueries({ queryKey: ['aegis-total-reports'] })
      const details = await totalAPI.getReport(r.data.sha256).then(res => res.data)
      setSelectedReport(details)
      setActivePath((details.files || [])[0]?.path || '')
      setFile(null)
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Upload failed.')
  })

  const deleteMut = useMutation({
    mutationFn: (sha: string) => totalAPI.deleteReport(sha),
    onSuccess: (_, sha) => {
      qc.invalidateQueries({ queryKey: ['aegis-total-reports'] })
      if (selectedReport?.sha256 === sha) setSelectedReport(null)
      setMsg('Report deleted (GDPR compliance). Binaries are never retained, only hashes & findings.')
    },
    onError: (e: any) => setMsg(e?.response?.data?.detail || 'Delete failed.')
  })

  const handleUpload = () => {
    if (!file) return setMsg('Please select a file or project .zip')
    if (!accepted) return setMsg('You must accept the defensive use disclaimer first.')
    setMsg('')
    uploadMut.mutate()
  }

  const openReport = async (sha: string) => {
    try {
      const details = await totalAPI.getReport(sha).then(r => r.data)
      setSelectedReport(details)
      setActivePath((details.files || [])[0]?.path || '')
    } catch (e: any) {
      setMsg(e?.response?.data?.detail || 'Report not found.')
    }
  }

  const activeFile = (selectedReport?.files || []).find((f: any) => f.path === activePath) || (selectedReport?.files || [])[0]

  return (
    <div className="space-y-6 animate-slide-in">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2 text-white">
          <FileSearch className="text-purple-400" /> Aegis Total
        </h1>
        <p className="text-sm text-[hsl(var(--muted-foreground))] mt-0.5">
          Internal static analysis sandbox. Upload single files or archives (<span className="text-white font-medium">.zip .tar .gz .7z .rar .apk .jar .docx .pdf</span>…).
        </p>
      </div>

      <div className="rounded-xl border border-orange-500/20 bg-orange-500/10 p-5 text-sm flex gap-4 items-start shadow-orange-500/5">
        <AlertTriangle size={24} className="shrink-0 text-orange-400" />
        <div>
          <div className="font-bold text-orange-400 mb-1">Defensive Use Only — Read Before Uploading</div>
          <div className="text-orange-200/80 mb-3">{disclaimer}</div>
          <label className="flex items-center gap-2 cursor-pointer text-orange-200 font-medium select-none">
            <input type="checkbox" checked={accepted} onChange={e => setAccepted(e.target.checked)} className="rounded border-orange-500/50 bg-transparent text-orange-500 focus:ring-orange-500/20 w-4 h-4" />
            I confirm I am authorized and this is for defensive analysis.
          </label>
        </div>
      </div>

      {msg && <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-400 animate-fade-in">{msg}</div>}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Upload Panel */}
        <div className="card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))] flex items-center gap-2"><Upload size={14} /> New Analysis</h3>
          
          <div className="relative border-2 border-dashed border-[hsl(var(--border))] rounded-xl p-6 text-center hover:bg-[hsl(var(--secondary)/0.5)] transition-colors">
            <input 
              type="file" 
              onChange={e => setFile(e.target.files?.[0] || null)} 
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            />
            <Package size={32} className="mx-auto text-[hsl(var(--muted-foreground))] mb-3" />
            {file ? (
              <div>
                <p className="font-mono text-cyan-400 text-sm truncate px-2">{file.name}</p>
                <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
              </div>
            ) : (
              <div>
                <p className="text-sm font-bold text-white">Click or drag file here</p>
                <p className="text-xs text-[hsl(var(--muted-foreground))] mt-1">
                  Any file is accepted — PE/.NET, ELF, Mach-O, Office, PDF, archives, scripts, firmware…
                </p>
              </div>
            )}
          </div>

          <button onClick={handleUpload} disabled={uploadMut.isPending || !accepted || !file} className="btn btn-primary w-full bg-purple-600 hover:bg-purple-500 border-purple-500 shadow-purple-500/20">
            {uploadMut.isPending ? 'Analyzing...' : 'Analyze File'}
          </button>

          <button onClick={() => setShowFormats(v => !v)} className="text-[11px] underline text-[hsl(var(--muted-foreground))] hover:text-white w-full text-center">
            {showFormats ? 'Hide supported formats' : `What can I upload? (${formatInfo?.formats?.length ?? 0}+ families)`}
          </button>

          {showFormats && formatInfo && (
            <div className="space-y-2 max-h-[280px] overflow-y-auto pr-1">
              {(formatInfo.formats || []).map((f: any) => (
                <div key={f.id} className="rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--secondary))] p-2.5">
                  <div className="text-xs font-bold text-white">{f.label}</div>
                  <div className="text-[10px] font-mono text-cyan-400/80 break-all mt-0.5">
                    {(f.extensions || []).filter((e: string) => e && e !== '*').slice(0, 12).join(' ')}
                    {(f.extensions || []).length > 12 ? ' …' : ''}
                  </div>
                  <div className="text-[10px] text-[hsl(var(--muted-foreground))] mt-1">{f.analysis}</div>
                </div>
              ))}
              <p className="text-[10px] text-[hsl(var(--muted-foreground))] italic">{formatInfo.note}</p>
            </div>
          )}

          <p className="text-[10px] text-[hsl(var(--muted-foreground))] text-center">
            Limits: {formatInfo?.limits?.max_file_mb ?? 100}MB file · {formatInfo?.limits?.max_zip_mb ?? 200}MB archive · max {formatInfo?.limits?.max_files_per_zip ?? 2000} files.
          </p>
        </div>

        {/* Reports List */}
        <div className="xl:col-span-2 card p-5 space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-widest text-[hsl(var(--muted-foreground))]">Recent Reports (dedup sha256)</h3>
          
          <div className="space-y-2 max-h-[300px] overflow-y-auto pr-2">
            {reports.map((r: any) => (
              <div key={r.sha256} className={cn("flex flex-col sm:flex-row sm:items-center justify-between p-3 rounded-lg border transition-colors cursor-pointer group", selectedReport?.sha256 === r.sha256 ? 'bg-[hsl(var(--primary)/0.05)] border-[hsl(var(--primary)/0.5)]' : 'bg-[hsl(var(--secondary))] border-[hsl(var(--border))] hover:border-[hsl(var(--primary)/0.3)]')}>
                <div className="flex-1 min-w-0" onClick={() => openReport(r.sha256)}>
                  <div className="flex items-center gap-2 mb-1">
                    {r.verdict === 'clean' ? <ShieldCheck size={14} className="text-emerald-400 shrink-0" /> : <ShieldAlert size={14} className="text-red-400 shrink-0" />}
                    <span className="font-mono text-sm font-semibold text-white truncate">{r.filename}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={cn('px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider', verdictBadge(r.verdict))}>{r.verdict}</span>
                    <span className="text-xs text-[hsl(var(--muted-foreground))]">Score: <span className="font-mono text-white">{r.score}</span></span>
                    <span className="text-[10px] font-mono text-[hsl(var(--muted-foreground))] hidden sm:inline-block truncate">sha256: {r.sha256.slice(0,16)}…</span>
                  </div>
                </div>
                <button onClick={(e) => { e.stopPropagation(); if (confirm(`Delete report ${r.sha256.slice(0, 12)}...?`)) deleteMut.mutate(r.sha256) }} className="p-2 rounded text-[hsl(var(--muted-foreground))] hover:text-red-400 hover:bg-red-500/10 transition-colors self-end sm:self-center mt-2 sm:mt-0">
                  <X size={16} />
                </button>
              </div>
            ))}
            {reports.length === 0 && <div className="text-center py-10 text-[hsl(var(--muted-foreground))] italic border border-dashed border-[hsl(var(--border))] rounded-lg">No reports yet. Upload a file to begin.</div>}
          </div>
        </div>
      </div>

      {/* Report Detail View */}
      {selectedReport && (
        <div className="card overflow-hidden border border-[hsl(var(--border))] animate-fade-in shadow-2xl">
          {/* Header */}
          <div className="bg-[hsl(var(--secondary))] px-5 py-4 border-b border-[hsl(var(--border))] flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-3">
              {selectedReport.verdict === 'clean' ? <ShieldCheck size={20} className="text-emerald-400" /> : <ShieldAlert size={20} className="text-red-400" />}
              <div>
                <h3 className="font-mono text-base font-bold text-white">{selectedReport.filename}</h3>
                <div className="flex items-center gap-2 mt-1">
                  <span className={cn('px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider', verdictBadge(selectedReport.verdict))}>{selectedReport.verdict}</span>
                  <span className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase">Score <span className="font-mono text-white">{selectedReport.score}</span></span>
                </div>
              </div>
            </div>
            <div className="ml-auto text-right">
              <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))] mb-0.5">SHA256</div>
              <div className="font-mono text-xs text-white bg-[hsl(var(--background))] px-2 py-1 rounded border border-[hsl(var(--border))]">{selectedReport.sha256}</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4">
            {/* File Tree */}
            <div className="lg:col-span-1 border-r border-[hsl(var(--border))] p-3 max-h-[600px] overflow-y-auto bg-[hsl(var(--card))]">
              <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-2 px-2">File Hierarchy</h4>
              <div className="space-y-0.5">
                {(selectedReport.files || []).slice(0, 300).map((f: any) => (
                  <button key={f.path} onClick={() => setActivePath(f.path)} className={cn('w-full flex items-center gap-2 text-left rounded-md px-2 py-1.5 text-xs font-mono truncate transition-colors', f.path === (activeFile?.path || '') ? 'bg-[hsl(var(--primary)/0.15)] text-[hsl(var(--primary))] font-semibold' : 'text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--secondary))] hover:text-white')}>
                    {f.kind === 'binary' ? <Package size={14} className="shrink-0" /> : <FileText size={14} className="shrink-0" />}
                    <span className="truncate">{f.path}</span>
                    {typeof f.score === 'number' && f.score > 0 && <span className="ml-auto shrink-0 bg-orange-500/20 text-orange-400 px-1.5 rounded text-[9px] font-bold">{f.score}</span>}
                  </button>
                ))}
              </div>
            </div>

            {/* Content Viewer */}
            <div className="lg:col-span-3 p-5 bg-[hsl(var(--background))]">
              {!activeFile ? (
                <div className="h-full flex items-center justify-center text-sm text-[hsl(var(--muted-foreground))] italic">Select a file from the tree to view contents.</div>
              ) : activeFile.kind === 'binary' || activeFile.kind === 'blocked' ? (
                <div className="h-full flex flex-col max-w-2xl mx-auto space-y-6 pt-4">
                  <div className="flex flex-col items-center justify-center text-center">
                    <div className="w-16 h-16 rounded-2xl bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] flex items-center justify-center text-[hsl(var(--muted-foreground))] mb-4">
                      <Package size={32} />
                    </div>
                    <h4 className="text-white font-bold mb-2">{activeFile.kind === 'blocked' ? 'Viewer Restricted (Anti-crack Policy)' : 'Binary Executable Analysis'}</h4>
                    <p className="text-sm text-[hsl(var(--muted-foreground))]">{activeFile.note}</p>
                    {activeFile.sha256 && <div className="font-mono text-xs bg-[hsl(var(--secondary))] px-3 py-1.5 rounded-lg border border-[hsl(var(--border))] text-cyan-400 mt-4">sha256: {activeFile.sha256}</div>}
                  </div>
                  
                  {activeFile.format && activeFile.format !== 'unknown' && (
                     <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                       <div className="bg-[hsl(var(--secondary))] p-3 rounded border border-[hsl(var(--border))] text-center">
                         <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))]">Format</div>
                         <div className="font-mono text-sm text-white mt-1">{activeFile.format.toUpperCase()}</div>
                       </div>
                       {activeFile.arch && (
                       <div className="bg-[hsl(var(--secondary))] p-3 rounded border border-[hsl(var(--border))] text-center">
                         <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))]">Architecture</div>
                         <div className="font-mono text-sm text-white mt-1">{activeFile.arch}</div>
                       </div>
                       )}
                       {activeFile.entropy !== undefined && (
                       <div className="bg-[hsl(var(--secondary))] p-3 rounded border border-[hsl(var(--border))] text-center">
                         <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))]">Entropy</div>
                         <div className={cn("font-mono text-sm mt-1", activeFile.entropy > 7.0 ? "text-red-400" : "text-white")}>{activeFile.entropy}</div>
                       </div>
                       )}
                       {activeFile.pe_type && (
                       <div className="bg-[hsl(var(--secondary))] p-3 rounded border border-[hsl(var(--border))] text-center">
                         <div className="text-[10px] uppercase font-bold text-[hsl(var(--muted-foreground))]">PE Type</div>
                         <div className="font-mono text-sm text-white mt-1">{activeFile.pe_type}</div>
                       </div>
                       )}
                     </div>
                  )}

                  {/* Findings (Binary) */}
                  {(activeFile.findings || []).length > 0 && (
                    <div>
                      <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-3">Static Analysis Findings</h4>
                      <div className="space-y-2">
                        {(activeFile.findings || []).map((fd: any, i: number) => (
                          <div key={i} className={cn('px-3 py-2 rounded-md text-xs font-mono border flex flex-col', fd.severity === 'high' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20')}>
                            <span className="font-bold uppercase tracking-wide">{fd.type}</span>
                            <span className="mt-1 opacity-90 whitespace-pre-wrap">{fd.detail || fd.match}</span>
                            {fd.mitre && <span className="mt-2 inline-block px-2 py-0.5 rounded bg-black/30 w-fit text-[10px]">{fd.mitre}</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Extracted IOCs (Binary) */}
                  {activeFile.iocs && Object.keys(activeFile.iocs).length > 0 && (
                    <div>
                      <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-3">Extracted IOCs (Network / Registry)</h4>
                      <div className="space-y-3">
                        {Object.entries(activeFile.iocs).map(([type, values]: [string, any], i) => (
                          <div key={i}>
                            <div className="text-[10px] font-bold text-[hsl(var(--muted-foreground))] uppercase mb-1">{type}</div>
                            <div className="flex flex-wrap gap-2">
                              {values.map((v: string, j: number) => (
                                <span key={j} className="px-2 py-1 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] text-xs font-mono text-cyan-400 break-all">{v.replace(/\./g, '[.]')}</span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {/* Suspicious Imports (PE) */}
                  {activeFile.imports_suspicious && activeFile.imports_suspicious.length > 0 && (
                    <div>
                      <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-3">Suspicious PE Imports</h4>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {activeFile.imports_suspicious.map((imp: any, i: number) => (
                          <div key={i} className="flex flex-col px-3 py-2 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] text-xs font-mono">
                            <span className="text-white font-bold">{imp.function}</span>
                            <span className="text-[10px] text-[hsl(var(--muted-foreground))] mt-1">{imp.capability} ({imp.mitre})</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Findings */}
                  {(activeFile.findings || []).length > 0 && (
                    <div>
                      <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-2">Security Findings</h4>
                      <div className="flex flex-wrap gap-2">
                        {(activeFile.findings || []).map((fd: any, i: number) => (
                          <span key={i} className={cn('px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wide border', fd.severity === 'high' ? 'bg-red-500/10 text-red-400 border-red-500/20' : fd.severity === 'medium' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20')}>
                            {fd.type}: {fd.pattern || fd.match} {fd.count ? `(${fd.count})` : ''}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Code Viewer */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))]">File Preview</h4>
                      <span className="text-[10px] text-[hsl(var(--muted-foreground))]">First 20k chars • Secrets redacted server-side</span>
                    </div>
                    <div className="rounded-lg bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] overflow-hidden">
                      <pre className="text-xs font-mono text-slate-300 overflow-auto max-h-[440px] p-0 m-0">
                        {(activeFile.preview || '(empty)').split('\n').slice(0, 800).map((line: string, i: number) => (
                          <div key={i} className="flex hover:bg-white/5 transition-colors group">
                            <span className="w-12 shrink-0 select-none text-right pr-3 py-0.5 text-slate-600 border-r border-slate-700 mr-3 group-hover:text-slate-400 bg-black/20">{i + 1}</span>
                            <span className="whitespace-pre-wrap break-all pr-4 py-0.5">{line || '\n'}</span>
                          </div>
                        ))}
                      </pre>
                    </div>
                  </div>
                </div>
              )}

              {/* SBOM lite */}
              {selectedReport.sbom?.packages?.length > 0 && (
                <div className="mt-6 border-t border-[hsl(var(--border))] pt-4">
                  <h4 className="text-[10px] uppercase font-bold tracking-widest text-[hsl(var(--muted-foreground))] mb-3">SBOM Manifests ({selectedReport.sbom.packages.length})</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedReport.sbom.packages.map((p: any, i: number) => (
                      <span key={i} className="px-2 py-1 rounded bg-[hsl(var(--secondary))] border border-[hsl(var(--border))] font-mono text-[10px] text-[hsl(var(--muted-foreground))]">{p.manifest}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
          
          {/* Analysis Engines Status */}
          {selectedReport.engines && (
            <div className="bg-[hsl(var(--secondary))] px-5 py-3 border-t border-[hsl(var(--border))] flex items-center gap-6 overflow-x-auto text-[10px] font-mono text-[hsl(var(--muted-foreground))]">
              <span className="uppercase font-bold tracking-widest mr-2">Engines:</span>
              <span className={cn(selectedReport.engines.pe_parser?.enabled ? 'text-cyan-400' : '')}>[PE: {selectedReport.engines.pe_parser?.enabled ? 'ON' : 'OFF'}]</span>
              <span className={cn(selectedReport.engines.elf_parser?.enabled ? 'text-cyan-400' : '')}>[ELF: {selectedReport.engines.elf_parser?.enabled ? 'ON' : 'OFF'}]</span>
              <span className={cn(selectedReport.engines.macho_parser?.enabled ? 'text-cyan-400' : '')}>[MACH-O: {selectedReport.engines.macho_parser?.enabled ? 'ON' : 'OFF'}]</span>
              <span className={cn(selectedReport.engines.office_parser?.enabled ? 'text-cyan-400' : '')}>[OFFICE: {selectedReport.engines.office_parser?.enabled ? 'ON' : 'OFF'}]</span>
              <span className={cn(selectedReport.engines.pdf_parser?.enabled ? 'text-cyan-400' : '')}>[PDF: {selectedReport.engines.pdf_parser?.enabled ? 'ON' : 'OFF'}]</span>
              <span className={cn(selectedReport.engines.archive_parser?.enabled ? 'text-cyan-400' : '')}>[ARCH: {selectedReport.engines.archive_parser?.enabled ? 'ON' : 'OFF'}]</span>
              <span className={cn(selectedReport.engines.strings_scan?.enabled ? 'text-cyan-400' : '')}>[STR: ON]</span>
              <span className={cn(selectedReport.engines.secret_scan?.enabled ? 'text-cyan-400' : '')}>[SECRETS: {selectedReport.engines.secret_scan?.patterns || 0}]</span>
              {selectedReport.engines.iocs_found && Object.keys(selectedReport.engines.iocs_found).length > 0 && (
                 <span className="text-yellow-400 font-bold">[IOCs: FOUND]</span>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
