import React, { useState, useEffect } from 'react';
import { Globe, Search, History, ShieldAlert, Zap, Loader2, MapPin } from 'lucide-react';
import { osintAPI } from '../services/api';
import { useDashboard } from '../context/DashboardContext';

export default function SentinelX() {
    const { settings } = useDashboard();
    const [target, setTarget] = useState('');
    const [scanType, setScanType] = useState('ip');
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [history, setHistory] = useState([]);

    useEffect(() => {
        fetchHistory();
    }, []);

    const fetchHistory = async () => {
        try {
            const res = await osintAPI.getHistory({ limit: 10 });
            setHistory(res.data.items || []);
        } catch (err) {
            console.error("History fetch failed", err);
        }
    };

    const handleScan = async (e) => {
        e.preventDefault();
        if (!target.trim() || loading) return;

        setLoading(true);
        setResult(null);
        try {
            const isAuthenticated = true;
            const forceScan = true;
            const res = scanType === 'ip' 
                ? await osintAPI.ipLookup(target, forceScan)
                : await osintAPI.domainLookup(target, forceScan);
            setResult(res.data.data);
            fetchHistory();
        } catch (err) {
            console.error("Scan failed", err);
            const status = err?.response?.status;
            if (status === 401) {
                setResult({ error: 'Authentication required to start live OSINT scans. Please log in.' });
            } else if (status === 403) {
                setResult({ error: 'Insufficient role to trigger live OSINT scans.' });
            } else if (status === 503) {
                setResult({ error: err?.response?.data?.detail || 'OSINT provider not configured. Check server .env for API keys.' });
            } else {
                setResult({ error: err?.response?.data?.detail || 'Scan failed. Check backend logs.' });
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="space-y-8 text-slate-100">
            <div>
                <h2 className="text-3xl font-bold flex items-center gap-3 text-white">
                    <Globe className="text-purple-500" /> SentinelX Intelligence
                </h2>
                <p className="text-slate-400 mt-1">Cross-reference indicators with global OSINT providers</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                {/* Search Panel */}
                <div className="lg:col-span-1 space-y-6">
                    <div className={`p-6 rounded-xl border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
                        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4">New Investigation</h3>
                        <form onSubmit={handleScan} className="space-y-4">
                            <div className="flex bg-slate-800 p-1 rounded-lg">
                                <button 
                                    type="button"
                                    onClick={() => setScanType('ip')}
                                    className={`flex-1 py-1.5 text-xs font-bold rounded-md transition-all ${scanType === 'ip' ? 'bg-purple-600 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
                                >IP</button>
                                <button 
                                    type="button"
                                    onClick={() => setScanType('domain')}
                                    className={`flex-1 py-1.5 text-xs font-bold rounded-md transition-all ${scanType === 'domain' ? 'bg-purple-600 text-white shadow-lg' : 'text-slate-400 hover:text-slate-200'}`}
                                >DOMAIN</button>
                            </div>
                            <div className="relative">
                                <Search className="absolute left-3 top-3 text-slate-500" size={16}/>
                                <input 
                                    type="text"
                                    placeholder={scanType === 'ip' ? '8.8.8.8' : 'example.com'}
                                    className="w-full bg-slate-800 border-none rounded-lg pl-10 pr-4 py-2.5 text-sm focus:ring-1 focus:ring-purple-500 outline-none"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    required
                                />
                            </div>
                            <button 
                                type="submit"
                                disabled={loading}
                                className="w-full bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-bold py-2.5 rounded-lg hover:shadow-[0_0_15px_rgba(147,51,234,0.4)] transition-all flex items-center justify-center gap-2"
                            >
                                {loading ? <Loader2 size={18} className="animate-spin"/> : <Zap size={18}/>}
                                {loading ? 'Querying...' : 'Start Scan'}
                            </button>
                        </form>
                    </div>

                    <div className={`p-6 rounded-xl border ${settings.darkMode ? 'bg-slate-900 border-slate-700' : 'bg-white border-slate-200'}`}>
                        <h3 className="text-xs font-bold text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                            <History size={14}/> Recent Queries
                        </h3>
                        <div className="space-y-3">
                            {history.map((h, i) => (
                                <div key={i} className="flex items-center justify-between group cursor-pointer" onClick={() => {setTarget(h.query); setScanType(h.source);}}>
                                    <span className="text-xs font-mono text-slate-400 group-hover:text-purple-400 transition-colors">{h.query}</span>
                                    <span className="text-[9px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-500 uppercase">{h.source}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Results Panel */}
                <div className="lg:col-span-3">
                    {!result && !loading ? (
                        <div className="h-full min-h-[400px] border-2 border-dashed border-slate-800 rounded-xl flex flex-col items-center justify-center text-slate-600">
                            <Globe size={48} className="mb-4 opacity-10"/>
                            <p>No active investigation. Enter an indicator to begin.</p>
                        </div>
                    ) : loading ? (
                        <div className="h-full min-h-[400px] bg-slate-900/30 rounded-xl flex flex-col items-center justify-center">
                            <div className="relative">
                                <div className="w-16 h-16 border-4 border-purple-500/20 border-t-purple-500 rounded-full animate-spin"/>
                                <Globe className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-purple-500 animate-pulse" size={24}/>
                            </div>
                            <p className="mt-4 text-slate-500 animate-pulse font-mono text-sm tracking-tighter">Querying Global OSINT Mesh...</p>
                        </div>
                    ) : (
                            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                                {result?.error && (
                                    <div className="bg-red-900/20 border border-red-800 text-red-400 p-4 rounded-lg mb-4">
                                        {result.error}
                                    </div>
                                )}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {/* AbuseIPDB Card */}
                                <div className="bg-slate-900 border border-slate-700 rounded-xl p-6">
                                    <div className="flex justify-between items-center mb-6">
                                        <h4 className="font-bold text-orange-500 flex items-center gap-2 uppercase text-xs tracking-widest">
                                            <ShieldAlert size={16}/> AbuseIPDB Reputation
                                        </h4>
                                        <span className="text-[10px] text-slate-500">Confidence: 90%</span>
                                    </div>
                                    <div className="text-center py-8">
                                        <div className="text-6xl font-black text-white mb-2">
                                            {result.sources?.abuseipdb?.abuseConfidenceScore || 0}<span className="text-2xl text-slate-600">%</span>
                                        </div>
                                        <p className="text-xs text-slate-400 uppercase tracking-[0.2em]">Malicious Confidence Score</p>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-slate-800">
                                        <div>
                                            <div className="text-[10px] text-slate-500 uppercase">Country</div>
                                            <div className="text-sm font-bold flex items-center gap-2">
                                                <MapPin size={12}/> {result.sources?.shodan?.country || 'N/A'}
                                            </div>
                                        </div>
                                        <div>
                                            <div className="text-[10px] text-slate-500 uppercase">Total Reports</div>
                                            <div className="text-sm font-bold">{result.sources?.abuseipdb?.totalReports || 0}</div>
                                        </div>
                                    </div>
                                </div>

                                {/* Shodan Card */}
                                <div className="bg-slate-900 border border-slate-700 rounded-xl p-6">
                                    <div className="flex justify-between items-center mb-6">
                                        <h4 className="font-bold text-cyan-500 flex items-center gap-2 uppercase text-xs tracking-widest">
                                            <Globe size={16}/> Shodan Intelligence
                                        </h4>
                                        <span className="text-[10px] text-slate-500">Indexed via API</span>
                                    </div>
                                    <div className="space-y-4">
                                        <div className="flex justify-between items-center">
                                            <span className="text-xs text-slate-400">ISP / Organization</span>
                                            <span className="text-sm font-bold text-slate-200">{result.sources?.shodan?.isp || 'Unknown'}</span>
                                        </div>
                                        <div className="flex justify-between items-center">
                                            <span className="text-xs text-slate-400">Operating System</span>
                                            <span className="text-sm font-bold text-slate-200">{result.sources?.shodan?.os || 'Unknown'}</span>
                                        </div>
                                        <div className="flex justify-between items-center">
                                            <span className="text-xs text-slate-400">Open Ports</span>
                                            <div className="flex gap-1 flex-wrap justify-end">
                                                {(result.sources?.shodan?.ports || []).map(p => (
                                                    <span key={p} className="px-2 py-0.5 bg-cyan-900/30 text-cyan-400 rounded text-[10px] font-mono border border-cyan-800/30">{p}</span>
                                                ))}
                                                {!(result.sources?.shodan?.ports?.length) && <span className="text-xs text-slate-600 italic">None detected</span>}
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                {/* VirusTotal Card */}
                                <div className="bg-slate-900 border border-slate-700 rounded-xl p-6">
                                    <div className="flex justify-between items-center mb-6">
                                        <h4 className="font-bold text-green-500 flex items-center gap-2 uppercase text-xs tracking-widest">
                                            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg> VirusTotal
                                        </h4>
                                        <span className={`text-[10px] ${result.sources?.virustotal?.malicious ? 'text-red-500' : 'text-slate-500'}`}>
                                            {result.sources?.virustotal ? 'Scanned' : 'No API key'}
                                        </span>
                                    </div>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div className="text-center p-3 rounded-lg bg-red-900/20 border border-red-800/30">
                                            <div className="text-2xl font-black text-red-500">{result.sources?.virustotal?.malicious || 0}</div>
                                            <div className="text-[10px] text-red-400 uppercase tracking-wider">Malicious</div>
                                        </div>
                                        <div className="text-center p-3 rounded-lg bg-orange-900/20 border border-orange-800/30">
                                            <div className="text-2xl font-black text-orange-400">{result.sources?.virustotal?.suspicious || 0}</div>
                                            <div className="text-[10px] text-orange-400 uppercase tracking-wider">Suspicious</div>
                                        </div>
                                        <div className="text-center p-3 rounded-lg bg-green-900/20 border border-green-800/30">
                                            <div className="text-2xl font-black text-green-400">{result.sources?.virustotal?.harmless || 0}</div>
                                            <div className="text-[10px] text-green-400 uppercase tracking-wider">Harmless</div>
                                        </div>
                                        <div className="text-center p-3 rounded-lg bg-slate-800 border border-slate-700">
                                            <div className="text-2xl font-black text-slate-300">{result.sources?.virustotal?.undetected || 0}</div>
                                            <div className="text-[10px] text-slate-500 uppercase tracking-wider">Undetected</div>
                                        </div>
                                    </div>
                                    {result.sources?.virustotal?.reputation !== undefined && (
                                        <div className="mt-4 pt-4 border-t border-slate-800 flex justify-between items-center">
                                            <span className="text-xs text-slate-400">Reputation</span>
                                            <span className={`text-sm font-bold ${result.sources.virustotal.reputation >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                                                {result.sources.virustotal.reputation}
                                            </span>
                                        </div>
                                    )}
                                    {result.sources?.virustotal?.as_owner && (
                                        <div className="mt-2 flex justify-between items-center">
                                            <span className="text-xs text-slate-400">AS Owner</span>
                                            <span className="text-xs font-bold text-slate-200">{result.sources.virustotal.as_owner}</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
