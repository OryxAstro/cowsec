// Folder picker for the server's filesystem (directories only, system folders blocked by
// the helper). Used to choose where mailcow backups go.
import { useEffect, useState } from 'react';
import { ArrowUp, ChevronRight, Folder, FolderOpen, FolderPlus, HardDrive, Loader2, X } from 'lucide-react';

interface Listing {
  path: string; parent: string | null; crumbs: { name: string; path: string }[];
  dirs: { name: string; path: string; selectable: boolean; hidden: boolean }[];
  selectable: boolean; freeBytes: number; totalBytes: number;
}

const gb = (n: number) => (n >= 1e12 ? `${(n / 1e12).toFixed(1)} TB` : `${(n / 1e9).toFixed(1)} GB`);

export default function FolderPicker({ start, onPick, onClose }: { start: string; onPick: (path: string) => void; onClose: () => void }) {
  const [path, setPath] = useState(start);
  const [data, setData] = useState<Listing | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showHidden, setShowHidden] = useState(false);
  const [newName, setNewName] = useState('');

  const load = async (p: string) => {
    setLoading(true);
    setError('');
    try {
      const r = await fetch(`/api/crowdsec/host/fs?path=${encodeURIComponent(p)}`, { cache: 'no-store' });
      if (!r.ok) {
        // A default that doesn't exist yet: show its nearest existing parent.
        const parent = p.replace(/\/[^/]+\/?$/, '') || '/';
        if (parent !== p) return load(parent);
        throw new Error(await r.text());
      }
      const d: Listing = await r.json();
      setData(d);
      setPath(d.path);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load(start);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const mkdir = async () => {
    setError('');
    const r = await fetch('/api/crowdsec/host/fs/mkdir', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ path: `${path.replace(/\/$/, '')}/${newName}` }) });
    if (!r.ok) return setError(await r.text());
    const d: Listing = await r.json();
    setData(d);
    setPath(d.path);
    setNewName('');
  };

  const dirs = (data?.dirs || []).filter((d) => showHidden || !d.hidden);
  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl cs-pop" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <h3 className="font-bold text-white flex items-center gap-2"><FolderOpen className="w-5 h-5 text-amber-400" /> Choose a backup folder</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-white cursor-pointer"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-5 py-3 flex items-center gap-1 flex-wrap text-xs border-b border-slate-800">
          <button onClick={() => load('/')} className="px-1.5 py-0.5 rounded hover:bg-slate-800 text-slate-300 cursor-pointer"><HardDrive className="w-3.5 h-3.5" /></button>
          {data?.crumbs.map((c) => (
            <span key={c.path} className="flex items-center gap-1">
              <ChevronRight className="w-3 h-3 text-slate-600" />
              <button onClick={() => load(c.path)} className="px-1.5 py-0.5 rounded hover:bg-slate-800 text-slate-200 font-mono cursor-pointer">{c.name}</button>
            </span>
          ))}
          {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-500 ml-2" />}
        </div>
        <div className="h-80 overflow-auto px-3 py-2">
          {data?.parent && (
            <button onClick={() => load(data.parent!)} className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-slate-400 hover:bg-slate-800 cursor-pointer"><ArrowUp className="w-4 h-4" /> ..</button>
          )}
          <div className="cs-stagger" key={data?.path}>
            {dirs.map((d) => (
              <button key={d.path} onClick={() => load(d.path)} className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm cursor-pointer ${d.selectable ? 'text-slate-200 hover:bg-slate-800' : 'text-slate-500 hover:bg-slate-800/50'}`}>
                <Folder className={`w-4 h-4 ${d.selectable ? 'text-amber-400' : 'text-slate-600'}`} />
                <span className="font-mono">{d.name}</span>
                {!d.selectable && <span className="ml-auto text-[10px] text-slate-600">system</span>}
              </button>
            ))}
            {data && dirs.length === 0 && <p className="text-xs text-slate-500 px-3 py-4">No sub-folders here.</p>}
          </div>
        </div>
        <div className="px-5 py-3 border-t border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-xs">
            <FolderPlus className="w-4 h-4 text-slate-400" />
            <input value={newName} onChange={(e) => setNewName(e.target.value.replace(/[^A-Za-z0-9._-]/g, ''))} placeholder="new folder name"
              className="bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white font-mono w-48 focus:outline-none focus:border-amber-500" />
            <button onClick={mkdir} disabled={!newName || !data?.selectable && path !== '/'} className="px-3 py-1.5 rounded-lg text-xs font-semibold text-amber-200 border border-amber-800 hover:bg-amber-950 disabled:opacity-40 cursor-pointer">Create here</button>
            <label className="ml-auto flex items-center gap-1.5 text-slate-400 cursor-pointer"><input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} /> hidden folders</label>
          </div>
          {error && <p className="text-xs text-rose-300">{error}</p>}
          <div className="flex items-center justify-between">
            <div className="text-xs text-slate-400">
              <p className="font-mono text-slate-200 break-all">{path}</p>
              {data && <p>{gb(data.freeBytes)} free of {gb(data.totalBytes)}</p>}
            </div>
            <button onClick={() => onPick(path)} disabled={!data?.selectable}
              className="px-4 py-2 rounded-xl text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-400 cursor-pointer">
              {data?.selectable ? 'Use this folder' : 'Pick another folder'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
