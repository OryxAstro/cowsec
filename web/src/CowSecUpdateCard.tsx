// Fresh Hay: CowSec's own updates from its GitHub releases. The optional access token
// (for a private repository) is write-only here: the server never sends it back.
import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, ChevronDown, ExternalLink, KeyRound, Loader2, RefreshCw, Rocket, Settings2, ShieldCheck, Trash2 } from 'lucide-react';
import { Card } from './HostPanel';
import CowSecLogo from './CowSecLogo';

interface Release {
  repo: string; tokenSet: boolean; installed: string | null; checked: string; error: string | null; updateAvailable: boolean;
  latest: { tag: string; name: string; published: string; notes: string; url: string; version: string; deb: { size?: number } } | null;
}

const btn = 'inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-1.5 cursor-pointer disabled:opacity-40';
const input = 'bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-sky-500';

export default function CowSecUpdateCard({ busy, onUpdate }: { busy: boolean; onUpdate: () => void }) {
  const [rel, setRel] = useState<Release | null>(null);
  const [checking, setChecking] = useState(false);
  const [notes, setNotes] = useState(false);
  const [source, setSource] = useState(false);
  const [repo, setRepo] = useState('');
  const [token, setToken] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = useCallback(async (refresh = false) => {
    setChecking(true);
    try {
      const r = await fetch(`/api/crowdsec/host/cowsec-release${refresh ? '?refresh=1' : ''}`, { cache: 'no-store' });
      if (!r.ok) throw new Error(await r.text());
      const d: Release = await r.json();
      setRel(d);
      setRepo((x) => x || d.repo);
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    } finally {
      setChecking(false);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const saveSource = async (body: Record<string, unknown>) => {
    setMsg(null);
    const r = await fetch('/api/crowdsec/host/cowsec-update-source', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) return setMsg({ ok: false, text: (await r.text()).trim() });
    setToken('');
    setMsg({ ok: true, text: 'Release source saved' });
    load(true);
  };

  return (
    <Card title="CowSec" icon={<CowSecLogo className="w-5 h-5" />}
      right={<button onClick={() => load(true)} disabled={checking || busy} className={`${btn} text-sky-300 border border-sky-800 hover:bg-sky-950`}>
        <RefreshCw className={`w-3.5 h-3.5 ${checking ? 'animate-spin' : ''}`} /> Check for a new release</button>}>
      {!rel ? <p className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Checking…</p> : (
        <div className="space-y-4">
          <div className="grid sm:grid-cols-3 gap-3 text-sm">
            <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Installed</p>
              <p className="font-mono text-white break-all">{rel.installed ?? '—'}</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3">
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Latest release</p>
              <p className="font-mono text-white break-all">{rel.latest ? rel.latest.version : '—'}</p>
              {rel.latest && <p className="text-[11px] text-slate-500">{rel.latest.tag} · {new Date(rel.latest.published).toLocaleDateString()}</p>}
            </div>
            <div className={`rounded-xl border p-3 ${rel.updateAvailable ? 'border-amber-500/40 bg-amber-500/10' : 'border-emerald-500/30 bg-emerald-500/5'}`}>
              <p className="text-[11px] uppercase tracking-wider text-slate-500">Status</p>
              <p className={`font-semibold ${rel.updateAvailable ? 'text-amber-200' : 'text-emerald-300'}`}>
                {rel.error ? 'Can\'t check' : rel.updateAvailable ? 'Update ready' : 'Up to date'}
              </p>
              <p className="text-[11px] text-slate-500">checked {new Date(rel.checked).toLocaleString()}</p>
            </div>
          </div>
          {rel.error && <p className="text-sm text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded-xl px-3 py-2">{rel.error}</p>}
          {rel.latest && (
            <div>
              <button onClick={() => setNotes(!notes)} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white cursor-pointer">
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${notes ? 'rotate-180' : ''}`} /> What's new in {rel.latest.name}
              </button>
              {notes && (
                <div className="mt-2 rounded-xl border border-slate-800 bg-slate-950/40 p-3 text-xs text-slate-300 whitespace-pre-wrap max-h-64 overflow-y-auto cs-page">
                  {rel.latest.notes || 'No release notes.'}
                  <a href={rel.latest.url} target="_blank" rel="noreferrer" className="mt-2 flex items-center gap-1 text-sky-300 hover:text-white">Open on GitHub <ExternalLink className="w-3 h-3" /></a>
                </div>
              )}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={onUpdate} disabled={!rel.updateAvailable || busy}
              className={`${btn} px-4 py-2 text-sm text-white bg-gradient-to-r from-indigo-600 to-sky-600 hover:from-indigo-500 hover:to-sky-500`}>
              <Rocket className="w-4 h-4" /> Update CowSec{rel.latest && rel.updateAvailable ? ` to ${rel.latest.version}` : ''}
            </button>
            <p className="text-[11px] text-slate-500 flex items-center gap-1"><ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> Checked against the release's SHA-256 before installing. Only the console restarts; mail and protection keep running.</p>
          </div>
          <div className="border-t border-slate-800 pt-3">
            <button onClick={() => setSource(!source)} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white cursor-pointer">
              <Settings2 className="w-3.5 h-3.5" /> Release source: <span className="font-mono">{rel.repo}</span>
              {rel.tokenSet && <span className="ml-1 inline-flex items-center gap-1 text-emerald-300"><KeyRound className="w-3 h-3" /> token set</span>}
            </button>
            {source && (
              <div className="mt-3 grid sm:grid-cols-[1fr_1.4fr_auto] gap-2 items-end cs-page">
                <label className="flex flex-col gap-1 text-xs text-slate-400">GitHub repository
                  <input className={input} value={repo} onChange={(e) => setRepo(e.target.value.trim())} placeholder="owner/name" />
                </label>
                <label className="flex flex-col gap-1 text-xs text-slate-400">Read-only token (only for a private repository)
                  <input className={`${input} font-mono`} type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off"
                    placeholder={rel.tokenSet ? 'A token is saved; paste a new one to replace it' : 'github_pat_…'} />
                </label>
                <div className="flex gap-2">
                  <button onClick={() => saveSource({ repo, ...(token ? { token } : {}) })} className={`${btn} bg-sky-600 hover:bg-sky-500 text-white`}><CheckCircle2 className="w-3.5 h-3.5" /> Save</button>
                  {rel.tokenSet && <button onClick={() => saveSource({ repo, clearToken: true })} className={`${btn} text-slate-400 hover:text-rose-300`} title="Remove the saved token"><Trash2 className="w-3.5 h-3.5" /></button>}
                </div>
                <p className="sm:col-span-3 text-[11px] text-slate-500">Create a fine-grained token with read-only <b>Contents</b> access to this one repository. It is stored root-only on the server and never shown again.</p>
              </div>
            )}
          </div>
          {msg && <p className={`text-sm ${msg.ok ? 'text-emerald-300' : 'text-rose-300'}`}>{msg.text}</p>}
        </div>
      )}
    </Card>
  );
}
