import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileText, Loader2, Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { Card, Tile } from './HostPanel';

interface Entry { value: string; comment: string; createdAt: string; expiration: string }
interface ParserWhitelist { file: string; name: string; description: string; reason: string; ips: string[] | null; cidrs: string[] | null; expressions: string[] | null; fromHub: boolean }
interface Data { allowlist: { name: string; entries: Entry[] }; parsers: ParserWhitelist[] }

export default function WhitelistsPanel() {
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState('');
  const [value, setValue] = useState('');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const load = async () => {
    try {
      const res = await fetch('/api/crowdsec/whitelists', { cache: 'no-store' });
      if (!res.ok) throw new Error(await res.text());
      setData(await res.json());
      setError('');
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };
  useEffect(() => {
    load();
  }, []);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy('add');
    setMsg(null);
    try {
      const res = await fetch('/api/crowdsec/whitelists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value, reason }),
      });
      if (!res.ok) throw new Error(await res.text());
      setMsg({ ok: true, text: `${value} is now part of the trusted herd.` });
      setValue('');
      setReason('');
      await load();
    } catch (err) {
      setMsg({ ok: false, text: String(err instanceof Error ? err.message : err) });
    } finally {
      setBusy('');
    }
  };

  const remove = async (v: string) => {
    setBusy(v);
    setMsg(null);
    try {
      const res = await fetch(`/api/crowdsec/whitelists?value=${encodeURIComponent(v)}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(await res.text());
      await load();
    } catch (err) {
      setMsg({ ok: false, text: String(err instanceof Error ? err.message : err) });
    } finally {
      setBusy('');
    }
  };

  if (error && !data) {
    return (
      <div className="flex items-center space-x-2 text-rose-300 bg-rose-950/40 border border-rose-900 rounded-xl p-4 text-sm">
        <AlertTriangle className="w-4 h-4" />
        <span>Couldn't read the trusted herd: {error}</span>
      </div>
    );
  }
  if (!data) {
    return (
      <div className="flex items-center space-x-2 text-slate-400 text-sm p-6">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Counting the trusted herd…</span>
      </div>
    );
  }

  const parserValues = data.parsers.reduce((n, p) => n + (p.ips?.length ?? 0) + (p.cidrs?.length ?? 0), 0);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <Tile label="Your allowlist" value={String(data.allowlist.entries.length)} sub="IPs and ranges CowSec never bans" tone="emerald" icon={<ShieldCheck className="w-4 h-4" />} />
        <Tile label="Whitelist parsers" value={String(data.parsers.length)} sub={`${parserValues} IPs/ranges, plus expressions`} tone="sky" icon={<FileText className="w-4 h-4" />} />
        <Tile label="How it works" value="Allowlist" sub="checked by CrowdSec's API: also filters community blocklists" tone="indigo" icon={<CheckCircle2 className="w-4 h-4" />} />
      </div>

      <Card title="Trusted herd (CowSec allowlist)" icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}>
        <p className="text-xs text-slate-400">
          Add your own static IPs, office ranges or monitoring services. Entries take effect immediately (no reload), stop local detections from banning them, and remove them from community and third-party blocklists.
        </p>
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <label className="space-y-1">
            <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500">IP or CIDR</span>
            <input
              value={value}
              onChange={(e) => setValue(e.target.value.trim())}
              placeholder="203.0.113.10 or 198.51.100.0/24"
              className="w-64 bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-emerald-500"
            />
          </label>
          <label className="space-y-1 flex-1 min-w-48">
            <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500">Reason (optional)</span>
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. office VPN"
              maxLength={200}
              className="w-full bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-emerald-500"
            />
          </label>
          <button
            type="submit"
            disabled={!value || busy === 'add'}
            className="inline-flex items-center space-x-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-400 text-white text-sm font-semibold rounded-lg px-3 py-1.5 cursor-pointer"
          >
            {busy === 'add' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            <span>Add to herd</span>
          </button>
        </form>
        {msg && (
          <p className={`text-xs flex items-center space-x-1.5 ${msg.ok ? 'text-emerald-300' : 'text-rose-300'}`}>
            {msg.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            <span>{msg.text}</span>
          </p>
        )}
        {data.allowlist.entries.length === 0 ? (
          <p className="text-xs text-slate-500">No entries yet. Your local network is already covered by the whitelist parser below.</p>
        ) : (
          <table className="w-full text-xs">
            <thead className="text-slate-500 text-left">
              <tr>
                <th className="py-1 font-semibold">IP / range</th>
                <th className="py-1 font-semibold">Reason</th>
                <th className="py-1 font-semibold">Added</th>
                <th />
              </tr>
            </thead>
            <tbody className="text-slate-300">
              {data.allowlist.entries.map((e) => (
                <tr key={e.value} className="border-t border-slate-800/60">
                  <td className="py-1.5 font-mono">{e.value}</td>
                  <td className="py-1.5 text-slate-400">{e.comment || '—'}</td>
                  <td className="py-1.5 text-slate-500">{new Date(e.createdAt).toLocaleDateString()}</td>
                  <td className="py-1.5 text-right">
                    <button onClick={() => remove(e.value)} disabled={busy === e.value} className="p-1 rounded text-slate-500 hover:text-rose-300 hover:bg-rose-950/50 cursor-pointer" aria-label={`Remove ${e.value}`}>
                      {busy === e.value ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Whitelist parsers (read only)" icon={<FileText className="w-4 h-4 text-sky-400" />}>
        <p className="text-xs text-slate-400">Parser files in /etc/crowdsec/parsers/s02-enrich that drop matching events before any scenario sees them.</p>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {data.parsers.map((p) => (
            <div key={p.file} className="bg-slate-950/50 border border-slate-800 rounded-xl p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs text-white">{p.name || p.file}</span>
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${p.fromHub ? 'bg-sky-950/60 text-sky-300' : 'bg-amber-950/60 text-amber-300'}`}>{p.fromHub ? 'hub' : 'local'}</span>
              </div>
              {p.description && <p className="text-[11px] text-slate-400">{p.description}</p>}
              <div className="flex flex-wrap gap-1">
                {[...(p.ips ?? []), ...(p.cidrs ?? [])].map((v) => (
                  <span key={v} className="text-[10px] font-mono bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-slate-300">{v}</span>
                ))}
              </div>
              {(p.expressions ?? []).length > 0 && <p className="text-[10px] text-slate-500">{p.expressions!.length} expression rule{p.expressions!.length > 1 ? 's' : ''}</p>}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
