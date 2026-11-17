import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileText, Globe, Loader2, Plus, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react';
import { Card, Tile } from './HostPanel';

interface Entry { value: string; comment: string; createdAt: string; expiration: string }
interface ParserWhitelist { file: string; name: string; description: string; reason: string; ips: string[] | null; cidrs: string[] | null; expressions: string[] | null; fromHub: boolean }
interface Data { allowlist: { name: string; entries: Entry[] }; parsers: ParserWhitelist[] }

const DYNDNS_TAG = 'dyndns:'; // entries kept up to date for a dynamic DNS hostname

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
  const manual = data.allowlist.entries.filter((e) => !e.comment?.startsWith(DYNDNS_TAG));

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <Tile label="Your allowlist" value={String(manual.length)} sub="IPs and ranges CowSec never bans" tone="emerald" icon={<ShieldCheck className="w-4 h-4" />} />
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
        {manual.length === 0 ? (
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
              {manual.map((e) => (
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

      <DynDnsCard onChange={load} />

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

interface DynHost { name: string; v6prefix: number; addresses: string[]; lastChecked?: string; error?: string | null }
interface DynData { hosts: DynHost[]; history: { time: string; added: string[]; removed: string[]; hosts: string[] }[]; maxHosts: number; expiryMinutes: number; netfilterSync: boolean }

function ago(iso?: string) {
  if (!iso) return 'not yet';
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  return s < 90 ? `${s}s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : new Date(iso).toLocaleString();
}

// Hostnames whose addresses (a home connection's changing IP) CowSec keeps trusted.
function DynDnsCard({ onChange }: { onChange: () => void }) {
  const [d, setD] = useState<DynData | null>(null);
  const [name, setName] = useState('');
  const [v6prefix, setV6prefix] = useState(64);
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const call = async (key: string, url: string, init?: RequestInit) => {
    setBusy(key);
    setMsg(null);
    try {
      const res = await fetch(url, { cache: 'no-store', ...init });
      if (!res.ok) throw new Error((await res.text()).trim());
      setD(await res.json());
      if (init) onChange();
      return true;
    } catch (err) {
      setMsg({ ok: false, text: String(err instanceof Error ? err.message : err) });
      return false;
    } finally {
      setBusy('');
    }
  };
  useEffect(() => { call('load', '/api/crowdsec/dyndns'); }, []);

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    const n = name.trim().toLowerCase();
    if (await call('add', '/api/crowdsec/dyndns', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: n, v6prefix }) })) {
      setMsg({ ok: true, text: `${n} is trusted now, and checked every minute.` });
      setName('');
    }
  };

  return (
    <Card
      title="Dynamic DNS hostnames"
      icon={<Globe className="w-4 h-4 text-sky-400" />}
      right={d && d.hosts.length > 0 && (
        <button onClick={() => call('check', '/api/crowdsec/dyndns/check', { method: 'POST' })} disabled={!!busy}
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-300 border border-slate-700 rounded-lg px-2.5 py-1 hover:bg-white/5 cursor-pointer">
          <RefreshCw className={`w-3.5 h-3.5 ${busy === 'check' ? 'animate-spin' : ''}`} /> Check now
        </button>
      )}
    >
      <p className="text-xs text-slate-400">
        For a home connection whose address changes. Point a dynamic DNS name at it (most routers can update one), add the name here, and CowSec looks it up
        every minute and keeps its current addresses in the trusted herd. A new address is unbanned straight away; an old one is dropped when the name moves on,
        and every entry lapses after {d?.expiryMinutes ?? 60} minutes unless the next check renews it.
      </p>
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-3 space-y-1.5 text-[11px] text-amber-100/90">
        <p className="flex items-center gap-1.5 font-semibold text-amber-200"><AlertTriangle className="w-3.5 h-3.5" /> Before you add one</p>
        <p>Whoever can change this DNS record decides who CowSec trusts. Protect the dynamic DNS account with a strong password and two-factor sign-in.</p>
        <p>If your provider uses carrier-grade NAT (CGNAT), your public IPv4 address is shared with other customers, and trusting it trusts them too. Your router's WAN address starting 100.64–100.127 is a sign of it.</p>
        <p>Trusted addresses are never banned for anything, including by community blocklists, so a compromised device at home would be trusted too.</p>
      </div>
      <form onSubmit={add} className="flex flex-wrap items-end gap-3">
        <label className="space-y-1">
          <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500">Hostname</span>
          <input value={name} onChange={(e) => setName(e.target.value.trim())} placeholder="home.example-dyndns.org"
            className="w-72 bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-sky-500" />
        </label>
        <div className="space-y-1">
          <span className="block text-[11px] font-semibold uppercase tracking-wider text-slate-500">IPv6</span>
          <div className="flex rounded-lg border border-slate-700 overflow-hidden text-xs font-semibold">
            {[{ v: 64, label: 'Whole home network (/64)' }, { v: 128, label: 'Exact address' }].map((o) => (
              <button type="button" key={o.v} onClick={() => setV6prefix(o.v)}
                className={`px-2.5 py-1.5 cursor-pointer ${v6prefix === o.v ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>{o.label}</button>
            ))}
          </div>
        </div>
        <button type="submit" disabled={!name || !!busy || (d ? d.hosts.length >= d.maxHosts : false)}
          className="inline-flex items-center space-x-1.5 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-400 text-white text-sm font-semibold rounded-lg px-3 py-1.5 cursor-pointer">
          {busy === 'add' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          <span>Trust this hostname</span>
        </button>
      </form>
      <p className="text-[11px] text-slate-500 -mt-1">
        IPv6: devices at home each use their own address inside the network's /64, not the one in the DNS record, so trusting the /64 is usually what you want.
      </p>
      {msg && (
        <p className={`text-xs flex items-center space-x-1.5 ${msg.ok ? 'text-emerald-300' : 'text-rose-300'}`}>
          {msg.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
          <span>{msg.text}</span>
        </p>
      )}
      {d && d.hosts.length > 0 && (
        <div className="space-y-2">
          {d.hosts.map((h) => (
            <div key={h.name} className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/40 px-3 py-2.5">
              <div className="min-w-0 flex-1">
                <p className="font-mono text-sm text-white">{h.name}</p>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(h.addresses || []).map((a) => (
                    <span key={a} className="text-[10px] font-mono bg-slate-900 border border-slate-800 rounded px-1.5 py-0.5 text-slate-300">{a}</span>
                  ))}
                </div>
                {h.error && <p className="text-[11px] text-amber-300 mt-1">Last check: {h.error}. The addresses above stay trusted until they lapse.</p>}
              </div>
              <span className="text-[11px] text-slate-500">checked {ago(h.lastChecked)}</span>
              <button onClick={() => call(h.name, `/api/crowdsec/dyndns?name=${encodeURIComponent(h.name)}`, { method: 'DELETE' })} disabled={!!busy}
                className="p-1 rounded text-slate-500 hover:text-rose-300 hover:bg-rose-950/50 cursor-pointer" aria-label={`Stop trusting ${h.name}`}>
                {busy === h.name ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
              </button>
            </div>
          ))}
        </div>
      )}
      {d && !d.netfilterSync && d.hosts.length > 0 && (
        <p className="text-[11px] text-slate-400">mailcow's own netfilter doesn't follow the trusted herd on this server. Turn on "Keep netfilter's whitelist in step" under Guard Dog so it never bans these addresses either.</p>
      )}
      {d && d.history.length > 0 && (
        <div className="space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Recent changes</p>
          {d.history.slice(0, 5).map((e, i) => (
            <p key={i} className="text-[11px] text-slate-400">
              <span className="text-slate-500">{new Date(e.time).toLocaleString()}</span> · {e.hosts.join(', ')}
              {e.added.length > 0 && <span className="text-emerald-300"> · trusted {e.added.join(', ')}</span>}
              {e.removed.length > 0 && <span className="text-rose-300"> · dropped {e.removed.join(', ')}</span>}
            </p>
          ))}
        </div>
      )}
    </Card>
  );
}
