// "The Farm": mailcow management through mailcow's API (domains, mailboxes, aliases,
// DKIM, quarantine, mail queue, logs, status). Every call goes to CowSec's validated
// /api/mailcow endpoints; CowSec's audit log records each change.
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  AlertTriangle, AtSign, Box, CheckCircle2, Copy, FileText, Globe, HardDrive, Inbox, KeyRound, Loader2,
  Pause, Play, Plus, RefreshCw, Search, Send, Server, ShieldAlert, Trash2, X,
} from 'lucide-react';
import { Card, Tile } from './HostPanel';

// ---------------------------------------------------------------- shared

type Result<T> = { data: T | null; error: string; loading: boolean; notConfigured: boolean; reload: () => void };

function useApi<T>(path: string | null): Result<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [notConfigured, setNotConfigured] = useState(false);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!path) return;
    let alive = true;
    setLoading(true);
    fetch(path, { cache: 'no-store' })
      .then(async (r) => {
        const body = await r.json().catch(() => ({}));
        if (!alive) return;
        if (r.status === 503 && body.configured === false) {
          setNotConfigured(true);
          setError('');
          return;
        }
        if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
        setData(body as T);
        setError('');
      })
      .catch((e) => alive && setError(String(e instanceof Error ? e.message : e)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [path, tick]);
  return { data, error, loading, notConfigured, reload: () => setTick((t) => t + 1) };
}

async function send(method: string, path: string, body?: unknown): Promise<string> {
  const r = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return (d.messages || []).join(' · ') || 'Done';
}

const mb = (n: number | string | undefined) => {
  const v = Number(n || 0) / 1048576;
  return v >= 1024 ? `${(v / 1024).toFixed(1)} GiB` : `${v.toFixed(v < 10 ? 1 : 0)} MiB`;
};
const on = (v: unknown) => v === 1 || v === '1' || v === true;

function NotConfigured() {
  return (
    <div className="max-w-xl mx-auto mt-10 text-center space-y-3 bg-slate-900/60 border border-amber-900/60 rounded-2xl p-8">
      <KeyRound className="w-8 h-8 text-amber-400 mx-auto" />
      <h2 className="text-lg font-bold text-white">The farm gate is locked</h2>
      <p className="text-sm text-slate-400">CowSec isn't connected to mailcow's API yet. On the server, run:</p>
      <pre className="text-sm font-mono text-amber-200 bg-slate-950/70 rounded-lg py-2">sudo cowsec-setup mailcow-api</pre>
      <p className="text-xs text-slate-500">It reuses mailcow's API key if you already have one and only allows it from this server.</p>
    </div>
  );
}

function Problem({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 text-rose-300 bg-rose-950/40 border border-rose-900 rounded-xl p-3 text-sm">
      <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
      <span>{text}</span>
    </div>
  );
}

function Loading({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-2 text-slate-400 text-sm p-6">
      <Loader2 className="w-4 h-4 animate-spin" /> {text}
    </div>
  );
}

function Toast({ msg, onClose }: { msg: { ok: boolean; text: string } | null; onClose: () => void }) {
  useEffect(() => {
    if (!msg) return;
    const t = window.setTimeout(onClose, 6000);
    return () => window.clearTimeout(t);
  }, [msg, onClose]);
  if (!msg) return null;
  return (
    <div className={`fixed bottom-6 right-6 z-50 max-w-md flex items-start gap-2 rounded-xl px-4 py-3 text-sm shadow-2xl border ${msg.ok ? 'bg-emerald-950/90 border-emerald-700 text-emerald-200' : 'bg-rose-950/90 border-rose-800 text-rose-200'}`}>
      {msg.ok ? <CheckCircle2 className="w-4 h-4 mt-0.5" /> : <AlertTriangle className="w-4 h-4 mt-0.5" />}
      <span className="flex-1">{msg.text}</span>
      <button onClick={onClose} className="cursor-pointer opacity-70 hover:opacity-100"><X className="w-4 h-4" /></button>
    </div>
  );
}

function useToast() {
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const close = useCallback(() => setMsg(null), []);
  const run = async (fn: () => Promise<string>, after?: () => void) => {
    try {
      setMsg({ ok: true, text: await fn() });
      after?.();
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    }
  };
  return { toast: <Toast msg={msg} onClose={close} />, run };
}

const input = 'bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-sky-500';
const btn = 'inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-1.5 cursor-pointer disabled:opacity-40';

function Pill({ ok, yes = 'Active', no = 'Inactive' }: { ok: boolean; yes?: string; no?: string }) {
  return <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${ok ? 'text-emerald-300 bg-emerald-950/60' : 'text-slate-400 bg-slate-800'}`}>{ok ? yes : no}</span>;
}

function Bar({ pct }: { pct: number }) {
  const p = Math.max(0, Math.min(100, pct || 0));
  return (
    <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
      <div className={`h-full ${p > 90 ? 'bg-rose-500' : p > 70 ? 'bg-amber-400' : 'bg-emerald-400'}`} style={{ width: `${p}%` }} />
    </div>
  );
}

function Confirm({ label, onConfirm, danger = true, children }: { label: string; onConfirm: () => void; danger?: boolean; children: ReactNode }) {
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const t = window.setTimeout(() => setArmed(false), 4000);
    return () => window.clearTimeout(t);
  }, [armed]);
  return (
    <button
      onClick={() => (armed ? (setArmed(false), onConfirm()) : setArmed(true))}
      title={label}
      className={`${btn} ${armed ? (danger ? 'bg-rose-600 text-white' : 'bg-amber-600 text-white') : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}
    >
      {armed ? 'Moo again to confirm' : children}
    </button>
  );
}

// ---------------------------------------------------------------- overview

interface Container { container: string; state: string; started_at: string; image: string }

export function FarmOverview() {
  const { data, error, notConfigured, loading, reload } = useApi<Record<string, unknown>>('/api/mailcow/status');
  if (notConfigured) return <NotConfigured />;
  if (error) return <Problem text={`Couldn't reach mailcow: ${error}`} />;
  if (!data) return <Loading text="Walking round the farm…" />;
  const containers = Object.entries((data.containers as Record<string, Container>) || {}).sort(([a], [b]) => a.localeCompare(b));
  const running = containers.filter(([, c]) => c.state === 'running').length;
  const domains = Array.isArray(data.domains) ? (data.domains as Record<string, unknown>[]) : [];
  const mailboxes = Array.isArray(data.mailboxes) ? (data.mailboxes as Record<string, unknown>[]) : [];
  const queue = Array.isArray(data.queue) ? data.queue.length : 0;
  const quarantine = Array.isArray(data.quarantine) ? data.quarantine.length : 0;
  const vmail = (data.vmail as Record<string, string>) || {};
  const version = (data.version as Record<string, string>)?.version;
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Farmhouse</h2>
          <p className="text-sm text-slate-400">mailcow {version ? `${version} ` : ''}at a glance</p>
        </div>
        <button onClick={reload} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}>
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tile label="Containers" value={`${running}/${containers.length}`} sub={running === containers.length ? 'the whole herd is up' : 'some stalls are empty'} tone={running === containers.length ? 'emerald' : 'rose'} icon={<Box className="w-4 h-4" />} />
        <Tile label="Paddocks" value={String(domains.length)} sub={`${mailboxes.length} mailboxes`} tone="sky" icon={<Globe className="w-4 h-4" />} />
        <Tile label="Milk queue" value={String(queue)} sub={queue ? 'messages waiting to go out' : 'nothing stuck'} tone={queue > 20 ? 'amber' : 'indigo'} icon={<Send className="w-4 h-4" />} />
        <Tile label="Storage" value={vmail.used_percent || '—'} sub={`${vmail.used || '?'} of ${vmail.total || '?'} · quarantine ${quarantine}`} tone="amber" icon={<HardDrive className="w-4 h-4" />} />
      </div>
      <Card title="Containers" icon={<Server className="w-4 h-4 text-sky-400" />}>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
          {containers.map(([name, c]) => (
            <div key={name} className="flex items-center justify-between bg-slate-950/50 border border-slate-800 rounded-lg px-3 py-2 text-xs">
              <div className="min-w-0">
                <p className="font-mono text-slate-200 truncate">{name}</p>
                <p className="text-slate-500 truncate">{(c.image || '').replace(/^ghcr\.io\/mailcow\//, '')}</p>
              </div>
              <Pill ok={c.state === 'running'} yes="running" no={c.state || 'down'} />
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------- domains

interface Domain {
  domain_name: string; description: string; active: number; mboxes_in_domain: number; max_num_mboxes_for_domain: number;
  aliases_in_domain: number; max_num_aliases_for_domain: number; quota_used_in_domain: number | string; max_quota_for_domain: number;
  bytes_total: number | string; msgs_total: number | string; def_new_mailbox_quota: number; max_quota_for_mbox: number;
}

export function DomainsPanel() {
  const { data, error, notConfigured, reload } = useApi<Domain[]>('/api/mailcow/domains');
  const { toast, run } = useToast();
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ domain: '', description: '', mailboxes: 10, aliases: 400, quota: 10240, defquota: 3072, maxquota: 10240 });
  if (notConfigured) return <NotConfigured />;
  const add = () =>
    run(() => send('POST', '/api/mailcow/domains', { ...f, active: true }), () => {
      setAdding(false);
      setF({ ...f, domain: '', description: '' });
      reload();
    });
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Paddocks (Domains)" sub="Mail domains on this server" action={<button onClick={() => setAdding(!adding)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add domain</button>} />
      {adding && (
        <Card title="New paddock" icon={<Plus className="w-4 h-4 text-emerald-400" />}>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <Field label="Domain"><input className={input} value={f.domain} onChange={(e) => setF({ ...f, domain: e.target.value.trim().toLowerCase() })} placeholder="example.org" /></Field>
            <Field label="Description"><input className={input} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
            <Field label="Max mailboxes"><input type="number" className={input} value={f.mailboxes} onChange={(e) => setF({ ...f, mailboxes: +e.target.value })} /></Field>
            <Field label="Max aliases"><input type="number" className={input} value={f.aliases} onChange={(e) => setF({ ...f, aliases: +e.target.value })} /></Field>
            <Field label="Domain quota (MiB)"><input type="number" className={input} value={f.quota} onChange={(e) => setF({ ...f, quota: +e.target.value })} /></Field>
            <Field label="Default mailbox quota (MiB)"><input type="number" className={input} value={f.defquota} onChange={(e) => setF({ ...f, defquota: +e.target.value })} /></Field>
            <Field label="Max mailbox quota (MiB)"><input type="number" className={input} value={f.maxquota} onChange={(e) => setF({ ...f, maxquota: +e.target.value })} /></Field>
          </div>
          <div className="flex gap-2">
            <button onClick={add} disabled={!f.domain} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}>Create</button>
            <button onClick={() => setAdding(false)} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
          </div>
          <p className="text-[11px] text-slate-500">mailcow creates a DKIM key for new domains. Publish it from Brand Irons (DKIM), and add MX/SPF/DMARC records at your DNS provider.</p>
        </Card>
      )}
      {error && <Problem text={error} />}
      {!data ? <Loading text="Counting paddocks…" /> : (
        <Card title={`${data.length} domain${data.length === 1 ? '' : 's'}`} icon={<Globe className="w-4 h-4 text-sky-400" />}>
          <table className="w-full text-sm">
            <thead className="text-xs text-slate-500 text-left">
              <tr><th className="py-2">Domain</th><th>Mailboxes</th><th>Aliases</th><th>Storage</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {data.map((d) => {
                const used = Number(d.bytes_total || 0);
                const pct = d.max_quota_for_domain ? (used / Number(d.max_quota_for_domain)) * 100 : 0;
                return (
                  <tr key={d.domain_name} className="border-t border-slate-800/70">
                    <td className="py-2.5">
                      <p className="font-semibold text-white">{d.domain_name}</p>
                      {d.description && <p className="text-xs text-slate-500">{d.description}</p>}
                    </td>
                    <td className="text-slate-300 font-mono text-xs">{d.mboxes_in_domain} / {d.max_num_mboxes_for_domain}</td>
                    <td className="text-slate-300 font-mono text-xs">{d.aliases_in_domain} / {d.max_num_aliases_for_domain}</td>
                    <td><div className="flex items-center gap-2"><Bar pct={pct} /><span className="text-xs text-slate-400 font-mono">{mb(used)}</span></div></td>
                    <td><Pill ok={on(d.active)} /></td>
                    <td className="text-right whitespace-nowrap">
                      <button onClick={() => run(() => send('PATCH', `/api/mailcow/domains/${d.domain_name}`, { active: !on(d.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>
                        {on(d.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />} {on(d.active) ? 'Disable' : 'Enable'}
                      </button>
                      <Confirm label="Delete domain (must have no mailboxes)" onConfirm={() => run(() => send('DELETE', `/api/mailcow/domains/${d.domain_name}`), reload)}>
                        <Trash2 className="w-3.5 h-3.5" />
                      </Confirm>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

function Header({ title, sub, action }: { title: string; sub: string; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 className="text-xl font-bold text-white">{title}</h2>
        <p className="text-sm text-slate-400">{sub}</p>
      </div>
      {action}
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
      {children}
    </label>
  );
}

// ---------------------------------------------------------------- mailboxes

interface Mailbox {
  username: string; name: string; domain: string; local_part: string; active: number; quota: number | string; quota_used: number | string;
  percent_in_use: number | string; messages: number; last_imap_login: number | string; last_smtp_login: number | string;
}

const lastSeen = (v: number | string | undefined) => {
  const n = Number(v || 0);
  if (!n) return 'never';
  const d = (Date.now() / 1000 - n) / 86400;
  return d < 1 ? 'today' : d < 2 ? 'yesterday' : `${Math.floor(d)} days ago`;
};

export function MailboxesPanel() {
  const domains = useApi<Domain[]>('/api/mailcow/domains');
  const [domain, setDomain] = useState('');
  const { data, error, notConfigured, reload } = useApi<Mailbox[]>(`/api/mailcow/mailboxes${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`);
  const { toast, run } = useToast();
  const [q, setQ] = useState('');
  const [adding, setAdding] = useState(false);
  const [f, setF] = useState({ local_part: '', domain: '', name: '', quota: 3072, password: '' });
  const [pwFor, setPwFor] = useState('');
  const [newPw, setNewPw] = useState('');
  const list = useMemo(() => (data || []).filter((m) => !q || m.username.includes(q.toLowerCase()) || (m.name || '').toLowerCase().includes(q.toLowerCase())), [data, q]);
  if (notConfigured || domains.notConfigured) return <NotConfigured />;
  const genPw = () => Array.from(crypto.getRandomValues(new Uint8Array(15)), (b) => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 56]).join('');
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Stalls (Mailboxes)" sub="Mail accounts, quotas and last logins" action={<button onClick={() => { setAdding(!adding); setF({ ...f, password: genPw(), domain: f.domain || domains.data?.[0]?.domain_name || '' }); }} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add mailbox</button>} />
      {adding && (
        <Card title="New stall" icon={<Plus className="w-4 h-4 text-emerald-400" />}>
          <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs">
            <Field label="Address">
              <div className="flex items-center gap-1">
                <input className={`${input} w-28`} value={f.local_part} onChange={(e) => setF({ ...f, local_part: e.target.value.trim() })} placeholder="alice" />
                <span className="text-slate-500">@</span>
                <select className={input} value={f.domain} onChange={(e) => setF({ ...f, domain: e.target.value })}>
                  {(domains.data || []).map((d) => <option key={d.domain_name}>{d.domain_name}</option>)}
                </select>
              </div>
            </Field>
            <Field label="Full name"><input className={input} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
            <Field label="Quota (MiB)"><input type="number" className={input} value={f.quota} onChange={(e) => setF({ ...f, quota: +e.target.value })} /></Field>
            <Field label="Password"><input className={`${input} font-mono`} value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></Field>
          </div>
          <div className="flex gap-2">
            <button disabled={!f.local_part || !f.domain || f.password.length < 10} onClick={() => run(() => send('POST', '/api/mailcow/mailboxes', { ...f, active: true }), () => { setAdding(false); reload(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}>Create</button>
            <button onClick={() => navigator.clipboard?.writeText(f.password)} className={`${btn} text-slate-400 hover:text-white`}><Copy className="w-3.5 h-3.5" /> Copy password</button>
            <button onClick={() => setAdding(false)} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
          </div>
        </Card>
      )}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input className={`${input} pl-8 w-64`} placeholder="Search mailboxes" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className={input} value={domain} onChange={(e) => setDomain(e.target.value)}>
          <option value="">All domains</option>
          {(domains.data || []).map((d) => <option key={d.domain_name}>{d.domain_name}</option>)}
        </select>
      </div>
      {error && <Problem text={error} />}
      {!data ? <Loading text="Checking the stalls…" /> : (
        <Card title={`${list.length} mailbox${list.length === 1 ? '' : 'es'}`} icon={<Inbox className="w-4 h-4 text-sky-400" />}>
          <table className="w-full text-sm">
            <thead className="text-xs text-slate-500 text-left">
              <tr><th className="py-2">Mailbox</th><th>Usage</th><th>Messages</th><th>Last IMAP / SMTP</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {list.map((m) => (
                <tr key={m.username} className="border-t border-slate-800/70 align-top">
                  <td className="py-2.5">
                    <p className="font-semibold text-white">{m.username}</p>
                    {m.name && <p className="text-xs text-slate-500">{m.name}</p>}
                    {pwFor === m.username && (
                      <div className="flex gap-1 mt-2">
                        <input className={`${input} font-mono text-xs`} value={newPw} onChange={(e) => setNewPw(e.target.value)} />
                        <button disabled={newPw.length < 10} onClick={() => run(() => send('PATCH', `/api/mailcow/mailboxes/${encodeURIComponent(m.username)}`, { password: newPw }), () => setPwFor(''))} className={`${btn} bg-sky-700 text-white`}>Set</button>
                        <button onClick={() => navigator.clipboard?.writeText(newPw)} className={`${btn} text-slate-400`}><Copy className="w-3.5 h-3.5" /></button>
                      </div>
                    )}
                  </td>
                  <td><div className="flex items-center gap-2"><Bar pct={Number(m.percent_in_use)} /><span className="text-xs text-slate-400 font-mono">{mb(m.quota_used)} / {mb(m.quota)}</span></div></td>
                  <td className="text-xs text-slate-300 font-mono">{m.messages ?? 0}</td>
                  <td className="text-xs text-slate-400">{lastSeen(m.last_imap_login)} / {lastSeen(m.last_smtp_login)}</td>
                  <td><Pill ok={on(m.active)} /></td>
                  <td className="text-right whitespace-nowrap">
                    <button onClick={() => { setPwFor(pwFor === m.username ? '' : m.username); setNewPw(genPw()); }} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Set a new password"><KeyRound className="w-3.5 h-3.5" /></button>
                    <button onClick={() => run(() => send('PATCH', `/api/mailcow/mailboxes/${encodeURIComponent(m.username)}`, { active: !on(m.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title={on(m.active) ? 'Disable' : 'Enable'}>
                      {on(m.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    </button>
                    <Confirm label="Delete mailbox and all its mail" onConfirm={() => run(() => send('DELETE', `/api/mailcow/mailboxes/${encodeURIComponent(m.username)}`), reload)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Confirm>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- aliases

interface Alias { id: number; address: string; goto: string; active: number; domain: string; is_catch_all?: number }

export function AliasesPanel() {
  const { data, error, notConfigured, reload } = useApi<Alias[]>('/api/mailcow/aliases');
  const { toast, run } = useToast();
  const [f, setF] = useState({ address: '', goto: '' });
  const [q, setQ] = useState('');
  if (notConfigured) return <NotConfigured />;
  const list = (data || []).filter((a) => !q || a.address.includes(q.toLowerCase()) || a.goto.includes(q.toLowerCase()));
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Ear Tags (Aliases)" sub="Forwarding addresses and catch-alls" />
      <Card title="New ear tag" icon={<AtSign className="w-4 h-4 text-emerald-400" />}>
        <div className="flex flex-wrap items-end gap-3 text-xs">
          <Field label="Alias address (or @domain for catch-all)"><input className={`${input} w-72`} value={f.address} onChange={(e) => setF({ ...f, address: e.target.value.trim() })} placeholder="sales@example.org" /></Field>
          <Field label="Deliver to (comma-separated)"><input className={`${input} w-96`} value={f.goto} onChange={(e) => setF({ ...f, goto: e.target.value })} placeholder="alice@example.org, bob@example.org" /></Field>
          <button disabled={!f.address || !f.goto} onClick={() => run(() => send('POST', '/api/mailcow/aliases', { ...f, active: true }), () => { setF({ address: '', goto: '' }); reload(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add</button>
        </div>
      </Card>
      <div className="relative w-64">
        <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
        <input className={`${input} pl-8 w-full`} placeholder="Search aliases" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {error && <Problem text={error} />}
      {!data ? <Loading text="Reading ear tags…" /> : (
        <Card title={`${list.length} alias${list.length === 1 ? '' : 'es'}`} icon={<AtSign className="w-4 h-4 text-sky-400" />}>
          {list.length === 0 ? <p className="text-sm text-slate-500">No aliases yet.</p> : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 text-left"><tr><th className="py-2">Alias</th><th>Delivers to</th><th>Status</th><th /></tr></thead>
              <tbody>
                {list.map((a) => (
                  <tr key={a.id} className="border-t border-slate-800/70">
                    <td className="py-2.5 font-semibold text-white">{a.address}{a.address.startsWith('@') && <span className="ml-2 text-[10px] text-amber-300">catch-all</span>}</td>
                    <td className="text-xs text-slate-300 font-mono break-all">{a.goto.split(',').join(', ')}</td>
                    <td><Pill ok={on(a.active)} /></td>
                    <td className="text-right whitespace-nowrap">
                      <button onClick={() => run(() => send('PATCH', `/api/mailcow/aliases/${a.id}`, { active: !on(a.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{on(a.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}</button>
                      <Confirm label="Delete alias" onConfirm={() => run(() => send('DELETE', `/api/mailcow/aliases/${a.id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- DKIM

interface Dkim { pubkey?: string; length?: string; dkim_txt?: string; dkim_selector?: string; privkey?: string }

function DkimRow({ domain, onToast }: { domain: string; onToast: ReturnType<typeof useToast>['run'] }) {
  const { data, reload } = useApi<Dkim>(`/api/mailcow/dkim/${domain}`);
  const has = !!data?.dkim_txt;
  const record = `${data?.dkim_selector || 'dkim'}._domainkey.${domain}`;
  return (
    <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-4 space-y-2">
      <div className="flex items-center justify-between">
        <p className="font-semibold text-white">{domain}</p>
        {has ? <Pill ok yes={`${data?.length || ''} bit`} /> : <Pill ok={false} no="no key" />}
      </div>
      {has ? (
        <>
          <p className="text-[11px] text-slate-500">TXT record name</p>
          <div className="flex items-center gap-2"><code className="text-xs text-sky-200 break-all">{record}</code><button onClick={() => navigator.clipboard?.writeText(record)} className={`${btn} text-slate-400`}><Copy className="w-3.5 h-3.5" /></button></div>
          <p className="text-[11px] text-slate-500">TXT record value</p>
          <div className="flex items-start gap-2"><code className="text-[11px] text-slate-300 break-all leading-relaxed">{data?.dkim_txt}</code><button onClick={() => navigator.clipboard?.writeText(data?.dkim_txt || '')} className={`${btn} text-slate-400`}><Copy className="w-3.5 h-3.5" /></button></div>
        </>
      ) : (
        <button onClick={() => onToast(() => send('POST', '/api/mailcow/dkim', { domain, key_size: 2048 }), reload)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><KeyRound className="w-3.5 h-3.5" /> Generate 2048-bit key</button>
      )}
    </div>
  );
}

export function DkimPanel() {
  const { data, error, notConfigured } = useApi<Domain[]>('/api/mailcow/domains');
  const { toast, run } = useToast();
  if (notConfigured) return <NotConfigured />;
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Brand Irons (DKIM)" sub="Signing keys, and the DNS records to publish for each domain" />
      {error && <Problem text={error} />}
      {!data ? <Loading text="Heating the irons…" /> : <div className="grid lg:grid-cols-2 gap-4">{data.map((d) => <DkimRow key={d.domain_name} domain={d.domain_name} onToast={run} />)}</div>}
    </div>
  );
}

// ---------------------------------------------------------------- quarantine

interface QItem { id: number; sender: string; rcpt: string; subject: string; score: number; action: string; created: number; virus_flag?: number; notified?: number }

export function QuarantinePanel() {
  const { data, error, notConfigured, reload } = useApi<QItem[]>('/api/mailcow/quarantine');
  const { toast, run } = useToast();
  if (notConfigured) return <NotConfigured />;
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Quarantine Pen" sub="Messages held back by rspamd. Release the ones that are genuine." />
      {error && <Problem text={error} />}
      {!data ? <Loading text="Checking the pen…" /> : (
        <Card title={`${data.length} held message${data.length === 1 ? '' : 's'}`} icon={<ShieldAlert className="w-4 h-4 text-amber-400" />}>
          {data.length === 0 ? <p className="text-sm text-slate-500">The pen is empty. Nothing is being held.</p> : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 text-left"><tr><th className="py-2">From → to</th><th>Subject</th><th>Score</th><th>When</th><th /></tr></thead>
              <tbody>
                {data.map((m) => (
                  <tr key={m.id} className="border-t border-slate-800/70 align-top">
                    <td className="py-2.5 text-xs"><p className="text-slate-200 break-all">{m.sender}</p><p className="text-slate-500 break-all">→ {m.rcpt}</p></td>
                    <td className="text-xs text-slate-300 max-w-xs break-words">{m.subject}{on(m.virus_flag) && <span className="ml-2 text-rose-300 font-semibold">virus</span>}</td>
                    <td className="text-xs font-mono text-amber-300">{Number(m.score).toFixed(1)}</td>
                    <td className="text-xs text-slate-400">{new Date(m.created * 1000).toLocaleString()}</td>
                    <td className="text-right whitespace-nowrap">
                      <Confirm danger={false} label="Release to the recipient" onConfirm={() => run(() => send('POST', `/api/mailcow/quarantine/${m.id}/release`), reload)}><Send className="w-3.5 h-3.5" /> Release</Confirm>
                      <Confirm label="Delete" onConfirm={() => run(() => send('DELETE', `/api/mailcow/quarantine/${m.id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- mail queue

interface QueueItem { queue_name: string; queue_id: string; arrival_time: number; message_size: number; sender: string; recipients: string[] | { address: string; delay_reason?: string }[] }

export function QueuePanel() {
  const { data, error, notConfigured, reload } = useApi<QueueItem[]>('/api/mailcow/queue');
  const { toast, run } = useToast();
  if (notConfigured) return <NotConfigured />;
  const rcpts = (r: QueueItem['recipients']) => (r || []).map((x) => (typeof x === 'string' ? x : `${x.address}${x.delay_reason ? ` (${x.delay_reason})` : ''}`));
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Milk Queue (Mail queue)" sub="Outgoing mail postfix is still trying to deliver"
        action={<div className="flex gap-2">
          <button onClick={reload} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
          <button onClick={() => run(() => send('POST', '/api/mailcow/queue/flush'), reload)} className={`${btn} bg-sky-700 hover:bg-sky-600 text-white`}><Send className="w-3.5 h-3.5" /> Retry all now</button>
        </div>} />
      {error && <Problem text={error} />}
      {!data ? <Loading text="Checking the queue…" /> : (
        <Card title={`${data.length} queued message${data.length === 1 ? '' : 's'}`} icon={<Send className="w-4 h-4 text-sky-400" />}>
          {data.length === 0 ? <p className="text-sm text-slate-500">The queue is empty. Everything has been delivered.</p> : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 text-left"><tr><th className="py-2">Queue</th><th>From → to</th><th>Size</th><th>Since</th><th /></tr></thead>
              <tbody>
                {data.map((m) => (
                  <tr key={m.queue_id} className="border-t border-slate-800/70 align-top">
                    <td className="py-2.5 text-xs"><p className="font-mono text-slate-200">{m.queue_id}</p><Pill ok={m.queue_name !== 'hold'} yes={m.queue_name} no="held" /></td>
                    <td className="text-xs"><p className="text-slate-200 break-all">{m.sender}</p>{rcpts(m.recipients).map((r) => <p key={r} className="text-slate-500 break-all">→ {r}</p>)}</td>
                    <td className="text-xs text-slate-400 font-mono">{(m.message_size / 1024).toFixed(1)} KB</td>
                    <td className="text-xs text-slate-400">{new Date(m.arrival_time * 1000).toLocaleString()}</td>
                    <td className="text-right whitespace-nowrap">
                      <button onClick={() => run(() => send('POST', `/api/mailcow/queue/${m.queue_id}/deliver`), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Try now"><Send className="w-3.5 h-3.5" /></button>
                      <button onClick={() => run(() => send('POST', `/api/mailcow/queue/${m.queue_id}/${m.queue_name === 'hold' ? 'unhold' : 'hold'}`), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title={m.queue_name === 'hold' ? 'Release hold' : 'Hold'}>{m.queue_name === 'hold' ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}</button>
                      <Confirm label="Delete from queue" onConfirm={() => run(() => send('DELETE', `/api/mailcow/queue/${m.queue_id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- logs

const LOGS: [string, string][] = [['postfix', 'Postfix (SMTP)'], ['dovecot', 'Dovecot (IMAP/POP)'], ['rspamd-history', 'rspamd (spam filter)'], ['sogo', 'SOGo (webmail)'],
  ['netfilter', 'mailcow netfilter'], ['autodiscover', 'Autodiscover'], ['acme', 'ACME (certificates)'], ['watchdog', 'Watchdog'], ['ratelimited', 'Rate limited'], ['api', 'API']];

export function LogsPanel() {
  const [type, setType] = useState('postfix');
  const [q, setQ] = useState('');
  const { data, error, notConfigured, loading, reload } = useApi<Record<string, unknown>[]>(`/api/mailcow/logs/${type}?count=300`);
  if (notConfigured) return <NotConfigured />;
  const rows = (data || []).map((l) => {
    if (type === 'rspamd-history') {
      const t = Number(l.unix_time || 0);
      return { time: t, text: `${l.action ?? ''} · score ${Number(l.score ?? 0).toFixed(1)} · ${l.sender_smtp ?? ''} → ${(l.rcpt_smtp as string[] | undefined)?.join(', ') ?? ''} · ${l.subject ?? ''}`, level: String(l.action || '') };
    }
    return { time: Number(l.time || 0), text: `${l.program ? `${l.program}: ` : ''}${l.message ?? l.task ?? JSON.stringify(l)}`, level: String(l.priority || l.type || '') };
  }).filter((r) => !q || r.text.toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="space-y-6">
      <Header title="Farm Log (Logs)" sub="mailcow's service logs" action={<button onClick={reload} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh</button>} />
      <div className="flex flex-wrap gap-2">
        {LOGS.map(([id, label]) => (
          <button key={id} onClick={() => setType(id)} className={`${btn} border ${type === id ? 'border-sky-500 bg-sky-500/15 text-white' : 'border-slate-800 text-slate-400 hover:text-white'}`}>{label}</button>
        ))}
      </div>
      <div className="relative w-80">
        <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
        <input className={`${input} pl-8 w-full`} placeholder="Filter lines" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {error && <Problem text={error} />}
      {!data ? <Loading text="Reading the farm log…" /> : (
        <Card title={`${rows.length} lines`} icon={<FileText className="w-4 h-4 text-sky-400" />}>
          <div className="max-h-[640px] overflow-auto font-mono text-[11.5px] leading-relaxed">
            {rows.map((r, i) => (
              <div key={i} className="flex gap-3 border-b border-slate-800/50 py-1">
                <span className="text-slate-500 shrink-0">{r.time ? new Date(r.time * 1000).toLocaleString() : ''}</span>
                <span className={/err|crit|alert|reject|warn/i.test(r.level) ? 'text-amber-300' : 'text-slate-300'}>{r.text}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

