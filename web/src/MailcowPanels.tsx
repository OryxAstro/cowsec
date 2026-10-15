// "The Farm": mailcow management through mailcow's API (domains, mailboxes, aliases,
// DKIM, quarantine, mail queue, logs, status). Every call goes to CowSec's validated
// /api/mailcow endpoints; CowSec's audit log records each change.
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  AlertTriangle, AtSign, Box, CheckCircle2, Copy, Eye, FileText, Globe, HardDrive, Inbox, KeyRound, Loader2,
  Pause, Pencil, Play, Plus, RefreshCw, Search, Send, Server, ShieldAlert, Trash2, X,
} from 'lucide-react';
import { Card, Tile } from './HostPanel';
import { AliasModal, DnsModal, DomainModal, MailboxModal } from './MailcowForms';
import { QuarantinePreview } from './MailcowExtras';
import Select from './Select';

// ---------------------------------------------------------------- shared

type Result<T> = { data: T | null; error: string; loading: boolean; notConfigured: boolean; reload: () => void };

export function useApi<T>(path: string | null): Result<T> {
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

export async function send(method: string, path: string, body?: unknown): Promise<string> {
  const r = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
  return (d.messages || []).join(' · ') || 'Done';
}

const mb = (n: number | string | undefined) => {
  const v = Number(n || 0) / 1048576;
  return v >= 1024 ? `${(v / 1024).toFixed(1)} GiB` : `${v.toFixed(v < 10 ? 1 : 0)} MiB`;
};
export const on = (v: unknown) => v === 1 || v === '1' || v === true;

export function NotConfigured() {
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

export function Problem({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 text-rose-300 bg-rose-950/40 border border-rose-900 rounded-xl p-3 text-sm">
      <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
      <span>{text}</span>
    </div>
  );
}

export function Loading({ text }: { text: string }) {
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

export function useToast() {
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

export const input = 'bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-sky-500';
export const btn = 'inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-1.5 cursor-pointer disabled:opacity-40';

export function Pill({ ok, yes = 'Active', no = 'Inactive' }: { ok: boolean; yes?: string; no?: string }) {
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

export function Confirm({ label, onConfirm, danger = true, children }: { label: string; onConfirm: () => void; danger?: boolean; children: ReactNode }) {
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
  const [modal, setModal] = useState<{ kind: 'add' } | { kind: 'edit'; d: Domain } | { kind: 'dns'; d: string } | null>(null);
  if (notConfigured) return <NotConfigured />;
  return (
    <div className="space-y-6">
      {toast}
      {modal?.kind === 'add' && <DomainModal onClose={() => setModal(null)} onSaved={reload} run={run} />}
      {modal?.kind === 'edit' && <DomainModal domain={modal.d} onClose={() => setModal(null)} onSaved={reload} run={run} />}
      {modal?.kind === 'dns' && <DnsModal domain={modal.d} domains={(data || []).map((d) => d.domain_name)} onClose={() => setModal(null)} run={run} />}
      <Header title="Paddocks (Domains)" sub="Mail domains on this server, their limits and their DNS" action={<button onClick={() => setModal({ kind: 'add' })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add domain</button>} />
      {error && <Problem text={error} />}
      {!data ? <Loading text="Counting paddocks…" /> : (
        <Card title={`${data.length} domain${data.length === 1 ? '' : 's'}`} icon={<Globe className="w-4 h-4 text-sky-400" />}>
          <table className="w-full text-sm">
            <thead className="text-xs text-slate-500 text-left">
              <tr><th className="py-2">Domain</th><th>Mailboxes</th><th>Aliases</th><th>Storage</th><th>Status</th><th /></tr>
            </thead>
            <tbody className="cs-stagger">
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
                      <button onClick={() => setModal({ kind: 'dns', d: d.domain_name })} className={`${btn} text-sky-300 hover:text-white hover:bg-slate-800`} title="DNS records"><Globe className="w-3.5 h-3.5" /> DNS</button>
                      <button onClick={() => setModal({ kind: 'edit', d })} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
                      <button onClick={() => run(() => send('PATCH', `/api/mailcow/domains/${d.domain_name}`, { active: !on(d.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title={on(d.active) ? 'Disable' : 'Enable'}>
                        {on(d.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
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

export function Header({ title, sub, action }: { title: string; sub: string; action?: ReactNode }) {
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

export function Field({ label, children }: { label: string; children: ReactNode }) {
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
  const [modal, setModal] = useState<{ user?: string } | null>(null);
  const [pwFor, setPwFor] = useState('');
  const [newPw, setNewPw] = useState('');
  const list = useMemo(() => (data || []).filter((m) => !q || m.username.includes(q.toLowerCase()) || (m.name || '').toLowerCase().includes(q.toLowerCase())), [data, q]);
  if (notConfigured || domains.notConfigured) return <NotConfigured />;
  const genPw = () => Array.from(crypto.getRandomValues(new Uint8Array(15)), (b) => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 56]).join('');
  return (
    <div className="space-y-6">
      {toast}
      {modal && <MailboxModal domains={domains.data || []} username={modal.user} onClose={() => setModal(null)} onSaved={reload} run={run} />}
      <Header title="Stalls (Mailboxes)" sub="Mail accounts, quotas and last logins" action={<button onClick={() => setModal({})} disabled={!domains.data?.length} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add mailbox</button>} />
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input className={`${input} pl-8 w-64`} placeholder="Search mailboxes" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <Select className="w-64" value={domain} onChange={setDomain} searchable={(domains.data || []).length > 8} ariaLabel="Filter by domain"
          options={[{ value: '', label: 'All domains' }, ...(domains.data || []).map((d) => ({ value: d.domain_name, label: d.domain_name }))]} />
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
                    <button onClick={() => setModal({ user: m.username })} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
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

interface Alias { id: number; address: string; goto: string; active: number; domain: string; is_catch_all?: number; sogo_visible?: number; internal?: number; private_comment?: string; public_comment?: string }

export function AliasesPanel() {
  const { data, error, notConfigured, reload } = useApi<Alias[]>('/api/mailcow/aliases');
  const { toast, run } = useToast();
  const [modal, setModal] = useState<{ alias?: Alias } | null>(null);
  const [q, setQ] = useState('');
  if (notConfigured) return <NotConfigured />;
  const list = (data || []).filter((a) => !q || a.address.includes(q.toLowerCase()) || a.goto.includes(q.toLowerCase()));
  return (
    <div className="space-y-6">
      {toast}
      {modal && <AliasModal alias={modal.alias} onClose={() => setModal(null)} onSaved={reload} run={run} />}
      <Header title="Ear Tags (Aliases)" sub="Forwarding addresses and catch-alls" action={<button onClick={() => setModal({})} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add alias</button>} />
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
                      <button onClick={() => setModal({ alias: a })} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
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

// ---------------------------------------------------------------- quarantine

interface QItem { id: number; sender: string; rcpt: string; subject: string; score: number; action: string; created: number; virus_flag?: number; notified?: number }

export function QuarantinePanel() {
  const { data, error, notConfigured, reload } = useApi<QItem[]>('/api/mailcow/quarantine');
  const { toast, run } = useToast();
  const [open, setOpen] = useState<number | null>(null);
  if (notConfigured) return <NotConfigured />;
  return (
    <div className="space-y-6">
      {toast}
      {open != null && <QuarantinePreview id={open} onClose={() => setOpen(null)} run={run} onChanged={reload} />}
      <Header title="Quarantine Pen" sub="Messages held back by rspamd. Open one to see why, then release it, train the filter or block the sender." />
      {error && <Problem text={error} />}
      {!data ? <Loading text="Checking the pen…" /> : (
        <Card title={`${data.length} held message${data.length === 1 ? '' : 's'}`} icon={<ShieldAlert className="w-4 h-4 text-amber-400" />}>
          {data.length === 0 ? <p className="text-sm text-slate-500">The pen is empty. Nothing is being held.</p> : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 text-left"><tr><th className="py-2">From → to</th><th>Subject</th><th>Score</th><th>When</th><th /></tr></thead>
              <tbody>
                {data.map((m) => (
                  <tr key={m.id} className="border-t border-slate-800/70 align-top hover:bg-slate-800/30 cursor-pointer" onClick={() => setOpen(m.id)}>
                    <td className="py-2.5 text-xs"><p className="text-slate-200 break-all">{m.sender}</p><p className="text-slate-500 break-all">→ {m.rcpt}</p></td>
                    <td className="text-xs text-slate-300 max-w-xs break-words">{m.subject}{on(m.virus_flag) && <span className="ml-2 text-rose-300 font-semibold">virus</span>}</td>
                    <td className="text-xs font-mono text-amber-300">{Number(m.score).toFixed(1)}</td>
                    <td className="text-xs text-slate-400">{new Date(m.created * 1000).toLocaleString()}</td>
                    <td className="text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <button onClick={() => setOpen(m.id)} className={`${btn} text-sky-300 hover:text-white hover:bg-slate-800`} title="Open"><Eye className="w-3.5 h-3.5" /> Open</button>
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
          {!!data?.length && <Confirm label="Delete every message in the queue" onConfirm={() => run(() => send('POST', '/api/mailcow/queue/purge'), reload)}><Trash2 className="w-3.5 h-3.5" /> Empty the queue</Confirm>}
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

