// Phase 3 pieces for The Farm: per-mailbox spam score, app passwords and disposable
// aliases, sender allow/block lists, domain footers and alias domains, DKIM keys with
// zero-downtime rotation, and a safe quarantine preview.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  AlertTriangle, ArrowRight, Ban, CheckCircle2, Clock, Copy, ExternalLink, Eye, FileText, Infinity as Forever, KeyRound, Link2, Loader2,
  Mail, Paperclip, Plus, RefreshCw, RotateCw, Send, ShieldCheck, Signature, ThumbsUp, Trash2,
} from 'lucide-react';
import { Chips, Labelled, Modal, Segmented, SwitchRow, TagInput } from './MailcowForms';
import { btn, Confirm, input, on, Pill, send, useApi } from './MailcowPanels';
import Select from './Select';

type Run = (fn: () => Promise<string>, after?: () => void) => Promise<void>;

export const list = <T,>(v: T[] | Record<string, never> | null | undefined): T[] => (Array.isArray(v) ? v : []);

export function Tabs<T extends string>({ value, onChange, tabs }: { value: T; onChange: (v: T) => void; tabs: [T, string, ReactNode][] }) {
  return (
    <div className="flex flex-wrap gap-1 border-b border-slate-800 -mt-1">
      {tabs.map(([v, l, icon]) => (
        <button key={v} type="button" onClick={() => onChange(v)}
          className={`inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold border-b-2 -mb-px cursor-pointer transition-colors ${value === v ? 'border-sky-400 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
          {icon}{l}
        </button>
      ))}
    </div>
  );
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" onClick={() => navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }).catch(() => {})}
      className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`} title="Copy">
      {done ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}{label}
    </button>
  );
}

const when = (v: unknown) => {
  const n = typeof v === 'number' ? v * 1000 : Date.parse(String(v || ''));
  return Number.isFinite(n) && n > 0 ? new Date(n).toLocaleString() : '—';
};

// ---------------------------------------------------------------- spam score

const SCALE = 30;

export function SpamScoreTab({ user, run }: { user: string; run: Run }) {
  const { data, reload } = useApi<{ score: string }>(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/spam-score`);
  const [junk, setJunk] = useState(8);
  const [reject, setReject] = useState(15);
  useEffect(() => {
    const [a, b] = String(data?.score || '8,15').split(',').map(Number);
    if (Number.isFinite(a)) setJunk(a);
    if (Number.isFinite(b)) setReject(b);
  }, [data]);
  const pct = (v: number) => `${(Math.min(v, SCALE) / SCALE) * 100}%`;
  const preset = (j: number, r: number) => { setJunk(j); setReject(r); };
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">rspamd gives every message a spam score. Choose where this mailbox draws its lines: below the first, mail goes to the inbox; between the two, to the Junk folder; above the second, it's rejected or quarantined.</p>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-5 space-y-5">
        <div className="relative h-3 rounded-full overflow-hidden flex">
          <div className="h-full bg-emerald-500/70 transition-all" style={{ width: pct(junk) }} />
          <div className="h-full bg-amber-400/80 transition-all" style={{ width: `calc(${pct(reject)} - ${pct(junk)})` }} />
          <div className="h-full flex-1 bg-rose-500/70" />
        </div>
        <div className="grid grid-cols-3 text-[11px] text-center">
          <span className="text-emerald-300 font-semibold">Inbox<br /><span className="text-slate-500 font-normal">score below {junk}</span></span>
          <span className="text-amber-300 font-semibold">Junk folder<br /><span className="text-slate-500 font-normal">{junk} to {reject}</span></span>
          <span className="text-rose-300 font-semibold">Rejected<br /><span className="text-slate-500 font-normal">above {reject}</span></span>
        </div>
        <Labelled label={`Junk folder from ${junk}`}>
          <input type="range" min={1} max={SCALE} step={0.5} value={junk} onChange={(e) => { const v = +e.target.value; setJunk(v); if (v > reject) setReject(v); }} className="w-full accent-amber-400" />
        </Labelled>
        <Labelled label={`Reject from ${reject}`}>
          <input type="range" min={1} max={SCALE} step={0.5} value={reject} onChange={(e) => { const v = +e.target.value; setReject(v); if (v < junk) setJunk(v); }} className="w-full accent-rose-400" />
        </Labelled>
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-[11px] text-slate-500 mr-1">Presets</span>
          <button type="button" onClick={() => preset(5, 10)} className={`${btn} border border-slate-700 text-slate-300`}>Strict · 5 / 10</button>
          <button type="button" onClick={() => preset(8, 15)} className={`${btn} border border-slate-700 text-slate-300`}>mailcow default · 8 / 15</button>
          <button type="button" onClick={() => preset(12, 25)} className={`${btn} border border-slate-700 text-slate-300`}>Relaxed · 12 / 25</button>
        </div>
      </div>
      <div className="flex justify-end gap-2">
        <button onClick={() => run(() => send('PUT', `/api/mailcow/mailboxes/${encodeURIComponent(user)}/spam-score`, { default: true }), reload)} className={`${btn} text-slate-400 hover:text-white`}>Reset to server default</button>
        <button onClick={() => run(() => send('PUT', `/api/mailcow/mailboxes/${encodeURIComponent(user)}/spam-score`, { junk, reject }), reload)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>Save spam score</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- app passwords

interface AppPw { id: number; name: string; active: unknown; created?: string; imap_access?: unknown; smtp_access?: unknown; eas_access?: unknown; dav_access?: unknown; pop3_access?: unknown; sieve_access?: unknown }
const APP_PROTOS: ['imap' | 'smtp' | 'eas' | 'dav' | 'pop3' | 'sieve', string][] = [['imap', 'IMAP'], ['smtp', 'SMTP'], ['dav', 'CalDAV / CardDAV'], ['eas', 'ActiveSync'], ['pop3', 'POP3'], ['sieve', 'Sieve']];

export function AppPasswordsTab({ user, run }: { user: string; run: Run }) {
  const { data, reload, loading } = useApi<AppPw[]>(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/app-passwords`);
  const [name, setName] = useState('');
  const [protos, setProtos] = useState<string[]>(['imap', 'smtp', 'dav']);
  const [made, setMade] = useState<{ name: string; password: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const create = async () => {
    setBusy(true);
    try {
      const r = await fetch(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/app-passwords`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, protocols: protos }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      setMade({ name, password: d.password });
      setName('');
      reload();
    } catch (e) {
      run(() => Promise.reject(e));
    } finally {
      setBusy(false);
    }
  };
  const rows = list(data);
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">A separate password for each app or device (phone mail, a calendar, a scanner). Revoke one without changing the main password, and it keeps working when the mailbox requires two-factor sign-in.</p>
      {made && (
        <div className="rounded-2xl border border-emerald-700/60 bg-emerald-950/40 p-4 space-y-2 cs-pop">
          <p className="text-sm font-semibold text-emerald-200 flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> “{made.name}” is ready. Copy it now: it won't be shown again.</p>
          <div className="flex items-center gap-2">
            <code className="flex-1 font-mono text-base tracking-wide text-white bg-slate-950/70 rounded-lg px-3 py-2 select-all">{made.password}</code>
            <CopyButton text={made.password} label="Copy" />
          </div>
          <p className="text-[11px] text-slate-400">Sign in with {user} as the username and this as the password.</p>
        </div>
      )}
      <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 space-y-3">
        <Labelled label="New app password">
          <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. iPhone mail, Thunderbird at home" maxLength={64} />
        </Labelled>
        <Labelled label="It may use"><Chips value={protos} onChange={setProtos} options={APP_PROTOS} /></Labelled>
        <div className="flex justify-end">
          <button disabled={!name.trim() || !protos.length || busy} onClick={create} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5" />} Create app password
          </button>
        </div>
      </div>
      {loading && !data ? <p className="text-sm text-slate-500">Loading…</p> : rows.length === 0 ? <p className="text-sm text-slate-500">No app passwords yet.</p> : (
        <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/80">
          {rows.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <KeyRound className="w-4 h-4 text-sky-300 shrink-0" />
              <div className="flex-1 min-w-[160px]">
                <p className="text-sm font-semibold text-white">{a.name}</p>
                <p className="text-[11px] text-slate-500">{APP_PROTOS.filter(([k]) => on((a as unknown as Record<string, unknown>)[`${k}_access`])).map(([, l]) => l).join(' · ') || 'no protocols'} · created {when(a.created)}</p>
              </div>
              <Pill ok={on(a.active)} />
              <button onClick={() => run(() => send('PATCH', `/api/mailcow/mailboxes/${encodeURIComponent(user)}/app-passwords/${a.id}`, { active: !on(a.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{on(a.active) ? 'Pause' : 'Resume'}</button>
              <Confirm label="Revoke this app password" onConfirm={() => run(() => send('DELETE', `/api/mailcow/app-passwords/${a.id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- disposable aliases

interface SpamAlias { address: string; description?: string; validity?: number | string; permanent?: unknown; created?: string }
const DURATIONS: [string, string][] = [['24', '1 day'], ['168', '1 week'], ['720', '1 month'], ['8760', '1 year'], ['forever', 'Forever']];

export function DisposableTab({ user, domains, run }: { user: string; domains: string[]; run: Run }) {
  const { data, reload } = useApi<SpamAlias[]>(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/spam-aliases`);
  const own = user.split('@')[1] || '';
  const [domain, setDomain] = useState(own);
  const [desc, setDesc] = useState('');
  const [dur, setDur] = useState('720');
  const rows = list(data).sort((a, b) => Number(b.validity || 0) - Number(a.validity || 0));
  const timing = (d: string) => (d === 'forever' ? { permanent: true } : { hours: Number(d) });
  const left = (a: SpamAlias) => {
    if (on(a.permanent)) return { text: 'never expires', tone: 'text-sky-300' };
    const s = Number(a.validity || 0) - Date.now() / 1000;
    if (s <= 0) return { text: 'expired', tone: 'text-slate-500' };
    const d = s / 86400;
    return { text: d >= 2 ? `${Math.floor(d)} days left` : `${Math.max(1, Math.floor(s / 3600))} hours left`, tone: d < 2 ? 'text-amber-300' : 'text-emerald-300' };
  };
  const opts = [...new Set([own, ...domains])].filter(Boolean);
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">Throwaway addresses that deliver to {user}: one per sign-up form or shop. If one starts getting spam, you'll see exactly who leaked it, and you can turn it off without touching anything else.</p>
      <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 space-y-3">
        <div className="grid sm:grid-cols-2 gap-3">
          <Labelled label="What it's for"><input className={input} value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="e.g. Hardware store newsletter" maxLength={255} /></Labelled>
          <Labelled label="Domain"><Select value={domain} onChange={setDomain} options={opts.map((d) => ({ value: d, label: `@${d}` }))} searchable={opts.length > 8} /></Labelled>
        </div>
        <Labelled label="Works for"><Segmented value={dur} onChange={setDur} options={DURATIONS} /></Labelled>
        <div className="flex justify-end">
          <button disabled={!domain} onClick={() => run(() => send('POST', `/api/mailcow/mailboxes/${encodeURIComponent(user)}/spam-aliases`, { domain, description: desc, ...timing(dur) }), () => { setDesc(''); reload(); })}
            className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}><Plus className="w-3.5 h-3.5" /> Create a disposable address</button>
        </div>
      </div>
      {rows.length === 0 ? <p className="text-sm text-slate-500">No disposable addresses yet.</p> : (
        <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/80">
          {rows.map((a) => {
            const l = left(a);
            return (
              <div key={a.address} className="flex flex-wrap items-center gap-3 px-4 py-3">
                <div className="flex-1 min-w-[200px]">
                  <p className="text-sm font-mono text-white break-all">{a.address}</p>
                  <p className="text-[11px] text-slate-500">{a.description || 'no description'} · <span className={l.tone}>{l.text}</span></p>
                </div>
                <CopyButton text={a.address} />
                <button onClick={() => run(() => send('PATCH', `/api/mailcow/spam-aliases/${encodeURIComponent(a.address)}`, { hours: 720 }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Extend by a month"><Clock className="w-3.5 h-3.5" /> +1 month</button>
                {!on(a.permanent) && <button onClick={() => run(() => send('PATCH', `/api/mailcow/spam-aliases/${encodeURIComponent(a.address)}`, { permanent: true }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Keep forever"><Forever className="w-3.5 h-3.5" /></button>}
                <Confirm label="Turn this address off" onConfirm={() => run(() => send('DELETE', `/api/mailcow/spam-aliases/${encodeURIComponent(a.address)}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- sender allow / block lists

interface PolicyRow { prefid: number; value: string; object?: string }

export function SenderListsTab({ scope, target, run }: { scope: 'mailbox' | 'domain'; target: string; run: Run }) {
  const path = `/api/mailcow/policies?scope=${scope}&target=${encodeURIComponent(target)}`;
  const { data, reload } = useApi<{ wl: PolicyRow[]; bl: PolicyRow[] }>(path);
  const [from, setFrom] = useState('');
  const [kind, setKind] = useState<'wl' | 'bl'>('wl');
  const add = () => run(() => send('POST', '/api/mailcow/policies', { scope, target, from, list: kind }), () => { setFrom(''); reload(); });
  const col = (k: 'wl' | 'bl', title: string, icon: ReactNode, tone: string) => (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/40 overflow-hidden">
      <p className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b border-slate-800 ${tone}`}>{icon}{title} <span className="ml-auto text-slate-500 font-mono">{list(data?.[k]).length}</span></p>
      {list(data?.[k]).length === 0 ? <p className="px-4 py-3 text-xs text-slate-500">Nobody yet.</p> : (
        <div className="divide-y divide-slate-800/70 max-h-64 overflow-y-auto">
          {list(data?.[k]).map((p) => (
            <div key={p.prefid} className="flex items-center gap-2 px-4 py-2">
              <span className="flex-1 font-mono text-xs text-slate-200 break-all">{p.value}</span>
              <Confirm label="Remove" onConfirm={() => run(() => send('DELETE', `/api/mailcow/policies/${scope}/${p.prefid}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
            </div>
          ))}
        </div>
      )}
    </div>
  );
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">{scope === 'domain' ? `Senders every mailbox at ${target} always accepts or always refuses.` : `Senders ${target} always accepts or always refuses.`} Allowed senders skip the spam filter; blocked ones are rejected. Use an address, a domain (@example.org) or a pattern (*@*.example.org).</p>
      <div className="flex flex-wrap items-end gap-2">
        <Labelled label="Sender"><input className={`${input} w-72`} value={from} onChange={(e) => setFrom(e.target.value.trim().toLowerCase())} onKeyDown={(e) => e.key === 'Enter' && from && add()} placeholder="news@example.org or *@example.org" /></Labelled>
        <Segmented value={kind} onChange={setKind} options={[['wl', 'Always allow'], ['bl', 'Always block']]} />
        <button disabled={!from} onClick={add} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white py-2`}><Plus className="w-3.5 h-3.5" /> Add</button>
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        {col('wl', 'Always allowed', <ThumbsUp className="w-3.5 h-3.5" />, 'text-emerald-300')}
        {col('bl', 'Always blocked', <Ban className="w-3.5 h-3.5" />, 'text-rose-300')}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- domain footer

const SAMPLE = 'Hi Sam,<br><br>Thanks for getting back to me. The quote is attached; let me know if you have questions.<br><br>Best,<br>Alex';

export function FooterTab({ domain, run }: { domain: string; run: Run }) {
  const { data } = useApi<{ html: string; plain: string; skip_replies: boolean; exclude: string[] }>(`/api/mailcow/domains/${domain}/footer`);
  const [f, setF] = useState({ html: '', plain: '', skip_replies: false, exclude: [] as string[] });
  const [view, setView] = useState<'html' | 'plain'>('html');
  useEffect(() => { if (data) setF({ html: data.html || '', plain: data.plain || '', skip_replies: !!data.skip_replies, exclude: data.exclude || [] }); }, [data]);
  const toPlain = () => {
    const d = new DOMParser().parseFromString(f.html.replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li|tr|h\d)>/gi, '\n'), 'text/html');
    setF({ ...f, plain: (d.body.textContent || '').replace(/\n{3,}/g, '\n\n').trim() });
  };
  // the preview runs in a sandboxed frame with no scripts, like a mail client would show it
  const doc = `<!doctype html><meta charset="utf-8"><body style="font:14px/1.5 -apple-system,Segoe UI,sans-serif;color:#1e293b;background:#fff;margin:16px">${SAMPLE}<br><br>${f.html}</body>`;
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">Added to the bottom of every message sent from {domain}: a disclaimer, a signature block or legal details. You can use mailcow's placeholders, such as {'{= foo =}'} for a mailbox's custom attributes.</p>
      {!data ? <p className="text-sm text-slate-500">Loading…</p> : (
        <>
          <div className="grid lg:grid-cols-2 gap-4">
            <div className="space-y-3">
              <Segmented value={view} onChange={setView} options={[['html', 'HTML version'], ['plain', 'Plain-text version']]} />
              {view === 'html' ? (
                <textarea className={`${input} w-full h-56 font-mono text-xs`} value={f.html} onChange={(e) => setF({ ...f, html: e.target.value })} placeholder={'<p style="color:#64748b;font-size:12px">Example Ltd · Registered in …</p>'} />
              ) : (
                <>
                  <textarea className={`${input} w-full h-56 font-mono text-xs`} value={f.plain} onChange={(e) => setF({ ...f, plain: e.target.value })} placeholder="Example Ltd · Registered in …" />
                  <button type="button" onClick={toPlain} disabled={!f.html} className={`${btn} border border-slate-700 text-slate-300`}><RefreshCw className="w-3.5 h-3.5" /> Make it from the HTML version</button>
                </>
              )}
            </div>
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5"><Eye className="w-3.5 h-3.5" /> How a message will look</span>
              {view === 'html' ? (
                <iframe title="Footer preview" sandbox="" srcDoc={doc} className="w-full h-64 rounded-xl border border-slate-700 bg-white" />
              ) : (
                <pre className="w-full h-64 overflow-auto rounded-xl border border-slate-700 bg-white text-slate-800 text-xs p-4 whitespace-pre-wrap font-mono">{'Hi Sam,\n\nThanks for getting back to me. The quote is attached; let me know if you have questions.\n\nBest,\nAlex\n\n'}{f.plain}</pre>
              )}
            </div>
          </div>
          <SwitchRow value={f.skip_replies} onChange={(v) => setF({ ...f, skip_replies: v })} label="Leave replies alone" hint="Only add the footer to new messages, not to replies." />
          <Labelled label="Never add it for" hint="Mailboxes, aliases or alias domains that send without the footer."><TagInput value={f.exclude} onChange={(v) => setF({ ...f, exclude: v })} placeholder="An address or alias domain, then Enter" /></Labelled>
          <div className="flex justify-end gap-2">
            {(data.html || data.plain) && <Confirm label="Remove the footer" onConfirm={() => run(() => send('PUT', `/api/mailcow/domains/${domain}/footer`, { html: '', plain: '', skip_replies: false, exclude: [] }), () => setF({ html: '', plain: '', skip_replies: false, exclude: [] }))}><Trash2 className="w-3.5 h-3.5" /> Remove footer</Confirm>}
            <button onClick={() => run(() => send('PUT', `/api/mailcow/domains/${domain}/footer`, f))} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>Save footer</button>
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- alias domains

interface AliasDomain { alias_domain: string; target_domain: string; active: unknown; created?: string }

export function AliasDomainsTab({ domain, run }: { domain: string; run: Run }) {
  const { data, reload } = useApi<AliasDomain[]>('/api/mailcow/alias-domains');
  const [name, setName] = useState('');
  const rows = list(data).filter((a) => a.target_domain === domain);
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">Another domain that works as a mirror of {domain}: mail to alice@<i>alias-domain</i> reaches alice@{domain}. Useful for a short name, an old name or a common misspelling. The alias domain needs its own MX record pointing here.</p>
      <div className="flex flex-wrap items-end gap-2">
        <Labelled label="Alias domain"><input className={`${input} w-72`} value={name} onChange={(e) => setName(e.target.value.trim().toLowerCase())} placeholder="example.net" /></Labelled>
        <ArrowRight className="w-4 h-4 text-slate-500 mb-2.5" />
        <span className="font-mono text-sm text-slate-300 mb-2">{domain}</span>
        <button disabled={!name} onClick={() => run(() => send('POST', '/api/mailcow/alias-domains', { alias_domain: name, target_domain: domain, active: true }), () => { setName(''); reload(); })}
          className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white py-2 ml-auto`}><Plus className="w-3.5 h-3.5" /> Add alias domain</button>
      </div>
      {rows.length === 0 ? <p className="text-sm text-slate-500">No alias domains point here.</p> : (
        <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/80">
          {rows.map((a) => (
            <div key={a.alias_domain} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <span className="flex-1 font-mono text-sm text-white">{a.alias_domain} <span className="text-slate-500">→ {a.target_domain}</span></span>
              <Pill ok={on(a.active)} />
              <button onClick={() => run(() => send('PATCH', `/api/mailcow/alias-domains/${a.alias_domain}`, { active: !on(a.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{on(a.active) ? 'Pause' : 'Resume'}</button>
              <Confirm label="Remove alias domain" onConfirm={() => run(() => send('DELETE', `/api/mailcow/alias-domains/${a.alias_domain}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- DKIM key and rotation

interface Dkim { dkim_selector?: string; length?: string; dkim_txt?: string }
interface Rotation { pending: boolean; published?: boolean; current?: string[]; rotation?: { selector: string; key_size: number; name: string; value: string; created: string } }

const suggestSelector = () => { const d = new Date(); return `s${d.getFullYear()}${String(d.getMonth() + 1).padStart(2, '0')}`; };

export function DkimCard({ domain, domains, run, onChanged }: { domain: string; domains: string[]; run: Run; onChanged: () => void }) {
  const key = useApi<Dkim>(`/api/mailcow/dkim/${domain}`);
  const rot = useApi<Rotation>(`/api/mailcow/dkim/${domain}/rotation`);
  const [mode, setMode] = useState<'' | 'generate' | 'rotate' | 'copy'>('');
  const [selector, setSelector] = useState(suggestSelector());
  const [size, setSize] = useState('2048');
  const [targets, setTargets] = useState<string[]>([]);
  const has = !!key.data?.dkim_txt;
  const pending = rot.data?.pending ? rot.data : null;
  // while a rotation waits for DNS, check again every 20 seconds
  useEffect(() => {
    if (!pending || pending.published) return;
    const t = window.setInterval(rot.reload, 20000);
    return () => window.clearInterval(t);
  }, [pending?.published, !!pending]); // eslint-disable-line react-hooks/exhaustive-deps
  const done = () => { key.reload(); rot.reload(); onChanged(); setMode(''); };
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="w-9 h-9 rounded-xl flex items-center justify-center bg-violet-500/15 text-violet-300"><Signature className="w-4 h-4" /></span>
        <div className="flex-1 min-w-[180px]">
          <p className="text-sm font-semibold text-white">DKIM signing key</p>
          <p className="text-[11px] text-slate-400">{has ? <>Selector <span className="font-mono text-slate-200">{key.data?.dkim_selector}</span> · {key.data?.length}-bit RSA</> : 'No key yet: mail from this domain is not signed.'}</p>
        </div>
        {!pending && (has ? (
          <>
            <button onClick={() => setMode(mode === 'rotate' ? '' : 'rotate')} className={`${btn} bg-violet-600 hover:bg-violet-500 text-white`}><RotateCw className="w-3.5 h-3.5" /> Rotate key</button>
            <button onClick={() => setMode(mode === 'copy' ? '' : 'copy')} className={`${btn} border border-slate-700 text-slate-300`}><Copy className="w-3.5 h-3.5" /> Use for other domains</button>
            <Confirm label="Delete the key (mail stops being signed)" onConfirm={() => run(() => send('DELETE', `/api/mailcow/dkim/${domain}`), done)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
          </>
        ) : <button onClick={() => setMode('generate')} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><KeyRound className="w-3.5 h-3.5" /> Create a key</button>)}
      </div>

      {!pending && (mode === 'generate' || mode === 'rotate') && (
        <div className="space-y-3 border-t border-slate-800 pt-4 cs-page">
          {mode === 'rotate' && (
            <ol className="grid sm:grid-cols-3 gap-2 text-[11px] text-slate-400">
              {['CowSec makes a new key under a new selector. Nothing changes yet.', 'You publish its DNS record. CowSec watches DNS until it appears.', 'mailcow switches to the new key. No message goes out unsigned.'].map((s, i) => (
                <li key={s} className="rounded-xl border border-slate-800 p-2.5"><span className="font-bold text-violet-300">{i + 1}. </span>{s}</li>
              ))}
            </ol>
          )}
          <div className="flex flex-wrap items-end gap-3">
            <Labelled label="Selector" hint={mode === 'rotate' ? 'Must differ from the current one.' : 'The name in DNS: <selector>._domainkey'}>
              <input className={`${input} w-40 font-mono`} value={selector} onChange={(e) => setSelector(e.target.value.trim().toLowerCase())} />
            </Labelled>
            <Labelled label="Key size"><Segmented value={size} onChange={setSize} options={[['2048', '2048-bit'], ['3072', '3072'], ['4096', '4096']]} /></Labelled>
            <button disabled={!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(selector)} onClick={() => mode === 'generate'
              ? run(() => send('POST', '/api/mailcow/dkim', { domain, key_size: Number(size), selector }), done)
              : run(() => send('POST', `/api/mailcow/dkim/${domain}/rotation`, { selector, key_size: Number(size) }), () => { rot.reload(); setMode(''); })}
              className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white py-2`}>{mode === 'generate' ? 'Create key' : 'Make the new key'}</button>
          </div>
          {size !== '2048' && <p className="text-[11px] text-amber-300/90">Larger keys don't fit in one 255-character DNS string. Most DNS providers split them for you; some need it done by hand.</p>}
        </div>
      )}

      {!pending && mode === 'copy' && (
        <div className="space-y-3 border-t border-slate-800 pt-4 cs-page">
          <p className="text-xs text-slate-400">Sign other domains with this same key. Each domain still needs its own DNS record, which then shows in its checklist.</p>
          <Chips value={targets} onChange={setTargets} options={domains.filter((d) => d !== domain).map((d) => [d, d] as [string, string])} />
          <div className="flex justify-end"><button disabled={!targets.length} onClick={() => run(() => send('POST', '/api/mailcow/dkim/duplicate', { from: domain, to: targets }), () => { setTargets([]); done(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white py-2`}>Copy key to {targets.length || ''} domain{targets.length === 1 ? '' : 's'}</button></div>
        </div>
      )}

      {pending?.rotation && (
        <div className="space-y-3 border-t border-slate-800 pt-4 cs-page">
          <div className="flex items-center gap-2 text-sm font-semibold">
            {pending.published ? <><CheckCircle2 className="w-4 h-4 text-emerald-400 cs-pop" /><span className="text-emerald-200">The new record is live in DNS. Ready to switch.</span></>
              : <><Loader2 className="w-4 h-4 text-violet-300 animate-spin" /><span className="text-violet-200">Step 2 of 3: publish this record. CowSec is watching DNS for it.</span></>}
          </div>
          <div className="grid gap-2 text-xs">
            <div className="flex items-center gap-2"><span className="w-12 text-slate-500">Name</span><code className="flex-1 font-mono text-slate-200 break-all">{pending.rotation.name}</code><CopyButton text={pending.rotation.name} /></div>
            <div className="flex items-center gap-2"><span className="w-12 text-slate-500">Type</span><code className="font-mono text-sky-300">TXT</code></div>
            <div className="flex items-start gap-2"><span className="w-12 text-slate-500 pt-1">Value</span><code className="flex-1 font-mono text-slate-300 break-all leading-relaxed">{pending.rotation.value}</code><CopyButton text={pending.rotation.value} /></div>
          </div>
          <p className="text-[11px] text-slate-500">Keep the old record ({key.data?.dkim_selector}._domainkey) for about a week after switching, so messages already sent still verify. The new key is held in memory only: if CowSec restarts before you switch, simply start again.</p>
          <div className="flex flex-wrap justify-end gap-2">
            <button onClick={() => run(() => send('DELETE', `/api/mailcow/dkim/${domain}/rotation`), done)} className={`${btn} text-slate-400 hover:text-white`}>Cancel rotation</button>
            <button onClick={rot.reload} className={`${btn} border border-slate-700 text-slate-300`}><RefreshCw className={`w-3.5 h-3.5 ${rot.loading ? 'animate-spin' : ''}`} /> Check DNS now</button>
            {pending.published
              ? <button onClick={() => run(() => send('POST', `/api/mailcow/dkim/${domain}/rotation/finish`, {}), done)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white py-2`}><ShieldCheck className="w-3.5 h-3.5" /> Switch to the new key</button>
              : <Confirm danger={false} label="Switch now, before DNS shows the record (mail may fail DKIM until it does)" onConfirm={() => run(() => send('POST', `/api/mailcow/dkim/${domain}/rotation/finish`, { force: true }), done)}>Switch anyway</Confirm>}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- quarantine preview

interface Symbol { name: string; score: number; description?: string; options?: string[] }
interface QDetail {
  id: number; sender: string; rcpt: string; subject: string; score: number | string; action: string; ip?: string; created?: number;
  symbols?: Symbol[] | Record<string, Symbol>;
  preview: { headers: Record<string, string>; text: string; from_html: boolean; links: { text: string; href: string; host: string; mismatch: boolean }[]; attachments: { name: string; type: string; size: number }[]; truncated: boolean; error?: string };
}

const RISKY = /\.(exe|scr|js|jse|vbs|vbe|bat|cmd|com|pif|msi|hta|iso|img|lnk|jar|docm|xlsm|pptm|zip|rar|7z|html?)$/i;

export function QuarantinePreview({ id, onClose, run, onChanged }: { id: number; onClose: () => void; run: Run; onChanged: () => void }) {
  const { data, error } = useApi<QDetail>(`/api/mailcow/quarantine/${id}`);
  const [tab, setTab] = useState<'message' | 'why' | 'links'>('message');
  const symbols = useMemo(() => {
    const s = data?.symbols;
    const arr = Array.isArray(s) ? s : s ? Object.values(s) : [];
    return arr.filter((x) => x && typeof x.score === 'number').sort((a, b) => Math.abs(b.score) - Math.abs(a.score));
  }, [data?.symbols]);
  const max = Math.max(1, ...symbols.map((s) => Math.abs(s.score)));
  const senderAddr = (data?.sender || '').toLowerCase();
  const senderDomain = senderAddr.includes('@') ? `*@${senderAddr.split('@')[1]}` : '';
  const finish = () => { onChanged(); onClose(); };
  const policy = (list: 'wl' | 'bl', from: string) => run(() => send('POST', '/api/mailcow/policies', { scope: 'mailbox', target: data!.rcpt, from, list }));
  const p = data?.preview;
  const mism = (p?.links || []).filter((l) => l.mismatch).length;
  return (
    <Modal wide title={data?.subject || 'Quarantined message'} sub={data ? `${data.sender} → ${data.rcpt}` : 'Loading…'} icon={<Mail className="w-5 h-5" />} onClose={onClose}
      footer={data && <>
        <Confirm label="Delete" onConfirm={() => run(() => send('DELETE', `/api/mailcow/quarantine/${id}`), finish)}><Trash2 className="w-3.5 h-3.5" /> Delete</Confirm>
        <span className="flex-1" />
        <button onClick={() => run(() => send('POST', `/api/mailcow/quarantine/${id}/release`), finish)} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800 py-2`}><Send className="w-3.5 h-3.5" /> Release</button>
        <button onClick={() => run(() => send('POST', `/api/mailcow/quarantine/${id}/learnham`), finish)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white py-2`} title="Deliver it and teach rspamd that mail like this is fine"><ThumbsUp className="w-3.5 h-3.5" /> Release and learn as not spam</button>
      </>}>
      {error && <p className="text-sm text-rose-300">{error}</p>}
      {!data ? <p className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Opening the pen…</p> : (
        <>
          <div className="grid sm:grid-cols-4 gap-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-3"><p className="text-[11px] text-slate-500">Spam score</p><p className="text-2xl font-bold text-amber-300 font-mono">{Number(data.score).toFixed(1)}</p></div>
            <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-3"><p className="text-[11px] text-slate-500">rspamd decided</p><p className="text-sm font-semibold text-white mt-1.5">{data.action}</p></div>
            <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-3"><p className="text-[11px] text-slate-500">Sent from</p><p className="text-sm font-mono text-white mt-1.5">{data.ip || '—'}</p></div>
            <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-3"><p className="text-[11px] text-slate-500">Links · attachments</p><p className="text-sm font-semibold mt-1.5"><span className={mism ? 'text-rose-300' : 'text-white'}>{p?.links.length || 0}{mism ? ` (${mism} disguised)` : ''}</span><span className="text-slate-500"> · </span><span className={(p?.attachments || []).some((a) => RISKY.test(a.name)) ? 'text-rose-300' : 'text-white'}>{p?.attachments.length || 0}</span></p></div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-500">For {data.rcpt}:</span>
            <button onClick={() => policy('wl', senderAddr)} className={`${btn} border border-emerald-800 text-emerald-300 hover:bg-emerald-950/50`}><ThumbsUp className="w-3.5 h-3.5" /> Always allow {senderAddr}</button>
            <button onClick={() => policy('bl', senderAddr)} className={`${btn} border border-rose-900 text-rose-300 hover:bg-rose-950/50`}><Ban className="w-3.5 h-3.5" /> Always block {senderAddr}</button>
            {senderDomain && <button onClick={() => policy('bl', senderDomain)} className={`${btn} border border-rose-900 text-rose-300 hover:bg-rose-950/50`}><Ban className="w-3.5 h-3.5" /> Block all of {senderDomain.slice(2)}</button>}
          </div>
          <Tabs value={tab} onChange={setTab} tabs={[['message', 'Message', <FileText key="m" className="w-3.5 h-3.5" />], ['why', `Why it was held (${symbols.length})`, <AlertTriangle key="w" className="w-3.5 h-3.5" />], ['links', `Links and files (${(p?.links.length || 0) + (p?.attachments.length || 0)})`, <Link2 key="l" className="w-3.5 h-3.5" />]]} />
          {tab === 'message' && p && (
            <div className="space-y-3">
              {p.error && <p className="text-sm text-amber-300">{p.error}</p>}
              <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70 text-xs">
                {['From', 'Reply-To', 'Return-Path', 'To', 'Date', 'Authentication-Results', 'X-Mailer'].filter((h) => p.headers[h]).map((h) => (
                  <div key={h} className="grid grid-cols-[150px_1fr] gap-3 px-4 py-2"><span className="text-slate-500">{h}</span><span className="text-slate-200 break-all font-mono">{p.headers[h]}</span></div>
                ))}
              </div>
              <p className="text-[11px] text-slate-500 flex items-center gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> Shown as plain text{p.from_html ? ' (converted from HTML)' : ''}. Images, scripts and tracking pixels never load here.</p>
              <pre className="max-h-[420px] overflow-auto rounded-2xl border border-slate-800 bg-slate-950/60 p-4 text-xs text-slate-200 whitespace-pre-wrap break-words font-mono leading-relaxed">{p.text || '(no text)'}{p.truncated ? '\n\n…' : ''}</pre>
            </div>
          )}
          {tab === 'why' && (
            symbols.length === 0 ? <p className="text-sm text-slate-500">rspamd didn't record its reasons for this message.</p> : (
              <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70">
                {symbols.map((s) => (
                  <div key={s.name} className="grid grid-cols-[minmax(0,1fr)_120px_48px] items-center gap-3 px-4 py-2 text-xs">
                    <div className="min-w-0"><p className="font-mono text-slate-200">{s.name}</p>{s.description && <p className="text-[11px] text-slate-500">{s.description}</p>}{s.options?.length ? <p className="text-[11px] text-slate-600 font-mono truncate">{s.options.join(', ')}</p> : null}</div>
                    <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden"><div className={`h-full ${s.score > 0 ? 'bg-rose-400' : 'bg-emerald-400'}`} style={{ width: `${(Math.abs(s.score) / max) * 100}%` }} /></div>
                    <span className={`text-right font-mono ${s.score > 0 ? 'text-rose-300' : s.score < 0 ? 'text-emerald-300' : 'text-slate-500'}`}>{s.score > 0 ? '+' : ''}{s.score.toFixed(1)}</span>
                  </div>
                ))}
              </div>
            )
          )}
          {tab === 'links' && p && (
            <div className="space-y-4">
              <section className="space-y-2">
                <h4 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400 flex items-center gap-1.5"><Link2 className="w-3.5 h-3.5" /> Where the links really go</h4>
                {p.links.length === 0 ? <p className="text-xs text-slate-500">No web links.</p> : (
                  <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70">
                    {p.links.map((l, i) => (
                      <div key={i} className={`px-4 py-2 text-xs ${l.mismatch ? 'bg-rose-950/30' : ''}`}>
                        <p className="text-slate-300">{l.text || <span className="text-slate-500">(image or no text)</span>}{l.mismatch && <span className="ml-2 text-rose-300 font-semibold">⚠ the text shows a different address</span>}</p>
                        <p className="font-mono text-slate-500 break-all"><ExternalLink className="w-3 h-3 inline mr-1" /><span className="text-sky-300">{l.host}</span> · {l.href}</p>
                      </div>
                    ))}
                  </div>
                )}
              </section>
              <section className="space-y-2">
                <h4 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400 flex items-center gap-1.5"><Paperclip className="w-3.5 h-3.5" /> Attachments</h4>
                {p.attachments.length === 0 ? <p className="text-xs text-slate-500">None.</p> : (
                  <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70">
                    {p.attachments.map((a, i) => (
                      <div key={i} className="flex items-center gap-3 px-4 py-2 text-xs">
                        <Paperclip className={`w-3.5 h-3.5 ${RISKY.test(a.name) ? 'text-rose-300' : 'text-slate-500'}`} />
                        <span className="flex-1 text-slate-200 break-all">{a.name || '(unnamed)'}{RISKY.test(a.name) && <span className="ml-2 text-rose-300 font-semibold">risky file type</span>}</span>
                        <span className="text-slate-500 font-mono">{a.type}</span>
                        <span className="text-slate-500 font-mono w-20 text-right">{(a.size / 1024).toFixed(1)} KB</span>
                      </div>
                    ))}
                  </div>
                )}
              </section>
            </div>
          )}
        </>
      )}
    </Modal>
  );
}
