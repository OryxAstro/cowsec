// Deliverability for The Farm: MTA-STS per domain, the Show Ribbons scorecard (a prize
// rosette per domain), and the new-domain wizard (domain, DKIM, DNS turning green, first mailbox).
import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  AlertTriangle, ArrowRight, Award, CheckCircle2, CircleDashed, Copy, Globe, KeyRound, Loader2, Lock, Mail, RefreshCw,
  Server, ShieldCheck, Sparkles, XCircle,
} from 'lucide-react';
import { Card } from './HostPanel';
import { Labelled, Modal, Segmented, SwitchRow, TagInput } from './MailcowForms';
import { btn, Header, input, Loading, NotConfigured, Problem, send, useApi } from './MailcowPanels';

type Run = (fn: () => Promise<string>, after?: () => void) => Promise<void>;

// ---------------------------------------------------------------- MTA-STS tab

interface Sts { active: boolean; mode: 'enforce' | 'testing' | 'none'; max_age: number; mx: string[]; id?: string; exists: boolean }
const AGES: [string, string][] = [['86400', '1 day'], ['604800', '1 week'], ['2592000', '30 days'], ['31536000', '1 year']];

export function MtaStsTab({ domain, run }: { domain: string; run: Run }) {
  const { data, reload } = useApi<{ policy: Sts; hostname: string; served: boolean }>(`/api/mailcow/domains/${domain}/mta-sts`);
  const [f, setF] = useState<Sts | null>(null);
  useEffect(() => { if (data) setF(data.policy); }, [data]);
  if (!data || !f) return <p className="text-sm text-slate-400">Loading…</p>;
  const age = AGES.find(([v]) => Number(v) === f.max_age)?.[0] || '86400';
  return (
    <div className="space-y-5">
      <p className="text-sm text-slate-400">MTA-STS tells other mail servers to always use an encrypted, verified connection when they deliver to {domain}, so nobody in the middle can quietly downgrade it. Start in <b>testing</b>, then switch to <b>enforce</b>.</p>
      <SwitchRow value={f.active} onChange={(v) => setF({ ...f, active: v })} label="Publish an MTA-STS policy" hint={f.active && data.policy.active ? (data.served ? 'Live: other servers can fetch the policy.' : 'Saved, but not reachable yet: publish the DNS records below.') : undefined} />
      {f.active && (
        <div className="space-y-4 cs-page">
          <Labelled label="Mode">
            <Segmented value={f.mode} onChange={(v) => setF({ ...f, mode: v })} options={[['testing', 'Testing (report only)'], ['enforce', 'Enforce'], ['none', 'Off (withdraw)']]} />
          </Labelled>
          <Labelled label="Senders remember the policy for"><Segmented value={age} onChange={(v) => setF({ ...f, max_age: Number(v) })} options={AGES} /></Labelled>
          <Labelled label="Mail servers allowed to receive" hint={`Usually just this server: ${data.hostname}`}><TagInput value={f.mx} onChange={(v) => setF({ ...f, mx: v })} placeholder="mail.example.org, then Enter" /></Labelled>
          <div className="rounded-xl border border-slate-800 bg-slate-950/50 p-4 text-xs space-y-2">
            <p className="font-semibold text-slate-200">DNS records to publish</p>
            <p className="font-mono text-slate-300 break-all">mta-sts.{domain} CNAME {data.hostname}</p>
            <p className="font-mono text-slate-300 break-all">_mta-sts.{domain} TXT "v=STSv1; id={f.id || '…shown after saving'}"</p>
            <p className="font-mono text-slate-400 break-all">_smtp._tls.{domain} TXT "v=TLSRPTv1; rua=mailto:postmaster@{domain}" <span className="font-sans text-slate-500">(optional: daily TLS reports)</span></p>
            <p className="text-slate-500">They're also in this domain's DNS checklist, checked live. The certificate must cover mta-sts.{domain}; CowSec's DNS-01 certificates do.</p>
          </div>
        </div>
      )}
      <div className="flex justify-end">
        <button onClick={() => run(() => send('PUT', `/api/mailcow/domains/${domain}/mta-sts`, f), reload)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>Save MTA-STS</button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- Show Ribbons (deliverability)

interface Check { id: string; label: string; state: 'ok' | 'warn' | 'fail' | 'info'; detail: string; fix?: string; points: number; max: number }
interface DomainScore { domain: string; score: number; grade: string; checks: Check[] }
interface Listing { ip: string; list: string; url: string; state: 'clean' | 'listed' | 'unknown'; answer?: string }
interface Scores { checked: string; server: { hostname: string; ips: string[]; ptr: Record<string, string[]>; ptr_ok: boolean; blocklists: Listing[]; listed: boolean }; domains: DomainScore[] }

const RIBBON: Record<string, [string, string, string]> = {
  A: ['#10b981', '#34d399', 'Best in show'], B: ['#0ea5e9', '#38bdf8', 'First prize'], C: ['#f59e0b', '#fbbf24', 'Highly commended'],
  D: ['#f97316', '#fb923c', 'Needs grooming'], F: ['#e11d48', '#fb7185', 'Back to the barn'],
};

// A prize rosette: petals in the grade's colour, a ring that fills to the score, and tails.
function Rosette({ grade, score, size = 96 }: { grade: string; score: number; size?: number }) {
  const [a, b] = RIBBON[grade] || RIBBON.F;
  const [shown, setShown] = useState(0);
  useEffect(() => { const t = window.setTimeout(() => setShown(score), 80); return () => window.clearTimeout(t); }, [score]);
  const petals = Array.from({ length: 14 }, (_, i) => i * (360 / 14));
  return (
    <svg viewBox="0 0 100 120" width={size} height={size * 1.2} role="img" aria-label={`Grade ${grade}, ${score} out of 100`} className="shrink-0">
      <path d="M38,70 L28,116 L40,108 L46,118 L50,74 Z" fill={a} opacity=".85" />
      <path d="M62,70 L72,116 L60,108 L54,118 L50,74 Z" fill={b} opacity=".85" />
      <g transform="translate(50 50)">
        {petals.map((r) => <ellipse key={r} rx="9" ry="20" transform={`rotate(${r}) translate(0 -24)`} fill={r % 2 ? a : b} opacity=".9" />)}
        <circle r="27" fill="#0b1220" />
        <circle r="24" fill="none" stroke="#1e293b" strokeWidth="4" />
        <circle r="24" fill="none" stroke={b} strokeWidth="4" strokeLinecap="round" transform="rotate(-90)"
          strokeDasharray={`${(shown / 100) * 150.8} 150.8`} style={{ transition: 'stroke-dasharray 1.1s cubic-bezier(.2,.8,.2,1)' }} />
        <text y="5" textAnchor="middle" fontSize="22" fontWeight="800" fill="#f8fafc">{grade}</text>
        <text y="17" textAnchor="middle" fontSize="7" fill="#94a3b8">{score}/100</text>
      </g>
    </svg>
  );
}

const STATE_ICON: Record<Check['state'], ReactNode> = {
  ok: <CheckCircle2 className="w-4 h-4 text-emerald-400" />, warn: <AlertTriangle className="w-4 h-4 text-amber-400" />,
  fail: <XCircle className="w-4 h-4 text-rose-400" />, info: <CircleDashed className="w-4 h-4 text-slate-500" />,
};

function DomainCard({ d }: { d: DomainScore }) {
  const [open, setOpen] = useState(d.grade !== 'A');
  const [, , title] = RIBBON[d.grade] || RIBBON.F;
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/40 p-4 space-y-3 cs-pop">
      <div className="flex items-center gap-4">
        <Rosette grade={d.grade} score={d.score} size={78} />
        <div className="flex-1 min-w-0">
          <p className="text-lg font-bold text-white truncate">{d.domain}</p>
          <p className="text-xs text-slate-400">{title}</p>
          <div className="mt-2 flex flex-wrap gap-1">
            {d.checks.map((c) => <span key={c.id} title={`${c.label}: ${c.detail}`} className={`w-2.5 h-2.5 rounded-full ${c.state === 'ok' ? 'bg-emerald-400' : c.state === 'warn' ? 'bg-amber-400' : c.state === 'fail' ? 'bg-rose-400' : 'bg-slate-600'}`} />)}
          </div>
        </div>
        <button onClick={() => setOpen(!open)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{open ? 'Hide' : 'Details'}</button>
      </div>
      {open && (
        <div className="divide-y divide-slate-800/70 rounded-xl border border-slate-800 cs-page">
          {d.checks.map((c) => (
            <div key={c.id} className="flex items-start gap-3 px-3 py-2 text-xs">
              <span className="mt-0.5">{STATE_ICON[c.state]}</span>
              <div className="flex-1 min-w-0">
                <p className="font-semibold text-slate-200">{c.label} <span className="font-normal text-slate-400">{c.detail}</span></p>
                {c.fix && <p className="text-slate-500 mt-0.5 break-words">→ {c.fix}</p>}
              </div>
              <span className="font-mono text-slate-500 shrink-0">{c.points}/{c.max}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function DeliverabilityPanel() {
  const [refresh, setRefresh] = useState(0);
  const { data, error, loading, notConfigured } = useApi<Scores>(`/api/mailcow/deliverability${refresh ? `?refresh=${refresh}` : ''}`);
  if (notConfigured) return <NotConfigured />;
  const s = data?.server;
  const listed = (s?.blocklists || []).filter((l) => l.state === 'listed');
  return (
    <div className="space-y-6">
      <Header title="Show Ribbons (Deliverability)" sub="How every domain will fare at other people's mail servers, graded"
        action={<button onClick={() => setRefresh(Date.now())} disabled={loading} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Judge again</button>} />
      {error && <Problem text={error} />}
      {!data ? <Loading text="The judges are inspecting the herd (DNS, reverse DNS and blocklists)…" /> : (
        <>
          <Card title="The server" icon={<Server className="w-4 h-4 text-sky-400" />}>
            <div className="grid md:grid-cols-3 gap-4 text-sm">
              <div className="space-y-1">
                <p className="text-[11px] uppercase tracking-wider text-slate-500">Address</p>
                {s!.ips.map((ip) => <p key={ip} className="font-mono text-slate-200">{ip}</p>)}
                <p className="text-xs text-slate-500">{s!.hostname}</p>
              </div>
              <div className="space-y-1">
                <p className="text-[11px] uppercase tracking-wider text-slate-500">Reverse DNS</p>
                <p className={`flex items-center gap-1.5 font-semibold ${s!.ptr_ok ? 'text-emerald-300' : 'text-rose-300'}`}>{s!.ptr_ok ? <CheckCircle2 className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}{s!.ptr_ok ? 'Matches the hostname' : 'Doesn\'t match'}</p>
                {Object.entries(s!.ptr).map(([ip, n]) => <p key={ip} className="text-xs text-slate-500 font-mono break-all">{ip} → {(n || []).join(', ') || 'none'}</p>)}
              </div>
              <div className="space-y-1">
                <p className="text-[11px] uppercase tracking-wider text-slate-500">Blocklists</p>
                <p className={`flex items-center gap-1.5 font-semibold ${listed.length ? 'text-rose-300' : 'text-emerald-300'}`}>{listed.length ? <XCircle className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}{listed.length ? `Listed on ${listed.length}` : 'Not listed'}</p>
                <div className="flex flex-wrap gap-1.5">
                  {Object.values(s!.blocklists.reduce((acc, l) => {
                    const rank = { listed: 2, unknown: 1, clean: 0 } as const;
                    const cur = acc[l.list];
                    if (!cur || rank[l.state] > rank[cur.state]) acc[l.list] = { ...l, answer: l.state === 'listed' ? `${l.ip}: ${l.answer}` : l.answer };
                    return acc;
                  }, {} as Record<string, Listing>)).map((l) => (
                    <a key={l.list} href={l.url} target="_blank" rel="noreferrer" title={l.answer || l.state}
                      className={`text-[11px] px-2 py-0.5 rounded-md border ${l.state === 'listed' ? 'border-rose-700 bg-rose-950/50 text-rose-200' : l.state === 'unknown' ? 'border-slate-700 text-slate-500' : 'border-emerald-900 text-emerald-300'}`}>
                      {l.list}{l.state === 'unknown' ? ' ?' : ''}
                    </a>
                  ))}
                </div>
                {s!.blocklists.some((l) => l.state === 'unknown') && <p className="text-[11px] text-slate-500">? = couldn't be checked: this server's DNS resolver doesn't pass blocklist queries through (common with public or filtering resolvers).</p>}
              </div>
            </div>
          </Card>
          {data.domains.length === 0 ? <p className="text-sm text-slate-500">No domains yet.</p> : (
            <div className="grid lg:grid-cols-2 gap-4 cs-stagger">{data.domains.map((d) => <DomainCard key={d.domain} d={d} />)}</div>
          )}
          <p className="text-[11px] text-slate-500">Checked {new Date(data.checked).toLocaleString()}. Results are kept for 10 minutes; "Judge again" checks now. DNS changes can take up to a day to show.</p>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- new-domain wizard

interface Rec { name: string; type: string; expected: string; state: string; optional: boolean }

export function NewDomainWizard({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [step, setStep] = useState(0);
  const [domain, setDomain] = useState('');
  const [desc, setDesc] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [recs, setRecs] = useState<Rec[] | null>(null);
  const [lp, setLp] = useState('postmaster');
  const [made, setMade] = useState<{ user: string; password: string } | null>(null);
  const timer = useRef<number | undefined>(undefined);
  const valid = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain);
  const call = async (method: string, path: string, body?: unknown) => {
    const r = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  };
  const create = async () => {
    setBusy(true); setErr('');
    try {
      await call('POST', '/api/mailcow/domains', { domain, description: desc, active: true });
      const key = await call('GET', `/api/mailcow/dkim/${domain}`).catch(() => ({}));
      if (!key.dkim_txt) await call('POST', '/api/mailcow/dkim', { domain, key_size: 2048, selector: 'dkim' }).catch(() => {});
      setStep(1);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); } finally { setBusy(false); }
  };
  const check = () => call('GET', `/api/mailcow/dns/${domain}`).then((d) => setRecs(d.records)).catch(() => {});
  useEffect(() => {
    if (step !== 1) return;
    check();
    timer.current = window.setInterval(check, 20000);
    return () => window.clearInterval(timer.current);
  }, [step]); // eslint-disable-line react-hooks/exhaustive-deps
  const needed = (recs || []).filter((r) => !r.optional && r.state !== 'info' && !r.type.startsWith('A') && r.type !== 'PTR' && r.type !== 'TLSA');
  const good = needed.filter((r) => r.state === 'ok').length;
  const makeMailbox = async () => {
    setBusy(true); setErr('');
    const pw = Array.from(crypto.getRandomValues(new Uint8Array(18)), (b) => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 56]).join('');
    try {
      await call('POST', '/api/mailcow/mailboxes', { local_part: lp, domain, password: pw, name: lp === 'postmaster' ? 'Postmaster' : lp, active: true });
      setMade({ user: `${lp}@${domain}`, password: pw }); setStep(3); onDone();
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); } finally { setBusy(false); }
  };
  const STEPS = ['Domain', 'DNS', 'First mailbox', 'Done'];
  return (
    <Modal wide title="Add a domain" sub="Domain, signing key and DNS, step by step" icon={<Sparkles className="w-5 h-5" />} onClose={onClose}>
      <ol className="flex flex-wrap items-center gap-2 text-xs">
        {STEPS.map((s, i) => (
          <li key={s} className={`flex items-center gap-2 ${i <= step ? 'text-white' : 'text-slate-500'}`}>
            <span className={`w-6 h-6 rounded-full flex items-center justify-center font-bold transition-colors ${i < step ? 'bg-emerald-500 text-white' : i === step ? 'bg-sky-600 text-white' : 'bg-slate-800'}`}>{i < step ? '✓' : i + 1}</span>{s}
            {i < STEPS.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-slate-600" />}
          </li>
        ))}
      </ol>
      {err && <Problem text={err} />}
      {step === 0 && (
        <div className="space-y-4 cs-page">
          <div className="grid sm:grid-cols-2 gap-3">
            <Labelled label="Domain name"><input autoFocus className={input} value={domain} onChange={(e) => setDomain(e.target.value.trim().toLowerCase())} placeholder="example.org" /></Labelled>
            <Labelled label="Description (optional)"><input className={input} value={desc} onChange={(e) => setDesc(e.target.value)} /></Labelled>
          </div>
          <p className="text-xs text-slate-500">CowSec creates the domain with mailcow's defaults (you can change limits later) and a 2048-bit DKIM key, then walks you through DNS.</p>
          <div className="flex justify-end"><button disabled={!valid || busy} onClick={create} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>{busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Globe className="w-3.5 h-3.5" />} Create {domain || 'domain'}</button></div>
        </div>
      )}
      {step === 1 && (
        <div className="space-y-4 cs-page">
          <div className="flex items-center gap-4 rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
            <Rosette grade={good === needed.length && needed.length ? 'A' : good >= needed.length - 1 ? 'B' : good > 1 ? 'C' : 'F'} score={needed.length ? Math.round((good / needed.length) * 100) : 0} size={64} />
            <div className="text-sm">
              <p className="font-semibold text-white">{recs ? `${good} of ${needed.length} records in place` : 'Asking DNS…'}</p>
              <p className="text-xs text-slate-400">Add these at your DNS provider. CowSec checks every 20 seconds; most changes show within minutes.</p>
            </div>
          </div>
          <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70 max-h-[46vh] overflow-y-auto">
            {needed.map((r) => (
              <div key={r.name + r.type} className="grid sm:grid-cols-[24px_minmax(0,1fr)_90px_minmax(0,1.6fr)] gap-3 px-4 py-2.5 text-xs items-start">
                <span>{r.state === 'ok' ? <CheckCircle2 className="w-4 h-4 text-emerald-400 cs-pop" /> : r.state === 'mismatch' ? <AlertTriangle className="w-4 h-4 text-amber-400" /> : <Loader2 className="w-4 h-4 text-slate-500 animate-spin" />}</span>
                <span className="font-mono text-slate-200 break-all">{r.name}</span>
                <span className="font-mono text-sky-300">{r.type}</span>
                <span className="flex items-start gap-1 font-mono text-slate-300 break-all">{r.expected}<button onClick={() => navigator.clipboard?.writeText(r.expected).catch(() => {})} className="p-0.5 text-slate-500 hover:text-white cursor-pointer" title="Copy"><Copy className="w-3.5 h-3.5" /></button></span>
              </div>
            ))}
          </div>
          <div className="flex flex-wrap justify-between gap-2">
            <button onClick={check} className={`${btn} border border-slate-700 text-slate-300`}><RefreshCw className="w-3.5 h-3.5" /> Check now</button>
            <button onClick={() => setStep(2)} className={`${btn} bg-sky-600 hover:bg-sky-500 text-white px-4 py-2`}>{good === needed.length ? 'All green: next' : 'Continue, I\'ll finish DNS later'} <ArrowRight className="w-3.5 h-3.5" /></button>
          </div>
        </div>
      )}
      {step === 2 && (
        <div className="space-y-4 cs-page">
          <p className="text-sm text-slate-400">Every domain should have a postmaster mailbox: other servers send delivery problems and reports there. CowSec makes it with a strong password.</p>
          <div className="flex items-center gap-2 max-w-md">
            <input className={`${input} flex-1`} value={lp} onChange={(e) => setLp(e.target.value.trim().toLowerCase())} /><span className="text-slate-500">@{domain}</span>
          </div>
          <div className="flex justify-between">
            <button onClick={() => { setStep(3); onDone(); }} className={`${btn} text-slate-400 hover:text-white`}>Skip</button>
            <button disabled={!lp || busy} onClick={makeMailbox} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>{busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Mail className="w-3.5 h-3.5" />} Create mailbox</button>
          </div>
        </div>
      )}
      {step === 3 && (
        <div className="space-y-4 text-center py-4 cs-pop">
          <Award className="w-12 h-12 text-amber-300 mx-auto cs-m-wobble" />
          <p className="text-lg font-bold text-white">{domain} is in the herd</p>
          {made && (
            <div className="max-w-md mx-auto rounded-xl border border-emerald-700/60 bg-emerald-950/40 p-3 text-left space-y-1">
              <p className="text-xs text-emerald-200 flex items-center gap-1.5"><KeyRound className="w-3.5 h-3.5" /> {made.user}: copy the password now, it isn't shown again.</p>
              <code className="block font-mono text-sm text-white bg-slate-950/70 rounded-lg px-3 py-2 select-all break-all">{made.password}</code>
            </div>
          )}
          <p className="text-xs text-slate-400">Turn on MTA-STS and set a footer from the domain's edit page. Check its rosette in Show Ribbons.</p>
          <button onClick={onClose} className={`${btn} bg-sky-600 hover:bg-sky-500 text-white px-4 py-2`}><Lock className="w-3.5 h-3.5" /> Done</button>
        </div>
      )}
    </Modal>
  );
}

// "Open in mailcow as this domain admin": a single-use token, valid for 30 seconds. The tab
// opens on the click (browsers block tabs opened later) and is sent to mailcow once the token arrives.
export function openAsDomainAdmin(user: string, run: Run) {
  const tab = window.open('about:blank', '_blank');
  return run(async () => {
    try {
      const r = await fetch(`/api/mailcow/domain-admins/${encodeURIComponent(user)}/sso`, { method: 'POST' });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      if (tab) { tab.opener = null; tab.location.href = d.url; } else window.location.href = d.url;
      return `Opened mailcow as ${user}`;
    } catch (e) {
      tab?.close();
      throw e;
    }
  });
}
