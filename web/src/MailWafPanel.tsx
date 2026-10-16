// Electric Fence (Mail WAF): CowSec's AppSec config. Rules for the mail stack block in the
// request path; every other rule watches after the response and bans the scanners that trip it.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Ban, Eye, Loader2, Pin, PinOff, Power, RefreshCw, Search, ShieldCheck, Sparkles, Zap } from 'lucide-react';

type Mode = 'block' | 'watch' | 'off';
interface Rule { name: string; description: string; auto: 'block' | 'watch'; mode: Mode; override: boolean; installed: boolean }
interface Plan { config: string; active: string | null; rules: Rule[]; counts: Record<Mode, number> }

const btn = 'inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-1.5 cursor-pointer disabled:opacity-40';
const TONES: Record<string, [string, string]> = {
  emerald: ['border-emerald-500/60 bg-emerald-500/10', 'text-emerald-300'],
  rose: ['border-rose-500/60 bg-rose-500/10', 'text-rose-300'],
  slate: ['border-slate-500/60 bg-slate-500/10', 'text-slate-300'],
};
const short = (n: string) => n.replace(/^crowdsecurity\//, '').replace(/^vpatch-/, '');

// A request flows through the blocking rules to mailcow; the watch rules look afterwards and
// send scanners to the ban list. Dots move along each path.
function Flow({ block, watch }: { block: number; watch: number }) {
  return (
    <svg viewBox="0 0 720 150" className="w-full h-auto" role="img" aria-label={`Requests pass ${block} blocking rules on the way to mailcow; ${watch} watching rules check afterwards and ban scanners`}>
      <defs>
        <linearGradient id="mwf-a" x1="0" x2="1"><stop offset="0" stopColor="#38bdf8" /><stop offset="1" stopColor="#34d399" /></linearGradient>
        <linearGradient id="mwf-b" x1="0" x2="1"><stop offset="0" stopColor="#818cf8" /><stop offset="1" stopColor="#fb7185" /></linearGradient>
      </defs>
      <path id="mwf-main" d="M40,55 H680" stroke="url(#mwf-a)" strokeWidth="3" strokeDasharray="6 8" fill="none" className="cs-flowline" />
      <path id="mwf-side" d="M470,55 C500,55 500,118 540,118 H680" stroke="url(#mwf-b)" strokeWidth="2.5" strokeDasharray="4 7" fill="none" className="cs-flowline" />
      {[0, 1.2, 2.4].map((d) => (
        <circle key={d} r="5" fill="#7dd3fc"><animateMotion dur="3.6s" begin={`${d}s`} repeatCount="indefinite"><mpath href="#mwf-main" /></animateMotion></circle>
      ))}
      <circle r="4" fill="#fb7185"><animateMotion dur="3.6s" begin="1.8s" repeatCount="indefinite"><mpath href="#mwf-side" /></animateMotion></circle>
      <g fontFamily="inherit" fontSize="13">
        <rect x="8" y="34" width="86" height="42" rx="12" className="fill-slate-900 stroke-slate-700" />
        <text x="51" y="60" textAnchor="middle" className="fill-slate-200" fontWeight="600">Request</text>
        <rect x="190" y="22" width="190" height="66" rx="16" className="fill-emerald-950 stroke-emerald-600" strokeWidth="1.5" />
        <text x="285" y="50" textAnchor="middle" className="fill-emerald-200" fontWeight="700">{block} blocking rules</text>
        <text x="285" y="70" textAnchor="middle" className="fill-emerald-300/80" fontSize="11">in the request path</text>
        <rect x="600" y="34" width="112" height="42" rx="12" className="fill-slate-900 stroke-sky-600" />
        <text x="656" y="60" textAnchor="middle" className="fill-sky-200" fontWeight="600">mailcow</text>
        <rect x="540" y="100" width="172" height="40" rx="12" className="fill-rose-950 stroke-rose-700" />
        <text x="626" y="118" textAnchor="middle" className="fill-rose-200" fontWeight="700">{watch} watching rules</text>
        <text x="626" y="133" textAnchor="middle" className="fill-rose-300/80" fontSize="10.5">after the reply · ban scanners</text>
      </g>
    </svg>
  );
}

export default function MailWafPanel() {
  const [plan, setPlan] = useState<Plan | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [filter, setFilter] = useState<'all' | Mode | 'pinned'>('all');
  const [q, setQ] = useState('');
  const load = () => {
    fetch('/api/crowdsec/appsec/plan', { cache: 'no-store' })
      .then(async (r) => { if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`); return r.json(); })
      .then((d) => { setPlan(d); setError(''); })
      .catch((e) => setError(String(e instanceof Error ? e.message : e)));
  };
  useEffect(load, []);
  const post = async (key: string, url: string, body?: unknown) => {
    setBusy(key);
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
      if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
      load();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy('');
    }
  };
  const setMode = async (rule: Rule, mode: Mode | 'auto') => {
    if (mode === 'off') return post(rule.name, '/api/crowdsec/appsec/toggle', { rule: rule.name, enabled: false });
    if (!rule.installed) {
      setBusy(rule.name);
      await fetch('/api/crowdsec/appsec/toggle', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rule: rule.name, enabled: true }) });
    }
    return post(rule.name, '/api/crowdsec/appsec/mode', { rule: rule.name, mode: mode === rule.auto && rule.override ? 'auto' : mode });
  };
  const rules = useMemo(() => (plan?.rules || []).filter((r) => {
    if (filter === 'pinned' ? !r.override : filter !== 'all' && r.mode !== filter) return false;
    const t = q.trim().toLowerCase();
    return !t || r.name.toLowerCase().includes(t) || r.description.toLowerCase().includes(t);
  }), [plan, filter, q]);
  if (error && !plan) return <div className="rounded-2xl border border-rose-900 bg-rose-950/40 p-4 text-sm text-rose-200">{error}</div>;
  if (!plan) return <p className="flex items-center gap-2 text-sm text-slate-400 p-6"><Loader2 className="w-4 h-4 animate-spin" /> Inspecting the fence…</p>;
  const ours = plan.active === plan.config;
  const c = plan.counts;
  return (
    <div className="space-y-5">
      <div className="rounded-2xl border border-indigo-800/40 bg-gradient-to-r from-indigo-950/60 via-slate-900/80 to-emerald-950/40 p-5 space-y-4">
        <div className="flex flex-wrap items-start gap-3">
          <div className="flex-1 min-w-[260px] space-y-1.5">
            <h3 className="flex items-center gap-2 text-base font-bold text-white"><ShieldCheck className="w-4 h-4 text-emerald-300" /> Mail WAF</h3>
            <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
              Rules for the mail stack (mailcow's PHP admin, webmail, nginx) <b className="text-emerald-300">block</b> in the request path.
              Every other rule only <b className="text-rose-300">watches</b>: it checks after the reply has gone, so it never slows anyone down or blocks a real request, and bans the scanners that trip it.
            </p>
          </div>
          <button onClick={load} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className="w-3.5 h-3.5" /> Refresh</button>
        </div>
        {!ours && (
          <div className="flex flex-wrap items-center gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm">
            <Zap className="w-4 h-4 text-amber-300" />
            <span className="flex-1 text-amber-100">The edge uses <code className="font-mono">{plan.active || 'no AppSec config'}</code>, which puts every rule in the request path.</span>
            <button disabled={!!busy} onClick={() => post('curate', '/api/crowdsec/appsec/curate')} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}>
              {busy === 'curate' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />} Switch to the mail WAF
            </button>
          </div>
        )}
        <Flow block={c.block} watch={c.watch} />
        <div className="grid grid-cols-3 gap-3">
          {([['block', 'Blocking', 'Checked before mailcow sees the request', 'emerald', <ShieldCheck key="i" className="w-4 h-4" />],
            ['watch', 'Watching', 'Checked after the reply; trips ban scanners', 'rose', <Eye key="i" className="w-4 h-4" />],
            ['off', 'Off', 'Not installed', 'slate', <Power key="i" className="w-4 h-4" />]] as [Mode, string, string, string, ReactNode][]).map(([m, label, sub, tone, icon]) => (
            <button key={m} onClick={() => setFilter(filter === m ? 'all' : m)} className={`text-left rounded-xl border p-3 cursor-pointer transition-colors ${filter === m ? TONES[tone][0] : 'border-slate-800 bg-slate-950/40 hover:border-slate-700'}`}>
              <p className={`flex items-center gap-1.5 text-xs font-semibold ${TONES[tone][1]}`}>{icon}{label}</p>
              <p className="text-2xl font-bold font-mono text-white">{c[m]}</p>
              <p className="text-[11px] text-slate-500">{sub}</p>
            </button>
          ))}
        </div>
      </div>

      {error && <div className="rounded-xl border border-rose-900 bg-rose-950/40 px-4 py-2 text-sm text-rose-200">{error}</div>}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search rules, products or CVEs" className="bg-slate-950/60 border border-slate-700 rounded-lg pl-8 pr-3 py-1.5 text-sm text-white w-72 focus:outline-none focus:border-sky-500" />
        </div>
        {(['all', 'block', 'watch', 'off', 'pinned'] as const).map((f) => (
          <button key={f} onClick={() => setFilter(f)} className={`${btn} border ${filter === f ? 'border-sky-500 bg-sky-500/15 text-white' : 'border-slate-800 text-slate-400 hover:text-white'}`}>
            {{ all: `All (${plan.rules.length})`, block: 'Blocking', watch: 'Watching', off: 'Off', pinned: 'Changed by you' }[f]}
          </button>
        ))}
      </div>

      <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70 overflow-hidden">
        {rules.length === 0 && <p className="px-4 py-6 text-sm text-slate-500">No rules match.</p>}
        {rules.map((r) => (
          <div key={r.name} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2.5">
            <div className="flex-1 min-w-[240px]">
              <p className="text-sm font-mono text-slate-100 flex items-center gap-2">
                {short(r.name)}
                {r.override ? <span className="inline-flex items-center gap-1 text-[10px] font-sans font-semibold text-amber-300"><Pin className="w-3 h-3" />your choice</span>
                  : r.installed && <span className="text-[10px] font-sans text-slate-500">automatic</span>}
              </p>
              <p className="text-xs text-slate-400 line-clamp-2">{r.description || 'AppSec rule'}</p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {r.override && <button disabled={!!busy} onClick={() => post(r.name, '/api/crowdsec/appsec/mode', { rule: r.name, mode: 'auto' })} className="p-1 text-slate-500 hover:text-white cursor-pointer" title={`Back to automatic (${r.auto})`}><PinOff className="w-3.5 h-3.5" /></button>}
              <div className="inline-flex rounded-lg border border-slate-700 bg-slate-950/60 p-0.5">
                {([['block', 'Block', <ShieldCheck key="i" className="w-3 h-3" />, 'bg-emerald-600'], ['watch', 'Watch', <Eye key="i" className="w-3 h-3" />, 'bg-rose-600'], ['off', 'Off', <Ban key="i" className="w-3 h-3" />, 'bg-slate-600']] as [Mode, string, ReactNode, string][]).map(([m, label, icon, on]) => (
                  <button key={m} disabled={!!busy || r.mode === m} onClick={() => setMode(r, m)}
                    className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold cursor-pointer disabled:cursor-default ${r.mode === m ? `${on} text-white` : 'text-slate-400 hover:text-white'}`}>
                    {busy === r.name && r.mode !== m ? null : icon}{label}
                  </button>
                ))}
              </div>
              {busy === r.name && <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-400" />}
            </div>
          </div>
        ))}
      </div>
      <p className="text-[11px] text-slate-500">New rules from hub updates watch by default; new patches for mail products (Roundcube, SOGo, Zimbra, Exchange, webmail, nginx) block automatically. Your own choices are kept across updates.</p>
    </div>
  );
}
