import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  Box,
  CheckCircle2,
  Clock,
  Cpu,
  FileText,
  Flame,
  Globe,
  Loader2,
  Lock,
  RefreshCw,
  RotateCw,
  Server,
  ShieldCheck,
  XCircle,
} from 'lucide-react';


interface Svc { name: string; state: string; sub: string; since: string; restarts: string }
interface HostStatus {
  host: string;
  uptime: string;
  load: number[];
  time: { source: string | null; offsetSeconds: number | null; stratum: string | null };
  crowdsecVersion: string | null;
  packages: Record<string, string | null>;
  services: Svc[];
  timers: Svc[];
  appsec: {
    listening: boolean;
    config: Record<string, string>;
    metrics: {
      'appsec-engine'?: Record<string, { processed?: number; blocked?: number }>;
      'appsec-rule'?: Record<string, Record<string, { triggered?: number }>>;
    };
  };
  lapi: { listening: boolean };
  acquisition: { acquisition?: Record<string, { reads?: number; parsed?: number; unparsed?: number; pour?: number; whitelisted?: number }> };
  bouncerMetrics: { bouncers?: Record<string, Record<string, { active_decisions?: { ip?: number }; dropped?: { byte?: number; packet?: number }; processed?: { byte?: number; packet?: number } }>> };
  firewall: { ipsets: Record<string, number | null>; iptablesRules: number };
  certificate: { notAfter: string | null; daysLeft: number | null; issuer: string | null; names: string[] } | null;
  cloudflareRealIP: { ranges: number; updated: string } | null;
  mailcowContainers: { running: number; total: number; unhealthy: string[] };
  setup?: { accessMode: string | null; edge: boolean | null; certMode: string | null };
}

const fmt = (n: number | undefined | null) => (n ?? 0).toLocaleString();
const bytes = (n: number | undefined) => {
  const v = n ?? 0;
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)} GB`;
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)} MB`;
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)} KB`;
  return `${v} B`;
};
const svcLabel: Record<string, string> = {
  crowdsec: 'Herd dog (CrowdSec engine + LAPI)',
  'crowdsec-firewall-bouncer': 'Gate bouncer (firewall)',
  openresty: 'Electric fence (OpenResty + AppSec)',
  chrony: 'Milking clock (chrony · KVM PTP)',
  cloudflared: 'Secret cattle path (Cloudflare Tunnel)',
  cowsec: 'CowSec console',
  'crowdsec-hubupdate.timer': 'Fresh hay (nightly hub update)',
  'cowsec-certs.timer': 'Re-branding (DNS-01 cert renewal + new domains)',
  'cowsec-cert-watch.path': "Reload the fence when mailcow renews its cert",
  'cowsec-cloudflare-realip.timer': 'Cloudflare real-IP refresh',
};
const originLabel = (o: string) =>
  o === 'CAPI' ? 'Wolf pack list (community CAPI)' : o === 'crowdsec' ? 'Spotted by our herd dog' : o.startsWith('lists:') ? `Wanted posters · ${o.slice(6)}` : o || 'All traffic through the gate';

export function Card({ title, icon, children, right }: { title: string; icon: ReactNode; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-white text-sm flex items-center space-x-2">
          {icon}
          <span>{title}</span>
        </h3>
        {right}
      </div>
      {children}
    </div>
  );
}

// Counts numbers up when they first appear or change ("37,903" animates from the last value).
export function useCountUp(target: number, ms = 900) {
  const [v, setV] = useState(target);
  const from = useRef(0);
  useEffect(() => {
    if (!Number.isFinite(target)) return;
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      setV(target);
      return;
    }
    const start = performance.now(), a = from.current;
    let raf = 0;
    const step = (t: number) => {
      const k = Math.min(1, (t - start) / ms);
      const e = 1 - Math.pow(1 - k, 3);
      setV(Math.round(a + (target - a) * e));
      if (k < 1) raf = requestAnimationFrame(step);
      else from.current = target;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return v;
}

function AnimatedValue({ value }: { value: string }) {
  // Animate plain numbers like "37,903" or "18"; leave text ("Herd safe", "63d", "18%") untouched.
  const m = /^-?[\d,]+$/.test(value.trim()) ? Number(value.replace(/,/g, '')) : NaN;
  const n = useCountUp(Number.isFinite(m) ? m : 0);
  return <>{Number.isFinite(m) ? n.toLocaleString() : value}</>;
}

export function Tile({ label, value, sub, tone, icon }: { label: string; value: string; sub: string; tone: 'emerald' | 'amber' | 'rose' | 'sky' | 'indigo'; icon: ReactNode }) {
  const tones = {
    emerald: 'from-emerald-500/15 border-emerald-500/30 text-emerald-300',
    amber: 'from-amber-500/15 border-amber-500/30 text-amber-300',
    rose: 'from-rose-500/15 border-rose-500/30 text-rose-300',
    sky: 'from-sky-500/15 border-sky-500/30 text-sky-300',
    indigo: 'from-indigo-500/15 border-indigo-500/30 text-indigo-300',
  }[tone];
  return (
    <div className={`rounded-2xl border bg-gradient-to-br to-transparent p-4 transition-transform duration-200 hover:-translate-y-0.5 ${tones}`}>
      <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        <span>{label}</span>
        {icon}
      </div>
      <p className="mt-2 text-2xl font-extrabold text-white font-mono tabular-nums"><AnimatedValue value={value} /></p>
      <p className="text-[11px] text-slate-400 mt-0.5">{sub}</p>
    </div>
  );
}

function StateBadge({ state }: { state: string }) {
  const ok = state === 'active';
  return (
    <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${ok ? 'text-emerald-400 bg-emerald-950/60' : 'text-rose-400 bg-rose-950/60'}`}>
      {ok ? 'Active' : state || 'unknown'}
    </span>
  );
}

const ACTIONS: { id: string; label: string; hint: string }[] = [
  { id: 'reload-crowdsec', label: 'Reload CrowdSec', hint: 'A gentle nudge: re-read config, hub items and scenarios' },
  { id: 'restart-crowdsec', label: 'Restart CrowdSec', hint: 'Wake the herd dog: full restart of engine + LAPI' },
  { id: 'restart-firewall-bouncer', label: 'Restart gate bouncer', hint: 'Rebuild the firewall gate (ipset blocklists)' },
  { id: 'reload-openresty', label: 'Re-wire the fence', hint: 'Reload OpenResty (config is tested first)' },
];

export default function HostPanel() {
  const [st, setSt] = useState<HostStatus | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [confirm, setConfirm] = useState('');
  const [running, setRunning] = useState('');
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/crowdsec/host/status', { cache: 'no-store' });
      if (!res.ok) throw new Error(await res.text());
      setSt(await res.json());
      setError('');
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(() => !document.hidden && load(), 15000);
    return () => clearInterval(t);
  }, []);

  const runAction = async (id: string) => {
    setConfirm('');
    setRunning(id);
    setResult(null);
    const res = await fetch('/api/crowdsec/host/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: id }),
    }).catch(() => null);
    const text = res ? await res.text() : 'Server unreachable';
    let message = text.trim();
    try {
      message = JSON.parse(text).message || message;
    } catch {
      // plain-text error from the server
    }
    setRunning('');
    setResult({ ok: !!res?.ok, text: message || (res?.ok ? 'Done' : 'Action failed') });
    setTimeout(load, 1500);
  };

  if (!st) {
    return (
      <div className="flex items-center justify-center py-16 text-sm text-slate-400 space-x-2">
        {error ? (
          <>
            <XCircle className="w-4 h-4 text-rose-400" />
            <span>The barn isn't answering: {error}</span>
          </>
        ) : (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Counting the herd…</span>
          </>
        )}
      </div>
    );
  }

  const servicesUp = st.services.filter((s) => s.state === 'active').length;
  const blocked = Object.values(st.firewall.ipsets).reduce<number>((a, b) => a + (b ?? 0), 0);
  const engine = Object.values(st.appsec.metrics['appsec-engine'] ?? {})[0] ?? {};
  const rules = Object.entries(Object.values(st.appsec.metrics['appsec-rule'] ?? {})[0] ?? {})
    .map(([name, v]) => ({ name, triggered: v.triggered ?? 0 }))
    .sort((a, b) => b.triggered - a.triggered);
  const acq = Object.entries(st.acquisition.acquisition ?? {})
    .filter(([src]) => src !== ':')
    .map(([src, v]) => ({ src, ...v }))
    .sort((a, b) => (b.reads ?? 0) - (a.reads ?? 0));
  const bouncers = st.bouncerMetrics.bouncers ?? {};
  const cert = st.certificate;
  const certTone = !cert || cert.daysLeft == null ? 'rose' : cert.daysLeft < 14 ? 'rose' : cert.daysLeft < 30 ? 'amber' : 'emerald';
  const edge = st.services.some((s) => s.name === 'openresty');
  const allUp = servicesUp === st.services.length && (!edge || st.appsec.listening);

  return (
    <div className="space-y-5">
      {/* Headline tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Tile label="Herd status" value={allUp ? 'Herd safe' : 'Udderly degraded'} sub={`${servicesUp}/${st.services.length} barn services · electric fence ${st.appsec.listening ? 'live' : 'off!'}`}
          tone={allUp ? 'emerald' : 'rose'} icon={allUp ? <ShieldCheck className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />} />
        <Tile label="Wolves at the gate" value={fmt(blocked)} sub={`blocked IPs · ${Object.keys(st.firewall.ipsets).length} sets · ${st.firewall.iptablesRules} firewall rules`} tone="rose" icon={<Flame className="w-4 h-4" />} />
        <Tile label="Zapped by the fence" value={fmt(engine.blocked)} sub={`of ${fmt(engine.processed)} web requests checked by AppSec`} tone="indigo" icon={<Activity className="w-4 h-4" />} />
        <Tile label="Brand (TLS cert)" value={cert?.daysLeft != null ? `${cert.daysLeft}d` : 'n/a'} sub={cert ? `${cert.issuer} · ${cert.names.length} names` : 'not found'} tone={certTone} icon={<Lock className="w-4 h-4" />} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        {/* Services & actions */}
        <Card title="Barn services & timers" icon={<Server className="w-4 h-4 text-sky-400" />}
          right={
            <button onClick={load} className="text-slate-400 hover:text-white cursor-pointer" title="Refresh">
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          }>
          <div className="divide-y divide-slate-800/80 text-xs">
            {[...st.services, ...st.timers].map((s) => (
              <div key={s.name} className="flex items-center justify-between py-2">
                <div className="min-w-0">
                  <p className="text-slate-200 font-medium">{svcLabel[s.name] || s.name}</p>
                  <p className="text-[11px] text-slate-500 font-mono truncate">
                    {s.name} · {s.sub}{s.since ? ` since ${s.since}` : ''}{s.restarts && s.restarts !== '0' ? ` · ${s.restarts} restarts` : ''}
                  </p>
                </div>
                <StateBadge state={s.state} />
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2 pt-1">
            {ACTIONS.filter((a) => a.id !== 'reload-openresty' || edge).map((a) => (
              <button key={a.id}
                onClick={() => (confirm === a.id ? runAction(a.id) : setConfirm(a.id))}
                disabled={!!running}
                title={a.hint}
                className={`flex items-center justify-center space-x-1.5 px-3 py-2 rounded-xl border text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50 ${
                  confirm === a.id ? 'border-amber-500/60 bg-amber-950/40 text-amber-200' : 'border-slate-700 bg-slate-800/40 text-slate-300 hover:text-white hover:border-slate-500'
                }`}>
                {running === a.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RotateCw className="w-3.5 h-3.5" />}
                <span>{confirm === a.id ? 'Moo again to confirm' : a.label}</span>
              </button>
            ))}
          </div>
          {result && (
            <p className={`text-xs rounded-lg px-3 py-2 border ${result.ok ? 'text-emerald-300 border-emerald-800/50 bg-emerald-950/30' : 'text-rose-300 border-rose-800/50 bg-rose-950/30'}`}>
              {result.text}
            </p>
          )}
        </Card>

        {/* Bouncers */}
        <Card title="Fence & gate bouncers" icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}>
          {Object.entries(bouncers).map(([name, origins]) => (
            <div key={name} className="space-y-2">
              <p className="text-xs font-semibold text-slate-300 font-mono truncate">{name}</p>
              <div className="rounded-xl border border-slate-800 bg-slate-950/40 divide-y divide-slate-800/80 text-xs">
                {Object.entries(origins).map(([origin, m]) => (
                  <div key={origin} className="flex items-center justify-between px-3 py-2">
                    <span className="text-slate-300">{originLabel(origin)}</span>
                    <span className="font-mono text-slate-400">
                      {m.active_decisions?.ip != null && <span className="text-rose-300">{fmt(m.active_decisions.ip)} IPs</span>}
                      {m.dropped && <span className="ml-3">dropped {bytes(m.dropped.byte)} / {fmt(m.dropped.packet)} pkts</span>}
                      {m.processed && <span>{bytes(m.processed.byte)} / {fmt(m.processed.packet)} pkts inspected</span>}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 text-xs space-y-1.5">
            <p className="font-semibold text-slate-300">OpenResty bouncer (HTTP + AppSec)</p>
            {Object.entries(st.appsec.config).map(([k, v]) => (
              <div key={k} className="flex justify-between font-mono">
                <span className="text-slate-500">{k}</span>
                <span className="text-slate-200">{v}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* AppSec engine */}
        <Card title="Electric fence (AppSec WAF)" icon={<Activity className="w-4 h-4 text-indigo-400" />}
          right={<span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${st.appsec.listening ? 'text-emerald-400 bg-emerald-950/60' : 'text-rose-400 bg-rose-950/60'}`}>{st.appsec.listening ? 'Fence live · :7422' : 'Fence is OFF'}</span>}>
          <div className="grid grid-cols-3 gap-3 text-center">
            {[
              ['Processed', fmt(engine.processed), 'text-slate-200'],
              ['Blocked', fmt(engine.blocked), 'text-rose-300'],
              ['Block rate', engine.processed ? `${(((engine.blocked ?? 0) / engine.processed) * 100).toFixed(1)}%` : '0%', 'text-amber-300'],
            ].map(([l, v, c]) => (
              <div key={l} className="rounded-xl border border-slate-800 bg-slate-950/40 py-3">
                <p className={`text-lg font-bold font-mono ${c}`}>{v}</p>
                <p className="text-[11px] text-slate-500">{l}</p>
              </div>
            ))}
          </div>
          <div className="text-xs space-y-1.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Most-zapped rules</p>
            {rules.length === 0 && <p className="text-slate-500">Nobody has touched the fence yet. Quiet pasture.</p>}
            {rules.slice(0, 8).map((r) => (
              <div key={r.name} className="flex items-center gap-2">
                <span className="font-mono text-slate-300 truncate flex-1">{r.name}</span>
                <div className="w-24 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-rose-500 to-amber-400" style={{ width: `${Math.max(6, (r.triggered / (rules[0]?.triggered || 1)) * 100)}%` }} />
                </div>
                <span className="font-mono text-rose-300 w-10 text-right">{r.triggered}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Log sources */}
        <Card title="Watering holes (log sources)" icon={<FileText className="w-4 h-4 text-amber-400" />}>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
                <th className="pb-2 font-semibold">Source</th>
                <th className="pb-2 font-semibold text-right">Read</th>
                <th className="pb-2 font-semibold text-right">Parsed</th>
                <th className="pb-2 font-semibold text-right">To buckets</th>
                <th className="pb-2 font-semibold w-20">Parse rate</th>
              </tr>
            </thead>
            <tbody>
              {acq.map((a) => {
                const rate = a.reads ? ((a.parsed ?? 0) / a.reads) * 100 : 0;
                return (
                  <tr key={a.src} className="border-t border-slate-800/80">
                    <td className="py-1.5 pr-2 font-mono text-slate-300 truncate max-w-[220px]" title={a.src}>
                      {a.src.replace('mailcowdockerized-', '').replace(/-mailcow-1$/, '')}
                    </td>
                    <td className="py-1.5 text-right font-mono text-slate-400">{fmt(a.reads)}</td>
                    <td className="py-1.5 text-right font-mono text-slate-300">{fmt(a.parsed)}</td>
                    <td className="py-1.5 text-right font-mono text-amber-300">{fmt(a.pour)}</td>
                    <td className="py-1.5 pl-2">
                      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                        <div className={`h-full ${rate > 80 ? 'bg-emerald-500' : rate > 30 ? 'bg-amber-500' : 'bg-rose-500'}`} style={{ width: `${rate}%` }} />
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Card>

        {/* Edge & TLS */}
        <Card title="Gate, brand & clock" icon={<Globe className="w-4 h-4 text-sky-400" />}>
          <div className="text-xs space-y-2">
            {[
              ['Certificate', cert ? `${cert.issuer} · expires ${cert.notAfter}` : 'not found'],
              ['Cloudflare real-IP', st.cloudflareRealIP ? `${st.cloudflareRealIP.ranges} ranges · refreshed ${st.cloudflareRealIP.updated}` : 'not configured'],
              ['Clock', `${st.time.source ?? '?'} · stratum ${st.time.stratum ?? '?'} · offset ${st.time.offsetSeconds != null ? `${(st.time.offsetSeconds * 1e6).toFixed(0)} µs` : '?'}`],
              ['Local API', st.lapi.listening ? '127.0.0.1:8080 listening' : 'not listening'],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-4">
                <span className="text-slate-500">{k}</span>
                <span className="text-slate-200 font-mono text-right">{v}</span>
              </div>
            ))}
          </div>
          {cert && (
            <div className="flex flex-wrap gap-1.5">
              {cert.names.map((n) => (
                <span key={n} className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-sky-500/10 border border-sky-400/20 text-sky-200">{n}</span>
              ))}
            </div>
          )}
        </Card>

        {/* Host */}
        <Card title="The barn (host)" icon={<Cpu className="w-4 h-4 text-violet-400" />}>
          <div className="text-xs space-y-2">
            {[
              ['Hostname', st.host],
              ['Uptime', st.uptime.replace(/^up /, '')],
              ['Load (1/5/15m)', st.load.join(' / ')],
              ['CrowdSec', st.crowdsecVersion ?? '?'],
            ].map(([k, v]) => (
              <div key={k} className="flex justify-between gap-4">
                <span className="text-slate-500">{k}</span>
                <span className="text-slate-200 font-mono text-right">{v}</span>
              </div>
            ))}
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-3 text-xs space-y-1.5">
            {Object.entries(st.packages).map(([p, v]) => (
              <div key={p} className="flex justify-between font-mono">
                <span className="text-slate-500">{p}</span>
                <span className="text-slate-200">{v ?? 'not installed'}</span>
              </div>
            ))}
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center space-x-1.5 text-slate-300">
              <Box className="w-3.5 h-3.5 text-sky-400" />
              <span>mailcow herd (containers)</span>
            </span>
            <span className={`font-mono font-semibold ${st.mailcowContainers.unhealthy.length ? 'text-amber-300' : 'text-emerald-300'}`}>
              {st.mailcowContainers.running}/{st.mailcowContainers.total} up
              {st.mailcowContainers.unhealthy.length > 0 && ` · ${st.mailcowContainers.unhealthy.join(', ')}`}
            </span>
          </div>
          <p className="text-[11px] text-slate-500 flex items-center space-x-1.5">
            <Clock className="w-3 h-3" />
            <span>Mooing back every 15 s</span>
            {allUp && <CheckCircle2 className="w-3 h-3 text-emerald-400 ml-1" />}
          </p>
        </Card>
      </div>
    </div>
  );
}
