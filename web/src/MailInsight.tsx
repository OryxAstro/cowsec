// Mail insight for The Farm: the Herd Health dashboard (mail flow, spam, refusals, bounces and
// failed sign-ins over 24 hours, 7 days or 30 days) and Hoofprints, the mail trail that follows one
// message from the gate to the mailbox. Both read the history CowSec's collector keeps.
import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  Activity, AlertTriangle, ArrowDownLeft, ArrowRight, ArrowUpRight, Ban, CheckCircle2, Clock, Copy, Footprints, HeartPulse, Inbox, KeyRound,
  Mail, MailWarning, Package, RefreshCw, Repeat, Search, Send, ShieldAlert, ShieldCheck, Undo2, Users, X, XCircle,
} from 'lucide-react';
import { Card } from './HostPanel';
import { Modal, Segmented } from './MailcowForms';
import { btn, Header, input, Loading, NotConfigured, Problem, send, useApi } from './MailcowPanels';

type Counts = Record<string, number>;
interface Point { t: number; c: Counts }
interface Health {
  from: number; to: number; step: number; series: Point[]; total: Counts; previous: Counts;
  mailboxes: { user: string; c: Counts }[]; reasons: { reason: string; count: number }[];
  since: number; gaps: number[]; last_poll?: number; error?: string;
}
interface Row { id: string; time: number; from: string; to: string[]; subject?: string; status: string; direction: string; spam: boolean; score?: number; user?: string; ip?: string; door?: boolean }
interface Hop { to: string; orig_to?: string; status: string; relay?: string; local: boolean; dsn?: string; reason?: string; delay?: number; first: number; time: number; attempts: number }
interface Verdict { action: string; score: number; required: number; symbols?: { name: string; score: number }[]; time: number }
interface Refusal { stage: 'door' | 'content'; code: string; reason: string; temporary: boolean; time: number }
interface Message {
  id: string; time: number; updated: number; from: string; to: string[]; subject?: string; message_id?: string; size?: number; client?: string; ip?: string;
  user?: string; via?: string; helo?: string; refused?: Refusal; verdict?: Verdict; hops: Hop[]; notice?: string; notice_for?: string; done: boolean;
}
interface Detail { message: Message; status: string; direction: string; spam: boolean; notice?: Row; notice_for?: Row }
interface Trail { messages: Row[]; found: number; kept: number; oldest: number; days: number }

const sum = (c: Counts | undefined, ...k: string[]) => k.reduce((a, x) => a + ((c && c[x]) || 0), 0);
const n = (v: number) => v.toLocaleString('en-GB');
const tzOffset = () => -new Date().getTimezoneOffset();

const clock = (t: number) => new Date(t * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
function when(t: number) {
  const d = new Date(t * 1000), today = new Date();
  if (d.toDateString() === today.toDateString()) return clock(t);
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) + ' ' + clock(t);
}
function bucketLabel(t: number, step: number) {
  const d = new Date(t * 1000);
  if (step <= 3600) return clock(t);
  if (step < 86400) return d.toLocaleDateString('en-GB', { weekday: 'short' }) + ' ' + clock(t);
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}
const bucketRange = (t: number, step: number) => (step < 86400 ? `${bucketLabel(t, step)}–${clock(t + step)}` : bucketLabel(t, step));

// ---------------------------------------------------------------- Herd Health

const TILES: { key: string; label: string; kinds: string[]; icon: ReactNode; color: string; good: 'up' | 'down' | 'none'; sub: string }[] = [
  { key: 'received', label: 'Received', kinds: ['received'], icon: <ArrowDownLeft className="w-4 h-4" />, color: '#38bdf8', good: 'none', sub: 'messages from outside, delivered' },
  { key: 'sent', label: 'Sent', kinds: ['sent'], icon: <Send className="w-4 h-4" />, color: '#818cf8', good: 'none', sub: 'messages your users sent' },
  { key: 'spam', label: 'Spam caught', kinds: ['spam', 'junk'], icon: <ShieldCheck className="w-4 h-4" />, color: '#f472b6', good: 'none', sub: 'refused or sent to Junk by rspamd' },
  { key: 'refused', label: 'Turned away', kinds: ['refused', 'greylisted'], icon: <Ban className="w-4 h-4" />, color: '#fbbf24', good: 'none', sub: 'refused at the gate, before delivery' },
  { key: 'bounced', label: 'Bounced', kinds: ['bounced'], icon: <Undo2 className="w-4 h-4" />, color: '#fb923c', good: 'down', sub: 'recipients that never got it' },
  { key: 'authfail', label: 'Failed sign-ins', kinds: ['authfail'], icon: <KeyRound className="w-4 h-4" />, color: '#fb7185', good: 'down', sub: 'wrong passwords, SMTP and IMAP' },
];

function Sparkline({ values, color, id }: { values: number[]; color: string; id: string }) {
  const w = 200, h = 30, max = Math.max(1, ...values);
  if (values.length < 2) return <svg className="w-full" height={h} />;
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, h - 2 - (v / max) * (h - 6)]);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  return (
    <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="w-full overflow-visible" style={{ height: h }} aria-hidden="true">
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2={h} gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor={color} stopOpacity="0.45" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${line} L${w},${h} L0,${h} Z`} fill={`url(#${id})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" className="cs-draw" />
    </svg>
  );
}

function Delta({ now, before, good }: { now: number; before: number; good: 'up' | 'down' | 'none' }) {
  if (!before && !now) return <span className="text-[11px] text-slate-500">no change</span>;
  if (!before) return <span className="text-[11px] text-slate-500">new this period</span>;
  const pct = Math.round(((now - before) / before) * 100);
  if (pct === 0) return <span className="text-[11px] text-slate-500">same as before</span>;
  const better = good === 'none' ? null : (good === 'down') === pct < 0;
  const tone = better === null ? 'text-slate-300 bg-slate-800' : better ? 'text-emerald-300 bg-emerald-950/60' : 'text-rose-300 bg-rose-950/60';
  return <span className={`text-[11px] font-semibold px-1.5 py-0.5 rounded ${tone}`}>{pct > 0 ? '▲' : '▼'} {Math.abs(pct)}%</span>;
}

function StatTile({ tile, h }: { tile: (typeof TILES)[number]; h: Health }) {
  const now = sum(h.total, ...tile.kinds), before = sum(h.previous, ...tile.kinds);
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/40 p-4 flex flex-col gap-2 transition-transform duration-200 hover:-translate-y-0.5">
      <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        <span>{tile.label}</span>
        <span style={{ color: tile.color }}>{tile.icon}</span>
      </div>
      <div className="flex items-center justify-between gap-2">
        <p className="text-2xl font-extrabold text-white font-mono tabular-nums">{n(now)}</p>
        <Delta now={now} before={before} good={tile.good} />
      </div>
      <Sparkline values={h.series.map((p) => sum(p.c, ...tile.kinds))} color={tile.color} id={`spark-${tile.key}`} />
      <span className="text-[11px] text-slate-500 leading-snug">{tile.sub}</span>
    </div>
  );
}

const FLOW: { key: string; label: string; kinds: string[]; color: string }[] = [
  { key: 'in', label: 'Into mailboxes', kinds: ['delivered_local'], color: '#38bdf8' },
  { key: 'out', label: 'Out to other servers', kinds: ['delivered_remote'], color: '#818cf8' },
  { key: 'spam', label: 'Spam caught', kinds: ['spam', 'junk'], color: '#f472b6' },
  { key: 'away', label: 'Turned away', kinds: ['refused', 'greylisted'], color: '#fbbf24' },
  { key: 'bounced', label: 'Bounced or delayed', kinds: ['bounced', 'deferred'], color: '#fb923c' },
];

function niceMax(v: number) {
  if (v <= 4) return 4;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

function FlowChart({ h }: { h: Health }) {
  const [hide, setHide] = useState<Record<string, boolean>>({});
  const [hover, setHover] = useState<number | null>(null);
  const [grown, setGrown] = useState(false);
  useEffect(() => { setGrown(false); const t = setTimeout(() => setGrown(true), 30); return () => clearTimeout(t); }, [h.from, h.step]);
  const layers = FLOW.filter((f) => !hide[f.key]);
  const totals = h.series.map((p) => layers.reduce((a, f) => a + sum(p.c, ...f.kinds), 0));
  const max = niceMax(Math.max(...totals, 0));
  const W = 900, H = 240, L = 36, B = 26, plotW = W - L - 8, plotH = H - B - 8;
  const bw = plotW / Math.max(1, h.series.length);
  const every = Math.ceil(h.series.length / 8);
  const hp = hover !== null ? h.series[hover] : null;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        {FLOW.map((f) => (
          <button key={f.key} onClick={() => setHide({ ...hide, [f.key]: !hide[f.key] })}
            className={`inline-flex items-center gap-1.5 text-xs rounded-full px-2.5 py-1 border cursor-pointer transition-opacity ${hide[f.key] ? 'opacity-40 border-slate-800' : 'border-slate-700'}`}>
            <span className="w-2.5 h-2.5 rounded-sm" style={{ background: f.color }} /> {f.label}
            <span className="font-mono text-slate-400">{n(sum(h.total, ...f.kinds))}</span>
          </button>
        ))}
      </div>
      <div className="relative">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label="Mail flow over time" onMouseLeave={() => setHover(null)}>
          {[0, 0.25, 0.5, 0.75, 1].map((f) => (
            <g key={f}>
              <line x1={L} x2={W - 8} y1={8 + plotH * (1 - f)} y2={8 + plotH * (1 - f)} className="stroke-slate-800" strokeDasharray={f ? '3 4' : undefined} />
              <text x={L - 6} y={12 + plotH * (1 - f)} textAnchor="end" className="fill-slate-500 text-[10px] font-mono">{n(Math.round(max * f))}</text>
            </g>
          ))}
          {h.series.map((p, i) => {
            let y = 8 + plotH;
            const x = L + i * bw;
            return (
              <g key={p.t} onMouseEnter={() => setHover(i)}>
                <rect x={x} y={8} width={bw} height={plotH} fill="transparent" />
                {hover === i && <rect x={x} y={8} width={bw} height={plotH} className="fill-slate-700/30" />}
                {layers.map((f) => {
                  const v = sum(p.c, ...f.kinds);
                  if (!v) return null;
                  const hh = (v / max) * plotH;
                  y -= hh;
                  return <rect key={f.key} x={x + bw * 0.15} y={y} width={bw * 0.7} height={Math.max(hh - 1, 1)} rx={Math.min(3, bw * 0.15)} fill={f.color}
                    style={{ transformOrigin: `0 ${8 + plotH}px`, transform: grown ? 'scaleY(1)' : 'scaleY(0)', transition: `transform 700ms cubic-bezier(.2,.8,.2,1) ${i * 12}ms` }} />;
                })}
                {i % every === 0 && <text x={x + bw / 2} y={H - 8} textAnchor="middle" className="fill-slate-500 text-[10px]">{bucketLabel(p.t, h.step)}</text>}
              </g>
            );
          })}
        </svg>
        {hp && (
          <div className="pointer-events-none absolute top-2 rounded-xl border border-slate-700 bg-slate-950/95 px-3 py-2 text-xs shadow-xl"
            style={{ left: `${Math.min(80, ((L + (hover! + 0.5) * bw) / W) * 100)}%` }}>
            <p className="font-semibold text-white mb-1">{bucketRange(hp.t, h.step)}</p>
            {FLOW.map((f) => (
              <p key={f.key} className="flex items-center gap-2 text-slate-300"><span className="w-2 h-2 rounded-sm" style={{ background: f.color }} />{f.label}<span className="ml-auto pl-3 font-mono">{n(sum(hp.c, ...f.kinds))}</span></p>
            ))}
            <p className="flex items-center gap-2 text-slate-400 mt-1 pt-1 border-t border-slate-800"><KeyRound className="w-3 h-3" />Failed sign-ins<span className="ml-auto pl-3 font-mono">{n(sum(hp.c, 'authfail'))}</span></p>
          </div>
        )}
      </div>
    </div>
  );
}

function AuthChart({ h }: { h: Health }) {
  const vals = h.series.map((p) => sum(p.c, 'authfail'));
  const max = niceMax(Math.max(...vals, 0));
  const W = 440, H = 150, L = 30, B = 22, pw = W - L - 6, ph = H - B - 8;
  const pts = vals.map((v, i) => [L + (vals.length < 2 ? 0 : (i / (vals.length - 1)) * pw), 8 + ph - (v / max) * ph]);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  const peak = vals.indexOf(Math.max(...vals));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label="Failed sign-ins over time">
      <defs>
        <linearGradient id="authfill" x1="0" y1="8" x2="0" y2={8 + ph} gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#fb7185" stopOpacity="0.4" />
          <stop offset="1" stopColor="#fb7185" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 0.5, 1].map((f) => (
        <g key={f}>
          <line x1={L} x2={W - 6} y1={8 + ph * (1 - f)} y2={8 + ph * (1 - f)} className="stroke-slate-800" strokeDasharray={f ? '3 4' : undefined} />
          <text x={L - 5} y={12 + ph * (1 - f)} textAnchor="end" className="fill-slate-500 text-[10px] font-mono">{n(Math.round(max * f))}</text>
        </g>
      ))}
      {pts.length > 1 && <path d={`${line} L${pts[pts.length - 1][0]},${8 + ph} L${L},${8 + ph} Z`} fill="url(#authfill)" />}
      {pts.length > 1 && <path d={line} fill="none" stroke="#fb7185" strokeWidth="2" strokeLinejoin="round" className="cs-draw" />}
      {vals[peak] > 0 && (
        <g>
          <circle cx={pts[peak][0]} cy={pts[peak][1]} r="4" fill="#fb7185" className="cs-zap" />
          <text x={pts[peak][0] + 8} y={Math.max(pts[peak][1] + 4, 16)} textAnchor="start" className="fill-rose-200 text-[10px] font-semibold">{n(vals[peak])}</text>
        </g>
      )}
      {h.series.map((p, i) => i % Math.ceil(h.series.length / 4) === 0 && (
        <text key={p.t} x={pts[i][0]} y={H - 6} textAnchor="middle" className="fill-slate-500 text-[10px]">{bucketLabel(p.t, h.step)}</text>
      ))}
    </svg>
  );
}

const reasonColor = (r: string) => (r.startsWith('Spam') || r.startsWith('Sent to Junk') ? '#f472b6' : r.startsWith('Bounced') || r.startsWith('Delayed') ? '#fb923c' : '#fbbf24');

export function HerdHealthPanel() {
  const [range, setRange] = useState<'24h' | '7d' | '30d'>(() => {
    try { return (localStorage.getItem('cowsec_health_range') as '24h' | '7d' | '30d') || '24h'; } catch { return '24h'; }
  });
  const { data, error, notConfigured, loading, reload } = useApi<Health>(`/api/mailcow/insight/health?range=${range}&tz=${tzOffset()}`);
  const [refreshing, setRefreshing] = useState(false);
  useEffect(() => { try { localStorage.setItem('cowsec_health_range', range); } catch { /* storage unavailable */ } }, [range]);
  useEffect(() => { const t = setInterval(reload, 60000); return () => clearInterval(t); }, [reload]);
  if (notConfigured) return <NotConfigured />;
  const refresh = async () => {
    setRefreshing(true);
    await send('POST', '/api/mailcow/insight/refresh').catch(() => {});
    setTimeout(() => { reload(); setRefreshing(false); }, 3000);
  };
  const boxMax = Math.max(1, ...(data?.mailboxes || []).map((m) => sum(m.c, 'sent', 'delivered_local')));
  const reasonMax = Math.max(1, ...(data?.reasons || []).map((r) => r.count));
  const empty = data && !data.since;
  return (
    <div className="space-y-6">
      <Header title="Herd Health (Dashboard)" sub="How the farm's mail is flowing: what came in, what went out, and what was kept out"
        action={
          <div className="flex items-center gap-2">
            <Segmented value={range} onChange={setRange} options={[['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days']]} />
            <button onClick={refresh} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`} title="Read mailcow's logs now">
              <RefreshCw className={`w-3.5 h-3.5 ${loading || refreshing ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        } />
      {error && <Problem text={error} />}
      {data?.error && <Problem text={`Couldn't read mailcow's logs: ${data.error}`} />}
      {!data ? <Loading text="Counting the herd…" /> : empty ? (
        <Card title="Counting the herd" icon={<HeartPulse className="w-4 h-4 text-rose-300" />}>
          <p className="text-sm text-slate-400">CowSec reads mailcow's logs every minute and keeps its own history, because mailcow only keeps the last few thousand lines. The first numbers appear after the first read; give it a minute.</p>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
            {TILES.map((t) => <StatTile key={t.key} tile={t} h={data} />)}
          </div>

          <Card title="Mail flow" icon={<Activity className="w-4 h-4 text-sky-400" />}
            right={<span className="text-xs text-slate-500">{data.step === 3600 ? 'per hour' : data.step === 86400 ? 'per day' : 'per 6 hours'}</span>}>
            <FlowChart h={data} />
          </Card>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Failed sign-ins" icon={<KeyRound className="w-4 h-4 text-rose-300" />}
              right={<span className="text-xs text-slate-500">{n(sum(data.total, 'authfail'))} in this period</span>}>
              <AuthChart h={data} />
              <p className="text-xs text-slate-500">Wrong passwords over SMTP, IMAP and POP3. CrowdSec bans addresses that keep trying; a steady climb against one mailbox is worth a look in the Lookout.</p>
            </Card>
            <Card title="Why mail didn't get through" icon={<Ban className="w-4 h-4 text-amber-300" />}>
              {data.reasons.length === 0 ? <p className="text-sm text-slate-500">Everything got through in this period: nothing refused, delayed or bounced.</p> : (
                <div className="space-y-2">
                  {data.reasons.map((r, i) => (
                    <div key={r.reason} className="grid grid-cols-[minmax(0,1fr)_8rem_auto] items-center gap-3 text-xs">
                      <span className="truncate text-slate-300" title={r.reason}>{r.reason}</span>
                      <div className="h-2.5 rounded-full bg-slate-800 overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${(r.count / reasonMax) * 100}%`, transitionDelay: `${i * 60}ms`, background: reasonColor(r.reason) }} />
                      </div>
                      <span className="font-mono text-slate-300 w-10 text-right">{n(r.count)}</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>

          <Card title="Mailboxes" icon={<Users className="w-4 h-4 text-indigo-300" />}
            right={<span className="text-xs text-slate-500">busiest first</span>}>
            {data.mailboxes.length === 0 ? <p className="text-sm text-slate-500">No mailbox sent or received mail in this period.</p> : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
                      <th className="py-2 pr-3 font-semibold">Mailbox</th><th className="py-2 px-3 font-semibold">Activity</th>
                      <th className="py-2 px-3 font-semibold text-right">Sent</th><th className="py-2 px-3 font-semibold text-right">Received</th>
                      <th className="py-2 px-3 font-semibold text-right">Bounced</th><th className="py-2 px-3 font-semibold text-right">Failed sign-ins</th><th />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {data.mailboxes.map((m) => {
                      const s = sum(m.c, 'sent'), r = sum(m.c, 'delivered_local');
                      return (
                        <tr key={m.user} className="hover:bg-slate-800/30">
                          <td className="py-2 pr-3 font-semibold text-slate-200 truncate max-w-[16rem]" title={m.user}>{m.user}</td>
                          <td className="py-2 px-3 w-48">
                            <div className="flex h-2.5 rounded-full bg-slate-800 overflow-hidden">
                              <div className="h-full bg-indigo-400 transition-all duration-700" style={{ width: `${(s / boxMax) * 100}%` }} />
                              <div className="h-full bg-sky-400 transition-all duration-700" style={{ width: `${(r / boxMax) * 100}%` }} />
                            </div>
                          </td>
                          <td className="py-2 px-3 text-right font-mono text-slate-300">{n(s)}</td>
                          <td className="py-2 px-3 text-right font-mono text-slate-300">{n(r)}</td>
                          <td className={`py-2 px-3 text-right font-mono ${sum(m.c, 'bounced') ? 'text-orange-300' : 'text-slate-500'}`}>{n(sum(m.c, 'bounced'))}</td>
                          <td className={`py-2 px-3 text-right font-mono ${sum(m.c, 'authfail') ? 'text-rose-300' : 'text-slate-500'}`}>{n(sum(m.c, 'authfail'))}</td>
                          <td className="py-2 pl-3 text-right">
                            <a href={`#/trail/${encodeURIComponent(m.user)}`} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Follow this mailbox's mail"><Footprints className="w-3.5 h-3.5" /></a>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <p className="text-xs text-slate-500">
            CowSec has been counting since {when(data.since)}{data.last_poll ? `, last read ${clock(data.last_poll)}` : ''}. Counts are kept for 31 days.
            {data.gaps.length > 0 && <span className="text-amber-300"> mailcow's log filled up faster than it was read around {data.gaps.map(when).join(', ')}, so counts around then are low.</span>}
          </p>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- Hoofprints (mail trail)

const STATUS: Record<string, { label: string; tone: string; icon: ReactNode }> = {
  delivered: { label: 'Delivered', tone: 'text-emerald-300 bg-emerald-950/60 border-emerald-800/60', icon: <CheckCircle2 className="w-3.5 h-3.5" /> },
  deferred: { label: 'Delayed', tone: 'text-amber-300 bg-amber-950/60 border-amber-800/60', icon: <Clock className="w-3.5 h-3.5" /> },
  bounced: { label: 'Bounced', tone: 'text-orange-300 bg-orange-950/60 border-orange-800/60', icon: <Undo2 className="w-3.5 h-3.5" /> },
  refused: { label: 'Refused', tone: 'text-rose-300 bg-rose-950/60 border-rose-800/60', icon: <Ban className="w-3.5 h-3.5" /> },
  greylisted: { label: 'Greylisted', tone: 'text-slate-300 bg-slate-800 border-slate-700', icon: <Clock className="w-3.5 h-3.5" /> },
  partial: { label: 'Partly delivered', tone: 'text-amber-300 bg-amber-950/60 border-amber-800/60', icon: <MailWarning className="w-3.5 h-3.5" /> },
  queued: { label: 'In the queue', tone: 'text-sky-300 bg-sky-950/60 border-sky-800/60', icon: <Package className="w-3.5 h-3.5" /> },
};

function StatusPill({ status, spam }: { status: string; spam?: boolean }) {
  const s = STATUS[status] || STATUS.queued;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-md border ${s.tone}`}>{s.icon}{s.label}</span>
      {spam && <span className="text-[11px] font-semibold px-2 py-0.5 rounded-md border text-pink-300 bg-pink-950/60 border-pink-800/60">{status === 'delivered' ? 'Junk' : 'Spam'}</span>}
    </span>
  );
}

const DIR: Record<string, [string, ReactNode]> = {
  in: ['Incoming', <ArrowDownLeft key="i" className="w-4 h-4 text-sky-300" />],
  out: ['Outgoing', <ArrowUpRight key="i" className="w-4 h-4 text-indigo-300" />],
  internal: ['Between your mailboxes', <Repeat key="i" className="w-4 h-4 text-emerald-300" />],
  system: ["Postfix's own notice", <Mail key="i" className="w-4 h-4 text-slate-400" />],
};

export function MailTrailPanel() {
  const initial = useMemo(() => {
    const rest = window.location.hash.replace(/^#\/?trail\/?/, '');
    return rest && !rest.startsWith('#') ? decodeURIComponent(rest) : '';
  }, []);
  const [q, setQ] = useState(initial);
  const [debounced, setDebounced] = useState(initial);
  const [status, setStatus] = useState('');
  const [dir, setDir] = useState<'' | 'in' | 'out' | 'internal'>('');
  const [open, setOpen] = useState('');
  useEffect(() => { const t = setTimeout(() => setDebounced(q), 300); return () => clearTimeout(t); }, [q]);
  const { data, error, notConfigured, loading, reload } = useApi<Trail>(`/api/mailcow/trail?q=${encodeURIComponent(debounced)}&status=${status}&dir=${dir}&limit=200`);
  useEffect(() => { const t = setInterval(reload, 30000); return () => clearInterval(t); }, [reload]);
  if (notConfigured) return <NotConfigured />;
  const chips: [string, string][] = [['', 'All'], ['delivered', 'Delivered'], ['deferred', 'Delayed'], ['bounced', 'Bounced'], ['refused', 'Refused'], ['spam', 'Spam']];
  return (
    <div className="space-y-6">
      {open && <Journey id={open} onOpen={setOpen} onClose={() => setOpen('')} />}
      <Header title="Hoofprints (Mail trail)" sub="Follow any message from the gate to the stall, with every step and the reason at each one"
        action={<button onClick={reload} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh</button>} />
      <div className="flex flex-col lg:flex-row lg:items-center gap-3">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Sender, recipient, subject, queue ID or IP address"
            className={`${input} w-full pl-9 py-2`} aria-label="Search the mail trail" />
          {q && <button onClick={() => setQ('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-500 hover:text-white cursor-pointer" aria-label="Clear"><X className="w-4 h-4" /></button>}
        </div>
        <Segmented value={dir} onChange={setDir} options={[['', 'All'], ['in', 'Incoming'], ['out', 'Outgoing'], ['internal', 'Internal']]} />
      </div>
      <div className="flex flex-wrap gap-2">
        {chips.map(([v, l]) => (
          <button key={v} onClick={() => setStatus(v)}
            className={`text-xs font-semibold rounded-full px-3 py-1 border cursor-pointer transition-colors ${status === v ? 'bg-sky-600 border-sky-500 text-white' : 'border-slate-700 text-slate-400 hover:text-white'}`}>{l}</button>
        ))}
      </div>
      {error && <Problem text={error} />}
      {!data ? <Loading text="Following the hoofprints…" /> : (
        <div className="bg-slate-900/40 border border-slate-800 rounded-2xl overflow-hidden">
          {data.messages.length === 0 ? (
            <div className="p-8 text-center text-sm text-slate-500">
              <Footprints className="w-8 h-8 mx-auto mb-2 text-slate-600" />
              {data.kept === 0 ? 'No mail yet. CowSec starts following messages as soon as it reads mailcow\'s logs, within a minute.' : 'No message matches that.'}
            </div>
          ) : (
            <div className="divide-y divide-slate-800/70">
              {data.messages.map((m, i) => (
                <button key={m.id} onClick={() => setOpen(m.id)}
                  className="cs-rise w-full text-left grid grid-cols-[1.25rem_minmax(0,1fr)_auto] md:grid-cols-[6.5rem_1.25rem_minmax(0,1.1fr)_minmax(0,1fr)_10.5rem] items-center gap-3 px-4 py-2.5 hover:bg-slate-800/40 cursor-pointer"
                  style={{ animationDelay: `${Math.min(i, 20) * 18}ms` }}>
                  <span className="hidden md:block font-mono text-xs text-slate-500">{when(m.time)}</span>
                  <span title={(DIR[m.direction] || DIR.system)[0]}>{(DIR[m.direction] || DIR.system)[1]}</span>
                  <span className="min-w-0">
                    <span className="block truncate text-sm text-slate-200">{m.from || <em className="text-slate-500">Postfix</em>} <ArrowRight className="inline w-3 h-3 text-slate-500" /> {m.to[0] || '—'}{m.to.length > 1 && <span className="text-slate-500"> +{m.to.length - 1}</span>}</span>
                    <span className="block md:hidden truncate text-xs text-slate-500">{m.subject || (m.door ? 'never accepted' : 'subject not known')} · {when(m.time)}</span>
                  </span>
                  <span className={`hidden md:block truncate text-sm ${m.subject ? 'text-slate-300' : 'text-slate-600 italic'}`}>{m.subject || (m.door ? 'never accepted' : 'subject not known')}</span>
                  <span className="justify-self-end"><StatusPill status={m.status} spam={m.spam} /></span>
                </button>
              ))}
            </div>
          )}
          <p className="px-4 py-2 text-xs text-slate-500 border-t border-slate-800">
            Showing {n(data.messages.length)} of {n(data.found)}. The trail keeps {data.days} days{data.oldest ? `, back to ${when(data.oldest)}` : ''}.
          </p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- one message's journey

interface Step { key: string; tone: 'sky' | 'emerald' | 'amber' | 'rose' | 'pink' | 'slate' | 'indigo'; icon: ReactNode; title: string; time?: number; body?: ReactNode; live?: boolean }

const TONE: Record<Step['tone'], [string, string]> = {
  sky: ['#38bdf8', 'border-sky-500/40 bg-sky-500/10 text-sky-300'], emerald: ['#34d399', 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300'],
  amber: ['#fbbf24', 'border-amber-500/40 bg-amber-500/10 text-amber-300'], rose: ['#fb7185', 'border-rose-500/40 bg-rose-500/10 text-rose-300'],
  pink: ['#f472b6', 'border-pink-500/40 bg-pink-500/10 text-pink-300'], slate: ['#94a3b8', 'border-slate-600 bg-slate-800 text-slate-300'],
  indigo: ['#818cf8', 'border-indigo-500/40 bg-indigo-500/10 text-indigo-300'],
};

const ACTION: Record<string, [string, Step['tone']]> = {
  'no action': ['Looked clean', 'emerald'], 'add header': ['Sent to Junk', 'pink'], 'rewrite subject': ['Marked as spam in the subject', 'pink'],
  reject: ['Refused as spam', 'rose'], 'soft reject': ['Asked the sender to try again later', 'amber'], greylist: ['Greylisted', 'amber'],
};

function ScoreBar({ v }: { v: Verdict }) {
  const top = Math.max(v.required * 1.2, v.score, 1), lo = Math.min(0, v.score);
  const pos = (x: number) => `${((x - lo) / (top - lo)) * 100}%`;
  return (
    <div className="space-y-1">
      <div className="relative h-2.5 rounded-full bg-gradient-to-r from-emerald-500/40 via-amber-500/40 to-rose-500/50">
        <div className="absolute -top-1 h-4.5 w-0.5 bg-rose-300/80" style={{ left: pos(v.required) }} title={`Refused from ${v.required}`} />
        <div className="absolute -top-1.5 w-5 h-5 -ml-2.5 rounded-full border-2 border-white bg-slate-900 shadow transition-all duration-1000" style={{ left: pos(Math.max(lo, Math.min(v.score, top))) }} />
      </div>
      <div className="flex justify-between text-[10px] text-slate-500 font-mono"><span>{lo}</span><span>refused from {v.required}</span></div>
    </div>
  );
}

function stepsFor(d: Detail): Step[] {
  const m = d.message, s: Step[] = [];
  const where = m.client || m.ip ? `${m.client && m.client !== 'unknown' ? m.client : 'an unnamed host'}${m.ip ? ` (${m.ip})` : ''}` : '';
  if (m.notice_for) {
    s.push({ key: 'arrive', tone: 'slate', icon: <Mail className="w-4 h-4" />, title: 'Postfix wrote a delivery report', time: m.time, body: 'An earlier message couldn\'t be delivered, so the server told its sender.' });
  } else if (m.user) {
    s.push({ key: 'arrive', tone: 'indigo', icon: <Send className="w-4 h-4" />, title: `Sent by ${m.user}`, time: m.time, body: <>Signed in{where ? <> from {where}</> : ''}{m.via === 'submission' ? ' over SMTP submission' : ''}.</> });
  } else if (m.via === 'local') {
    s.push({ key: 'arrive', tone: 'slate', icon: <Package className="w-4 h-4" />, title: 'Created on the server', time: m.time, body: 'Handed to Postfix by a program on this server (for example a webmail or cron job).' });
  } else {
    s.push({ key: 'arrive', tone: 'sky', icon: <ArrowDownLeft className="w-4 h-4" />, title: 'Arrived from outside', time: m.time, body: <>From {where || 'another server'}{m.helo ? <>, introducing itself as <code className="font-mono text-slate-300">{m.helo}</code></> : ''}.</> });
  }
  if (m.refused?.stage === 'door') {
    s.push({ key: 'refused', tone: m.refused.temporary ? 'amber' : 'rose', icon: <Ban className="w-4 h-4" />, title: m.refused.temporary ? 'Asked to try again later' : 'Turned away at the gate', time: m.refused.time,
      body: <><span className="text-slate-200">{m.refused.reason}</span> <span className="font-mono text-slate-500">({m.refused.code})</span><br />The message was never accepted, so nobody received it{m.refused.temporary ? ' yet; a real mail server tries again' : ''}.</> });
    return s;
  }
  if (m.verdict) {
    const [label, tone] = ACTION[m.verdict.action] || [m.verdict.action, 'slate'];
    const sym = m.verdict.symbols || [];
    s.push({ key: 'rspamd', tone, icon: <ShieldAlert className="w-4 h-4" />, title: `rspamd: ${label}`, time: m.verdict.time,
      body: (
        <div className="space-y-2">
          <p>Spam score <span className="font-mono text-white">{m.verdict.score.toFixed(1)}</span>{m.subject && <> for “<span className="text-slate-200">{m.subject}</span>”</>}.</p>
          <ScoreBar v={m.verdict} />
          {sym.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {sym.map((x) => (
                <span key={x.name} className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${x.score > 0 ? 'text-rose-200 border-rose-900 bg-rose-950/40' : 'text-emerald-200 border-emerald-900 bg-emerald-950/40'}`}>
                  {x.name} {x.score > 0 ? '+' : ''}{x.score}
                </span>
              ))}
            </div>
          )}
        </div>
      ) });
  } else if (!m.notice_for) {
    s.push({ key: 'rspamd', tone: 'slate', icon: <ShieldAlert className="w-4 h-4" />, title: 'rspamd checked it', body: 'Its verdict isn\'t in rspamd\'s recent history any more, so the score and subject aren\'t known.' });
  }
  if (m.refused?.stage === 'content') {
    s.push({ key: 'refused', tone: m.refused.temporary ? 'amber' : 'rose', icon: <XCircle className="w-4 h-4" />, title: m.refused.temporary ? 'Asked to try again later' : 'Refused after reading it', time: m.refused.time,
      body: <><span className="text-slate-200">{m.refused.reason}</span> <span className="font-mono text-slate-500">({m.refused.code})</span><br />The sending server was told at once; nothing was delivered.</> });
    return s;
  }
  s.push({ key: 'queue', tone: 'slate', icon: <Package className="w-4 h-4" />, title: 'Accepted into the queue',
    body: <>Queue ID <code className="font-mono text-slate-300">{m.id}</code>{m.size ? <> · {(m.size / 1024).toFixed(1)} KB</> : ''}{m.from ? <> · from <span className="text-slate-300">{m.from}</span></> : ''}</> });
  for (const h of m.hops) {
    const to = <span className="text-slate-200">{h.to}</span>;
    const via = h.orig_to && h.orig_to !== h.to ? <> (sent to {h.orig_to})</> : null;
    if (h.status === 'sent') {
      s.push(h.local
        ? { key: 'hop' + h.to, tone: 'emerald', icon: <Inbox className="w-4 h-4" />, title: 'Delivered to a mailbox', time: h.time, body: <>{to}{via}, after {h.delay ?? 0} s{h.attempts > 1 ? <>, on try {h.attempts}</> : ''}.</> }
        : { key: 'hop' + h.to, tone: 'emerald', icon: <ArrowUpRight className="w-4 h-4" />, title: 'Handed to the recipient\'s server', time: h.time, body: <>{to}{via} via <code className="font-mono text-slate-300">{h.relay}</code>, which accepted it{h.attempts > 1 ? <> on try {h.attempts}</> : ''}. <span className="text-slate-500">{h.reason}</span></> });
    } else if (h.status === 'deferred') {
      s.push({ key: 'hop' + h.to, tone: 'amber', live: true, icon: <Clock className="w-4 h-4" />, title: 'Delayed: Postfix keeps trying', time: h.time,
        body: <>{to}{via}: <span className="text-amber-200">{h.reason}</span><br />Tried {h.attempts} time{h.attempts === 1 ? '' : 's'} since {when(h.first)}. Postfix retries for up to 5 days before giving up.</> });
    } else {
      s.push({ key: 'hop' + h.to, tone: 'rose', icon: <Undo2 className="w-4 h-4" />, title: h.status === 'expired' ? 'Gave up after 5 days' : 'Bounced', time: h.time,
        body: <>{to}{via}: <span className="text-rose-200">{h.reason}</span> {h.dsn && <span className="font-mono text-slate-500">({h.dsn})</span>}</> });
    }
  }
  if (m.notice) s.push({ key: 'notice', tone: 'slate', icon: <Mail className="w-4 h-4" />, title: 'The sender was told', body: 'Postfix sent a delivery report back to the sender.' });
  if (m.done && !m.hops.some((h) => h.status === 'deferred')) s.push({ key: 'done', tone: 'slate', icon: <CheckCircle2 className="w-4 h-4" />, title: 'Left the queue', time: m.updated });
  return s;
}

function Journey({ id, onOpen, onClose }: { id: string; onOpen: (id: string) => void; onClose: () => void }) {
  const { data, error } = useApi<Detail>(`/api/mailcow/trail/${encodeURIComponent(id)}`);
  const [copied, setCopied] = useState('');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copy = (v: string) => { navigator.clipboard?.writeText(v); setCopied(v); if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(() => setCopied(''), 1500); };
  const m = data?.message;
  const steps = data ? stepsFor(data) : [];
  return (
    <Modal wide title={m?.subject || (m?.refused?.stage === 'door' ? 'Turned away at the gate' : m ? 'Subject not known' : 'Message')} sub={m ? `${m.from || 'Postfix'} → ${m.to.join(', ') || '—'}` : ''} icon={<Footprints className="w-5 h-5" />} onClose={onClose}>
      {error && <Problem text={error} />}
      {!data || !m ? <Loading text="Following the hoofprints…" /> : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <StatusPill status={data.status} spam={data.spam} />
            <span className="inline-flex items-center gap-1 text-slate-400">{(DIR[data.direction] || DIR.system)[1]} {(DIR[data.direction] || DIR.system)[0]}</span>
            <span className="text-slate-600">·</span>
            {[...(m.id.startsWith('nq') ? [] : [['Queue ID', m.id]]), ...(m.message_id ? [['Message-ID', m.message_id]] : [])].map(([k, v]) => (
              <button key={k} onClick={() => copy(v)} className="inline-flex items-center gap-1 font-mono text-slate-400 hover:text-white cursor-pointer" title={`Copy the ${k}`}>
                {k}: <span className="text-slate-300 max-w-[18rem] truncate">{v}</span> {copied === v ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            ))}
          </div>
          <ol className="relative">
            {steps.map((st, i) => {
              const [color, chip] = TONE[st.tone];
              const last = i === steps.length - 1;
              return (
                <li key={st.key} className="cs-rise relative grid grid-cols-[2.5rem_1fr] gap-3 pb-5" style={{ animationDelay: `${i * 140}ms` }}>
                  {!last && (
                    <svg className="absolute left-[1.2rem] top-9 w-1 overflow-visible" style={{ height: 'calc(100% - 2rem)' }} aria-hidden="true">
                      <line x1="0.5" y1="0" x2="0.5" y2="100%" stroke={color} strokeOpacity="0.5" strokeWidth="2" className="cs-flowline" />
                      <circle cx="0.5" r="3.5" fill={color} className="cs-travel" style={{ animationDelay: `${i * 140 + 400}ms` }} />
                    </svg>
                  )}
                  <span className={`relative z-10 w-10 h-10 rounded-full border flex items-center justify-center ${chip} ${st.live ? 'cs-pulse' : ''}`}>{st.icon}</span>
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 px-4 py-3">
                    <div className="flex flex-wrap items-baseline justify-between gap-2">
                      <p className="font-semibold text-white text-sm">{st.title}</p>
                      {st.time ? <span className="text-xs font-mono text-slate-500">{when(st.time)}{st.time !== m.time && st.time > m.time ? ` · +${fmtGap(st.time - m.time)}` : ''}</span> : null}
                    </div>
                    {st.body && <div className="mt-1 text-xs text-slate-400 leading-relaxed">{st.body}</div>}
                  </div>
                </li>
              );
            })}
          </ol>
          {(data.notice || data.notice_for) && (
            <button onClick={() => onOpen((data.notice || data.notice_for)!.id)} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}>
              <Mail className="w-3.5 h-3.5" /> {data.notice ? 'Open the delivery report' : 'Open the message it was about'}
            </button>
          )}
          {m.ip && !m.user && !m.notice_for && data.direction === 'in' && (
            <p className="text-xs text-slate-500 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" />To keep {m.ip} out, ban it under Banned from the Herd.</p>
          )}
        </div>
      )}
    </Modal>
  );
}

function fmtGap(s: number) {
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${(s / 3600).toFixed(1)} h`;
  return `${(s / 86400).toFixed(1)} days`;
}
