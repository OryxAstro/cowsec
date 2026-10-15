// Live "Pasture map": how traffic reaches mailcow and where CowSec stops it. Flow lines
// speed up and thicken with traffic (log scale, like Stratum's topology); the gate sparks
// when the firewall drops packets. Rates are deltas between two status polls.
import type { ReactNode } from 'react';

export interface FlowSample {
  t: number;
  webChecked: number;   // AppSec requests processed (cumulative)
  webBlocked: number;   // AppSec requests blocked (cumulative)
  mailLines: number;    // postfix/dovecot log lines read by CrowdSec (cumulative)
  dropped: number;      // packets dropped by the firewall bouncer (cumulative)
}

export interface FlowState {
  blockedIPs: number;
  gateUp: boolean;
  edgeUp: boolean;
  engineUp: boolean;
  mailcowUp: boolean;
}

const rate = (a: number, b: number, dt: number) => (dt > 0 && b >= a ? (b - a) / dt : 0);
const dur = (perSec: number) => `${Math.max(0.35, 2.4 - Math.log10(1 + perSec) * 0.9).toFixed(2)}s`;
const width = (perSec: number) => 1.8 + Math.min(2.4, Math.log10(1 + perSec) * 1.1);
const fmtN = (v: number) => (v >= 1e6 ? `${(v / 1e6).toFixed(1)}M` : v >= 1e3 ? `${(v / 1e3).toFixed(1)}k` : `${Math.round(v)}`);
const fmtRate = (v: number) => (v >= 10 ? v.toFixed(0) : v >= 1 ? v.toFixed(1) : v > 0 ? v.toFixed(2) : '0');

function Node({ x, y, w = 190, title, sub, tone, up, icon }: { x: number; y: number; w?: number; title: string; sub: string; tone: string; up: boolean; icon: ReactNode }) {
  return (
    <g transform={`translate(${x - w / 2} ${y - 26})`}>
      <rect width={w} height="52" rx="14" style={{ fill: 'var(--map-node)' }} stroke={up ? tone : '#f43f5e'} strokeOpacity={up ? 0.55 : 0.9} strokeWidth="1.5" />
      <rect width={w} height="52" rx="14" fill={tone} fillOpacity="0.07" />
      <text x="40" y="23" style={{ fill: 'var(--map-ink)' }} fontSize="13" fontWeight="700">{title}</text>
      <text x="40" y="40" style={{ fill: 'var(--map-sub)' }} fontSize="10.5" fontFamily="ui-monospace, monospace">{sub}</text>
      <g transform="translate(12 16)" color={up ? tone : '#f43f5e'}>{icon}</g>
      {!up && <circle cx={w - 10} cy="10" r="4" fill="#f43f5e" className="cs-zap" />}
    </g>
  );
}

function Flow({ d, color, perSec, dashed, label, lx, ly }: { d: string; color: string; perSec: number; dashed?: boolean; label?: string; lx?: number; ly?: number }) {
  return (
    <g>
      <path d={d} stroke={color} strokeOpacity="0.14" strokeWidth={width(perSec) + 5} fill="none" strokeLinecap="round" />
      <path d={d} stroke={color} strokeWidth={width(perSec)} fill="none" strokeLinecap="round"
        className={dashed ? 'cs-flowline cs-flowline--slow' : 'cs-flowline'} style={{ animationDuration: dashed ? undefined : dur(perSec) }} />
      {label && <text x={lx} y={ly} fill={color} fontSize="10.5" fontFamily="ui-monospace, monospace" textAnchor="middle">{label}</text>}
    </g>
  );
}

const ico = (p: string) => <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d={p} /></svg>;
const I = {
  globe: ico('M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20'),
  gate: ico('M3 21V8l9-5 9 5v13M7 21v-8h10v8M7 17h10'),
  shield: ico('M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'),
  web: ico('M3 5h18v14H3zM3 9h18'),
  mail: ico('M3 6h18v12H3zM3 7l9 6 9-6'),
  dog: ico('M12 3c4 0 7 3 7 7v4l2 3h-6l-3 4-3-4H3l2-3v-4c0-4 3-7 7-7zM9 10h.01M15 10h.01'),
};

export default function PastureMap({ prev, cur, state }: { prev: FlowSample | null; cur: FlowSample; state: FlowState }) {
  const dt = prev ? (cur.t - prev.t) / 1000 : 0;
  const web = prev ? rate(prev.webChecked, cur.webChecked, dt) : 0;
  const waf = prev ? rate(prev.webBlocked, cur.webBlocked, dt) : 0;
  const mail = prev ? rate(prev.mailLines, cur.mailLines, dt) : 0;
  const drop = prev ? rate(prev.dropped, cur.dropped, dt) : 0;
  const warming = !prev;
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-950/50 p-4 overflow-x-auto">
      <div className="flex items-center justify-between mb-2 min-w-[800px]">
        <p className="text-sm font-semibold text-white">Pasture map <span className="text-slate-500 font-normal">· live traffic and where it's stopped</span></p>
        <p className="text-[11px] font-mono text-slate-500">{warming ? 'totals since CrowdSec started · measuring rates…' : `totals since CrowdSec started · rates over the last ${Math.round(dt)} s`}</p>
      </div>
      <svg viewBox="0 0 1010 300" className="w-full min-w-[800px]" role="img" aria-label="Traffic flow from the internet through the firewall gate and the edge to mailcow">
        {/* traffic in */}
        <Flow d="M200 70 L260 70" color="#38bdf8" perSec={web + mail + drop} />
        <Flow d="M450 70 L535 70" color="#38bdf8" perSec={web} label={`${fmtRate(web)} req/s`} lx={492} ly={58} />
        <Flow d="M725 70 L810 70" color="#38bdf8" perSec={Math.max(0, web - waf)} />
        <Flow d="M365 96 C365 160 420 170 535 170" color="#34d399" perSec={mail} label={`${fmtRate(mail)} lines/s · ${fmtN(cur.mailLines)} read`} lx={445} ly={197} />
        <Flow d="M725 170 L810 170" color="#34d399" perSec={mail} />
        {/* detections and decisions */}
        <Flow d="M905 196 C905 258 830 262 725 262" color="#a78bfa" perSec={0} dashed />
        <Flow d="M560 96 C512 132 512 236 535 254" color="#a78bfa" perSec={0} dashed />
        <Flow d="M535 270 C410 272 316 214 316 96" color="#fb7185" perSec={0} dashed label="bans" lx={296} ly={214} />

        <Node x={105} y={70} title="Internet" sub="the wide pasture" tone="#94a3b8" up icon={I.globe} />
        <Node x={355} y={70} title="Firewall gate" sub={`${fmtN(state.blockedIPs)} addresses banned`} tone="#fb7185" up={state.gateUp} icon={I.gate} />
        <Node x={630} y={70} title="Edge + WAF" sub={`${fmtN(cur.webBlocked)} of ${fmtN(cur.webChecked)} stopped`} tone="#818cf8" up={state.edgeUp} icon={I.shield} />
        <Node x={905} y={70} title="mailcow web" sub="admin · webmail" tone="#38bdf8" up={state.mailcowUp} icon={I.web} />
        <Node x={630} y={170} title="Mail ports" sub="SMTP · IMAP" tone="#34d399" up={state.gateUp} icon={I.mail} />
        <Node x={905} y={170} title="Postfix · Dovecot" sub="mailcow containers" tone="#34d399" up={state.mailcowUp} icon={I.mail} />
        <Node x={630} y={262} title="CrowdSec" sub="reads logs · decides" tone="#a78bfa" up={state.engineUp} icon={I.dog} />

        {/* the gate sparks while it drops packets */}
        {(drop > 0 || state.blockedIPs > 0) && (
          <g>
            {[0, 1, 2].map((i) => (
              <circle key={i} cx={220 + i * 9} cy={58 + (i % 2) * 22} r="3" fill="#fb7185" className="cs-zap" style={{ animationDelay: `${i * 0.35}s` }} />
            ))}
            <text x="355" y="32" fill="#fb7185" fontSize="10.5" fontFamily="ui-monospace, monospace" textAnchor="middle">{drop > 0 ? `${fmtRate(drop)} pkt/s dropped · ${fmtN(cur.dropped)} in total` : `gate shut · ${fmtN(cur.dropped)} packets dropped`}</text>
          </g>
        )}
      </svg>
    </div>
  );
}
