// Animated view of a staged background job (CrowdSec upgrade, mailcow update): stages
// linked by a flowing line, live container states, health checks and the log.
import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, ChevronDown, Circle, Loader2, Terminal, XCircle } from 'lucide-react';

export interface PipelineStep { id: string; title: string; state: 'pending' | 'running' | 'ok' | 'failed'; began?: number; ended?: number }
export interface ContainerState { service: string; up: boolean; healthy: boolean; starting: boolean; status: string }
export interface Check { name: string; ok: boolean; detail: string }
export interface PipelineJob {
  state: 'never' | 'running' | 'ok' | 'failed';
  steps?: PipelineStep[];
  extra?: { containers?: { containers: ContainerState[]; total: number; up: number }; checks?: Check[]; backup?: string };
  log?: string;
  error?: string;
  started?: string;
  finished?: string;
}

const secs = (s?: PipelineStep, now = Date.now() / 1000) => {
  if (!s?.began) return '';
  const d = Math.max(0, Math.round((s.ended ?? now) - s.began));
  return d >= 60 ? `${Math.floor(d / 60)}m ${d % 60}s` : `${d}s`;
};

function Node({ step, index }: { step: PipelineStep; index: number }) {
  const tone =
    step.state === 'ok' ? 'border-emerald-400 bg-emerald-500/15 text-emerald-300'
      : step.state === 'failed' ? 'border-rose-400 bg-rose-500/15 text-rose-300 cs-shake'
        : step.state === 'running' ? 'border-sky-400 bg-sky-500/15 text-sky-200 cs-ring'
          : 'border-slate-700 bg-slate-900 text-slate-500';
  return (
    <div className={`relative z-10 w-12 h-12 rounded-full border-2 flex items-center justify-center font-bold ${tone}`} style={{ ['--ring' as string]: 'rgba(56,189,248,.55)' }}>
      {step.state === 'ok' ? <CheckCircle2 key="ok" className="w-6 h-6 cs-pop" /> : step.state === 'failed' ? <XCircle className="w-6 h-6 cs-pop" />
        : step.state === 'running' ? <Loader2 className="w-6 h-6 animate-spin" /> : <span>{index + 1}</span>}
    </div>
  );
}

export function ContainerGrid({ data }: { data: NonNullable<PipelineJob['extra']>['containers'] }) {
  if (!data?.containers?.length) return null;
  const pct = data.total ? Math.round((data.up / data.total) * 100) : 0;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-slate-300">Bringing the herd back in</span>
        <span className="font-mono text-slate-400">{data.up}/{data.total} running</span>
      </div>
      <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full bg-gradient-to-r from-sky-500 to-emerald-400 transition-all duration-700 ${pct < 100 ? 'cs-shimmer' : ''}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 cs-stagger">
        {data.containers.map((c) => (
          <div key={c.service} className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[11px] transition-colors duration-500 ${c.up && !c.starting ? 'border-emerald-800 bg-emerald-950/40 text-emerald-200' : 'border-slate-800 bg-slate-900/60 text-slate-400'}`}>
            <span className={`w-2 h-2 rounded-full shrink-0 ${c.up && !c.starting ? 'bg-emerald-400' : c.up ? 'bg-amber-400 cs-breathe' : 'bg-slate-600 cs-breathe'}`} />
            <span className="truncate font-mono">{c.service.replace(/-mailcow$/, '')}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function Checklist({ checks }: { checks?: Check[] }) {
  if (!checks?.length) return null;
  return (
    <div className="space-y-1.5 cs-stagger">
      <p className="text-xs font-semibold text-slate-300">Health checks</p>
      {checks.map((c) => (
        <div key={c.name} className={`flex items-start gap-2.5 rounded-lg px-3 py-2 text-sm border ${c.ok ? 'border-emerald-900/70 bg-emerald-950/30' : 'border-rose-900/70 bg-rose-950/30'}`}>
          {c.ok ? <CheckCircle2 className="w-4 h-4 mt-0.5 text-emerald-400 cs-pop" /> : <XCircle className="w-4 h-4 mt-0.5 text-rose-400 cs-pop" />}
          <div>
            <p className={c.ok ? 'text-emerald-100' : 'text-rose-100'}>{c.name}</p>
            {c.detail && <p className="text-[11px] text-slate-400">{c.detail}</p>}
          </div>
        </div>
      ))}
    </div>
  );
}

export default function Pipeline({ job, title }: { job: PipelineJob; title: string }) {
  const steps = job.steps || [];
  const done = steps.filter((s) => s.state === 'ok').length;
  const running = steps.find((s) => s.state === 'running');
  const pct = steps.length ? Math.round(((done + (running ? 0.5 : 0)) / steps.length) * 100) : job.state === 'ok' ? 100 : 5;
  const [, tick] = useState(0);
  const [showLog, setShowLog] = useState(false);
  const logRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    if (job.state !== 'running') return;
    const t = window.setInterval(() => tick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, [job.state]);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [job.log, showLog]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-bold text-white">{title}</p>
          <p className={`text-xs ${job.state === 'failed' ? 'text-rose-300' : job.state === 'ok' ? 'text-emerald-300' : 'text-slate-400'}`}>
            {job.state === 'running' ? (running ? `${running.title}…` : 'Starting…') : job.state === 'ok' ? 'Finished successfully' : job.state === 'failed' ? job.error || 'Stopped' : ''}
          </p>
        </div>
        <span className="text-2xl font-extrabold font-mono text-white tabular-nums">{pct}%</span>
      </div>

      {/* overall progress */}
      <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full transition-all duration-700 ${job.state === 'failed' ? 'bg-rose-500' : 'bg-gradient-to-r from-indigo-500 via-sky-400 to-emerald-400'} ${job.state === 'running' ? 'cs-shimmer' : ''}`} style={{ width: `${pct}%` }} />
      </div>

      {/* stages */}
      {steps.length > 0 && (
        <div className="relative">
          <svg className="absolute left-0 right-0 top-6 w-full h-1 overflow-visible" preserveAspectRatio="none" aria-hidden>
            <line x1="4%" y1="0" x2="96%" y2="0" stroke="#1e293b" strokeWidth="3" />
            <line x1="4%" y1="0" x2={`${4 + (92 * Math.max(0, done - (steps.length > 1 ? 0 : 0))) / Math.max(1, steps.length - 1)}%`} y2="0"
              stroke="url(#cs-pipe)" strokeWidth="3" style={{ transition: 'all .8s ease' }} />
            {job.state === 'running' && <line x1="4%" y1="0" x2="96%" y2="0" stroke="#38bdf8" strokeOpacity=".35" strokeWidth="3" className="cs-flow" />}
            <defs>
              <linearGradient id="cs-pipe" x1="0" x2="1"><stop offset="0" stopColor="#818cf8" /><stop offset="1" stopColor="#34d399" /></linearGradient>
            </defs>
          </svg>
          <div className="relative grid gap-2" style={{ gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))` }}>
            {steps.map((s, i) => (
              <div key={s.id} className="flex flex-col items-center text-center gap-2">
                <Node step={s} index={i} />
                <p className={`text-[11.5px] leading-tight ${s.state === 'pending' ? 'text-slate-500' : 'text-slate-200 font-semibold'}`}>{s.title}</p>
                <p className="text-[10px] font-mono text-slate-500 h-3">{secs(s)}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <ContainerGrid data={job.extra?.containers} />
      <Checklist checks={job.extra?.checks} />
      {job.extra?.backup && <p className="text-xs text-slate-400">Configuration backup: <code className="font-mono text-slate-300">{job.extra.backup}</code></p>}

      <div className="border border-slate-800 rounded-xl">
        <button onClick={() => setShowLog(!showLog)} className="w-full flex items-center justify-between px-3 py-2 text-xs text-slate-300 cursor-pointer">
          <span className="flex items-center gap-2"><Terminal className="w-3.5 h-3.5 text-indigo-400" /> Full log</span>
          <ChevronDown className={`w-4 h-4 transition-transform ${showLog ? 'rotate-180' : ''}`} />
        </button>
        {showLog && <pre ref={logRef} className="text-[11px] leading-relaxed text-slate-300 bg-slate-950/70 border-t border-slate-800 px-3 py-2 max-h-72 overflow-auto whitespace-pre-wrap">{job.log || '(no output yet)'}</pre>}
      </div>
      {steps.length === 0 && job.state === 'running' && <p className="flex items-center gap-2 text-xs text-slate-400"><Circle className="w-3 h-3 cs-breathe" /> Preparing…</p>}
    </div>
  );
}
