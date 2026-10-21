// Animated view of a staged background job (CrowdSec upgrade, mailcow update): stages
// linked by a flowing line, live container states, health checks and the log.
import { useEffect, useRef, useState } from 'react';
import {
  Archive, ArrowUpCircle, Check, CheckCircle2, ChevronDown, Circle, CloudDownload, Download, FlaskConical, HeartPulse, ListChecks,
  PackageOpen, Power, RefreshCcw, RefreshCw, Search, ShieldCheck, Terminal, X, XCircle, type LucideIcon,
} from 'lucide-react';

export interface PipelineStep { id: string; title: string; state: 'pending' | 'running' | 'ok' | 'failed'; began?: number; ended?: number }
export interface ContainerState { service: string; up: boolean; healthy: boolean; starting: boolean; ready?: boolean; status: string; reason?: string }
export interface Check { name: string; ok: boolean; detail: string }
export interface PipelineJob {
  state: 'never' | 'running' | 'ok' | 'failed';
  steps?: PipelineStep[];
  extra?: { containers?: { containers: ContainerState[]; total: number; up: number; ready?: number }; checks?: Check[]; backup?: string };
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

// Each stage gets an icon that says what it does, and a motion that acts it out while it runs.
const TASKS: Record<string, [LucideIcon, string]> = {
  check: [Search, 'cs-m-sweep'], download: [Download, 'cs-m-drop'], verify: [ShieldCheck, 'cs-m-pulse'], install: [PackageOpen, 'cs-m-lid'],
  health: [HeartPulse, 'cs-m-beat'], backup: [Archive, 'cs-m-lid'], prefetch: [CloudDownload, 'cs-m-drop'], update: [RefreshCw, 'cs-m-spin'],
  checks: [ListChecks, 'cs-m-pulse'], refresh: [RefreshCcw, 'cs-m-spin'], upgrade: [ArrowUpCircle, 'cs-m-rise'], test: [FlaskConical, 'cs-m-wobble'],
  restart: [Power, 'cs-m-pulse'],
};

function Node({ step }: { step: PipelineStep; index: number }) {
  const [Icon, motion] = TASKS[step.id] ?? [Circle, 'cs-m-pulse'];
  const st = step.state;
  return (
    <div className="relative z-10 w-14 h-14 flex items-center justify-center">
      {st === 'running' && (
        <>
          <span className="absolute inset-0 rounded-full cs-orbit" style={{ background: 'conic-gradient(from 0deg, transparent 0 55%, #38bdf8 75%, #818cf8 90%, transparent 100%)' }} />
          <span className="absolute -inset-2 rounded-full bg-sky-400/20 blur-md cs-breathe" />
        </>
      )}
      <span className="absolute w-12 h-12 rounded-full bg-slate-900" />
      <span className={`relative w-12 h-12 rounded-full flex items-center justify-center border transition-colors duration-500 ${
        st === 'ok' ? 'bg-emerald-500/15 border-emerald-400/60 text-emerald-300'
          : st === 'failed' ? 'bg-rose-500/15 border-rose-400/70 text-rose-300 cs-shake'
            : st === 'running' ? 'bg-slate-900 border-transparent text-sky-200'
              : 'bg-slate-900 border-dashed border-slate-700 text-slate-500'}`}>
        <Icon key={st} className={`w-6 h-6 ${st === 'running' ? motion : st === 'ok' ? 'cs-draw' : ''}`} strokeWidth={1.9} />
      </span>
      {st === 'ok' && <span className="absolute -right-0.5 -bottom-0.5 w-5 h-5 rounded-full bg-emerald-500 text-white flex items-center justify-center ring-2 ring-slate-900 cs-pop"><Check className="w-3 h-3" strokeWidth={3} /></span>}
      {st === 'failed' && <span className="absolute -right-0.5 -bottom-0.5 w-5 h-5 rounded-full bg-rose-500 text-white flex items-center justify-center ring-2 ring-slate-900 cs-pop"><X className="w-3 h-3" strokeWidth={3} /></span>}
    </div>
  );
}

export function ContainerGrid({ data }: { data: NonNullable<PipelineJob['extra']>['containers'] }) {
  if (!data?.containers?.length) return null;
  const isReady = (c: ContainerState) => c.ready ?? (c.up && c.healthy && !c.starting);
  const ready = data.ready ?? data.containers.filter(isReady).length;
  const waiting = data.containers.filter((c) => !isReady(c));
  const pct = data.total ? Math.round((ready / data.total) * 100) : 0;
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-slate-300">Bringing the herd back in</span>
        <span className="font-mono text-slate-400">
          {ready}/{data.total} ready{waiting.length > 0 ? ` · waiting on ${waiting.map((w) => w.service.replace(/-mailcow$/, '')).join(', ')}` : ''}
        </span>
      </div>
      <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full bg-gradient-to-r from-sky-500 to-emerald-400 transition-all duration-700 ${pct < 100 ? 'cs-shimmer' : ''}`} style={{ width: `${pct}%` }} />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 cs-stagger">
        {data.containers.map((c) => {
          const ok = isReady(c);
          return (
            <div key={c.service} title={c.reason ? `${c.status} — ${c.reason}` : c.status}
              className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[11px] transition-colors duration-500 ${ok ? 'border-emerald-800 bg-emerald-950/40 text-emerald-200' : !c.healthy ? 'border-rose-800/80 bg-rose-950/40 text-rose-200' : 'border-amber-800/70 bg-amber-950/30 text-amber-200'}`}>
              <span className={`w-2 h-2 rounded-full shrink-0 ${ok ? 'bg-emerald-400' : !c.healthy ? 'bg-rose-400 cs-breathe' : c.up ? 'bg-amber-400 cs-breathe' : 'bg-slate-600 cs-breathe'}`} />
              <span className="truncate font-mono">{c.service.replace(/-mailcow$/, '')}</span>
            </div>
          );
        })}
      </div>
      {waiting.length > 0 && (
        <div className="rounded-lg border border-amber-800/60 bg-amber-950/25 px-3 py-2 text-xs space-y-1">
          {waiting.map((w) => (
            <div key={w.service} className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-amber-200">
              <span className="font-mono font-semibold">{w.service.replace(/-mailcow$/, '')}</span>
              <span className="text-amber-300/80 font-mono text-[11px]">{w.status}</span>
              {w.reason && <span className="text-slate-300 font-mono text-[11px] break-all">— {w.reason}</span>}
            </div>
          ))}
        </div>
      )}
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
          <div className="absolute left-0 right-0 top-7 grid gap-2" style={{ gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))` }} aria-hidden>
            {steps.map((st, i) => i < steps.length - 1 && (
              <div key={st.id} className="relative h-[3px] rounded-full bg-slate-800 overflow-hidden" style={{ gridColumnStart: i + 1, width: 'calc(100% + 0.5rem)', transform: 'translateX(50%)' }}>
                <div className={`absolute inset-y-0 left-0 rounded-full transition-all duration-700 ${st.state === 'ok' && steps[i + 1].state === 'running' ? 'cs-flowbar' : 'bg-gradient-to-r from-indigo-400 to-emerald-400'}`}
                  style={{ width: st.state === 'ok' ? '100%' : '0%' }} />
              </div>
            ))}
          </div>
          <div className="relative grid gap-2" style={{ gridTemplateColumns: `repeat(${steps.length}, minmax(0, 1fr))` }}>
            {steps.map((s, i) => (
              <div key={s.id} className="flex flex-col items-center text-center gap-2">
                <Node step={s} index={i} />
                <p className={`text-[11.5px] leading-tight transition-colors ${s.state === 'pending' ? 'text-slate-500' : s.state === 'running' ? 'text-sky-200 font-semibold' : 'text-slate-200 font-semibold'}`}>{s.title}</p>
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
