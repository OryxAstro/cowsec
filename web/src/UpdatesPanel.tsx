import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle, ArrowUpCircle, CheckCircle2, Clock, Download, FolderOpen, Loader2, Mail, Package, RefreshCw, Rocket, ShieldCheck, X,
} from 'lucide-react';
import { Card, Tile } from './HostPanel';
import Pipeline, { type PipelineJob } from './Pipeline';
import FolderPicker from './FolderPicker';

interface Pkg { name: string; installed: string | null; candidate: string | null; upgradable: boolean; managed: boolean }
interface MailcowInfo {
  found: boolean; dir?: string; defaultBackupDir?: string;
  version?: { tag: string | null; branch: string | null; commit: string | null; date: string | null };
  check?: { state?: 'available' | 'current' | 'error'; checked?: string; detail?: string };
  options?: { backup: boolean; path: string; keepDays: number };
}
interface Updates {
  packages: Pkg[];
  aptListsUpdated: string | null;
  hub: { counts: Record<string, number>; pending: { type: string; name: string; version: string }[]; tainted: { type: string; name: string }[]; indexUpdated: string | null };
  hubAutoUpdate: { enabled: boolean; active: boolean; last: string | null; next: string | null; lastResult: string | null };
  jobs: Record<string, PipelineJob & { name: string }>;
  mailcow?: MailcowInfo;
}

const STAGED: Record<string, string> = { 'upgrade-crowdsec': 'Upgrading CrowdSec & bouncers', 'mailcow-update': 'Updating mailcow', 'mailcow-check': 'Checking for a mailcow update' };

const when = (s: string | null | undefined) => {
  if (!s || s === 'n/a') return '—';
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleString();
};
const ago = (s: string | null | undefined) => {
  if (!s) return 'never';
  const d = new Date(s).getTime();
  if (isNaN(d)) return s;
  const days = Math.floor((Date.now() - d) / 86400000);
  return days <= 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`;
};
const btn = 'inline-flex items-center gap-1.5 text-xs font-semibold rounded-lg px-3 py-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-default';

async function post(url: string, body: unknown, method = 'POST') {
  const r = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  if (!r.ok) throw new Error(await r.text());
  return r.json().catch(() => ({}));
}

export default function UpdatesPanel() {
  const [u, setU] = useState<Updates | null>(null);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [active, setActive] = useState<string>('');
  const [job, setJob] = useState<PipelineJob | null>(null);
  const [liveContainers, setLiveContainers] = useState<NonNullable<PipelineJob['extra']>['containers']>();
  const [confirm, setConfirm] = useState<'' | 'mailcow' | 'crowdsec'>('');
  const [picker, setPicker] = useState(false);
  const [opts, setOpts] = useState({ backup: true, path: '/var/backups/cowsec/mailcow', keepDays: 14 });
  const optsLoaded = useRef(false);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/crowdsec/host/updates', { cache: 'no-store' });
      if (!res.ok) throw new Error(await res.text());
      const d: Updates = await res.json();
      setU(d);
      setError('');
      if (!optsLoaded.current && d.mailcow?.options) {
        setOpts(d.mailcow.options);
        optsLoaded.current = true;
      }
      const running = Object.entries(d.jobs).find(([n, j]) => STAGED[n] && j.state === 'running');
      if (running) setActive(running[0]);
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  // Follow the active staged job closely; refresh the page when it ends.
  useEffect(() => {
    if (!active) return;
    let alive = true;
    let t: number | undefined;
    const tick = async () => {
      try {
        const r = await fetch(`/api/crowdsec/host/jobs/${active}`, { cache: 'no-store' });
        const j: PipelineJob = await r.json();
        if (!alive) return;
        setJob(j);
        const step = j.steps?.find((s) => s.state === 'running')?.id;
        if (active === 'mailcow-update' && (step === 'update' || step === 'health')) {
          const c = await fetch('/api/crowdsec/host/mailcow/containers', { cache: 'no-store' }).then((x) => (x.ok ? x.json() : null)).catch(() => null);
          if (alive && c) setLiveContainers(c);
        }
        if (j.state === 'running') t = window.setTimeout(tick, 1500);
        else load();
      } catch {
        t = window.setTimeout(tick, 3000);
      }
    };
    tick();
    return () => {
      alive = false;
      window.clearTimeout(t);
    };
  }, [active, load]);

  const start = async (name: string) => {
    setMsg(null);
    setConfirm('');
    try {
      if (name === 'mailcow-update') await post('/api/crowdsec/host/mailcow/update-options', opts, 'PUT');
      await post('/api/crowdsec/host/jobs', { job: name });
      if (STAGED[name]) {
        setJob({ state: 'running', steps: [] });
        setLiveContainers(undefined);
        setActive(name);
      } else {
        setMsg({ ok: true, text: 'Started. This takes a moment.' });
        window.setTimeout(load, 4000);
      }
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    }
  };

  if (error && !u) {
    return (
      <div className="flex items-center space-x-2 text-rose-300 bg-rose-950/40 border border-rose-900 rounded-xl p-4 text-sm">
        <AlertTriangle className="w-4 h-4" />
        <span>Couldn't check the hay barn: {error}</span>
      </div>
    );
  }
  if (!u) {
    return (
      <div className="flex items-center space-x-2 text-slate-400 text-sm p-6">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Checking for fresh hay…</span>
      </div>
    );
  }

  const upgradable = u.packages.filter((p) => p.managed && p.upgradable);
  const busy = Object.values(u.jobs).some((j) => j.state === 'running') || job?.state === 'running';
  const hubTotal = Object.values(u.hub.counts).reduce((a, b) => a + b, 0);
  const mc = u.mailcow;
  const mcState = mc?.check?.state;
  const shownJob = job && active ? { ...job, extra: { ...job.extra, containers: job.extra?.containers ?? liveContainers } } : null;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tile label="mailcow" value={mcState === 'available' ? 'Update ready' : mcState === 'current' ? 'Up to date' : 'Not checked'}
          sub={mc?.version?.tag ? `${mc.version.tag} · checked ${ago(mc.check?.checked)}` : 'version unknown'} tone={mcState === 'available' ? 'amber' : 'emerald'} icon={<Mail className="w-4 h-4" />} />
        <Tile label="CrowdSec packages" value={upgradable.length ? `${upgradable.length} update${upgradable.length > 1 ? 's' : ''}` : 'Up to date'}
          sub={`versions checked ${ago(u.aptListsUpdated)}`} tone={upgradable.length ? 'amber' : 'emerald'} icon={<Package className="w-4 h-4" />} />
        <Tile label="Hub items" value={u.hub.pending.length ? `${u.hub.pending.length} to update` : 'All fresh'}
          sub={`${hubTotal} installed · index ${ago(u.hub.indexUpdated)}`} tone={u.hub.pending.length ? 'amber' : 'emerald'} icon={<ArrowUpCircle className="w-4 h-4" />} />
        <Tile label="Nightly hub update" value={u.hubAutoUpdate.enabled ? 'On' : 'Off'}
          sub={u.hubAutoUpdate.enabled ? `last run: ${u.hubAutoUpdate.lastResult ?? '—'}` : 'hub items only update when you ask'} tone={u.hubAutoUpdate.enabled ? 'emerald' : 'amber'} icon={<Clock className="w-4 h-4" />} />
      </div>

      {msg && (
        <p className={`text-sm flex items-center gap-2 ${msg.ok ? 'text-emerald-300' : 'text-rose-300'}`}>
          {msg.ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />} {msg.text}
        </p>
      )}

      {shownJob && (
        <Card title={STAGED[active] || active} icon={<Rocket className="w-4 h-4 text-sky-400" />}
          right={shownJob.state !== 'running' ? <button onClick={() => { setActive(''); setJob(null); }} className={`${btn} text-slate-400 hover:text-white`}><X className="w-3.5 h-3.5" /> Close</button> : undefined}>
          <Pipeline job={shownJob} title={shownJob.state === 'running' ? 'In progress (you can leave this page; it carries on)' : shownJob.state === 'ok' ? 'All done' : 'Stopped'} />
        </Card>
      )}

      {mc?.found && (
        <Card title="mailcow" icon={<Mail className="w-4 h-4 text-sky-400" />}
          right={<button onClick={() => start('mailcow-check')} disabled={busy} className={`${btn} text-sky-300 border border-sky-800 hover:bg-sky-950`}><RefreshCw className="w-3.5 h-3.5" /> Check for update</button>}>
          <div className="grid sm:grid-cols-3 gap-3 text-xs">
            <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-3">
              <p className="text-slate-500">Installed</p>
              <p className="text-lg font-bold text-white font-mono">{mc.version?.tag || '—'}</p>
              <p className="text-slate-500 font-mono">{mc.version?.branch} · {mc.version?.commit} · {mc.version?.date}</p>
            </div>
            <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-3">
              <p className="text-slate-500">Update</p>
              <p className={`text-lg font-bold ${mcState === 'available' ? 'text-amber-300' : mcState === 'current' ? 'text-emerald-300' : 'text-slate-300'}`}>
                {mcState === 'available' ? 'Available' : mcState === 'current' ? 'Up to date' : mcState === 'error' ? 'Check failed' : 'Not checked yet'}
              </p>
              <p className="text-slate-500">checked {when(mc.check?.checked)}</p>
            </div>
            <div className="bg-slate-950/50 border border-slate-800 rounded-xl p-3">
              <p className="text-slate-500">Release notes</p>
              <a href="https://github.com/mailcow/mailcow-dockerized/releases" target="_blank" rel="noreferrer" className="text-sm font-semibold text-sky-300 hover:text-white">mailcow releases ↗</a>
              <p className="text-slate-500">read before updating</p>
            </div>
          </div>
          <div className="border border-slate-800 rounded-xl p-4 space-y-3">
            <label className="flex items-center gap-2 text-sm text-slate-200 cursor-pointer">
              <input type="checkbox" checked={opts.backup} onChange={(e) => setOpts({ ...opts, backup: e.target.checked })} />
              Back up mail, configuration and database first <span className="text-xs text-slate-500">(mailcow's backup_and_restore.sh)</span>
            </label>
            <div className={`flex flex-wrap items-center gap-2 ${opts.backup ? '' : 'opacity-40 pointer-events-none'}`}>
              <div className="flex items-stretch flex-1 min-w-72">
                <input value={opts.path} onChange={(e) => setOpts({ ...opts, path: e.target.value })} aria-label="Backup folder"
                  className="flex-1 bg-slate-950/60 border border-slate-700 rounded-l-lg px-3 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-amber-500" />
                <button onClick={() => setPicker(true)} title="Browse the server" className="px-3 border border-l-0 border-slate-700 rounded-r-lg bg-slate-800 hover:bg-slate-700 text-amber-300 cursor-pointer">
                  <FolderOpen className="w-4 h-4" />
                </button>
              </div>
              <label className="flex items-center gap-2 text-xs text-slate-400">
                keep for
                <input type="number" min={0} max={3650} value={opts.keepDays} onChange={(e) => setOpts({ ...opts, keepDays: Math.max(0, Math.round(+e.target.value)) })}
                  className="w-16 bg-slate-950/60 border border-slate-700 rounded-lg px-2 py-1 text-sm text-white font-mono" />
                days <span className="text-slate-600">(0 = keep all)</span>
              </label>
              <button onClick={() => setOpts({ ...opts, path: mc.defaultBackupDir || '/var/backups/cowsec/mailcow' })} className={`${btn} text-slate-400 hover:text-white`}>Use default</button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={() => setConfirm('mailcow')} disabled={busy}
              className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-gradient-to-r from-sky-600 to-emerald-600 hover:from-sky-500 hover:to-emerald-500 disabled:opacity-40 cursor-pointer">
              <Rocket className="w-4 h-4" /> Update mailcow
            </button>
            <p className="text-xs text-slate-500">Mail is briefly offline while containers restart. CowSec then checks the edge, firewall, log reading and certificates.</p>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card title="CrowdSec engine & bouncers" icon={<Package className="w-4 h-4 text-sky-400" />}
          right={<button onClick={() => start('apt-refresh')} disabled={busy} className={`${btn} text-sky-300 border border-sky-800 hover:bg-sky-950`}><RefreshCw className="w-3.5 h-3.5" /> Check for new versions</button>}>
          <table className="w-full text-xs">
            <thead className="text-slate-500 text-left">
              <tr><th className="py-1 font-semibold">Package</th><th className="py-1 font-semibold">Installed</th><th className="py-1 font-semibold">Available</th><th className="py-1 font-semibold text-right">Status</th></tr>
            </thead>
            <tbody className="text-slate-300 cs-stagger">
              {u.packages.filter((p) => p.installed).map((p) => (
                <tr key={p.name} className="border-t border-slate-800/60">
                  <td className="py-1.5 font-mono">{p.name}</td>
                  <td className="py-1.5 font-mono text-slate-400">{p.installed ?? '—'}</td>
                  <td className="py-1.5 font-mono text-slate-400">{p.candidate ?? '—'}</td>
                  <td className="py-1.5 text-right whitespace-nowrap">{p.upgradable ? <span className="text-amber-300">{p.managed ? 'update available' : 'via system updates'}</span> : <span className="text-emerald-400">up to date</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <button onClick={() => setConfirm('crowdsec')} disabled={busy || upgradable.length === 0}
            className="inline-flex items-center gap-2 text-sm font-semibold rounded-xl px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white disabled:bg-slate-800 disabled:text-slate-500 cursor-pointer disabled:cursor-default">
            <Download className="w-4 h-4" /> {upgradable.length ? `Upgrade CrowdSec & bouncers (${upgradable.length})` : 'Nothing to upgrade'}
          </button>
        </Card>

        <Card title="Hub: collections, parsers, scenarios, WAF rules" icon={<ArrowUpCircle className="w-4 h-4 text-amber-400" />}
          right={<button onClick={() => start('hub-upgrade')} disabled={busy} className={`${btn} text-amber-300 border border-amber-800 hover:bg-amber-950`}><RefreshCw className="w-3.5 h-3.5" /> Update hub now</button>}>
          <div className="flex flex-wrap gap-1.5 cs-stagger">
            {Object.entries(u.hub.counts).map(([k, v]) => (
              <span key={k} className="text-[11px] bg-slate-950/60 border border-slate-800 rounded-md px-2 py-0.5 text-slate-300">{k} <span className="font-mono text-white">{v}</span></span>
            ))}
          </div>
          {u.hub.pending.length > 0 ? (
            <ul className="text-xs space-y-1 max-h-40 overflow-auto">
              {u.hub.pending.map((p) => <li key={p.type + p.name} className="flex justify-between text-slate-300"><span className="font-mono">{p.name}</span><span className="text-slate-500">{p.type}</span></li>)}
            </ul>
          ) : (
            <p className="text-xs text-emerald-300 flex items-center gap-1.5"><CheckCircle2 className="w-3.5 h-3.5" /> Every installed hub item is on its latest version.</p>
          )}
          <div className="flex items-center justify-between border-t border-slate-800 pt-3">
            <div className="text-xs text-slate-400 space-y-0.5">
              <p className="text-slate-200 font-semibold">Nightly auto-update</p>
              <p>Last run {when(u.hubAutoUpdate.last)} ({u.hubAutoUpdate.lastResult ?? '—'}) · next {u.hubAutoUpdate.enabled ? when(u.hubAutoUpdate.next) : 'off'}</p>
            </div>
            <button onClick={async () => { await post('/api/crowdsec/host/action', { action: u.hubAutoUpdate.enabled ? 'disable-hub-autoupdate' : 'enable-hub-autoupdate' }); load(); }}
              className={`${btn} text-slate-300 border border-slate-700 hover:bg-slate-800`}>{u.hubAutoUpdate.enabled ? 'Turn off' : 'Turn on'}</button>
          </div>
        </Card>
      </div>

      {picker && <FolderPicker start={opts.path || mc?.defaultBackupDir || '/var/backups'} onClose={() => setPicker(false)} onPick={(p) => { setOpts({ ...opts, path: p }); setPicker(false); }} />}

      {confirm && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={() => setConfirm('')}>
          <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-2xl p-6 space-y-4 shadow-2xl cs-pop" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-white flex items-center gap-2"><Rocket className="w-5 h-5 text-sky-400" /> {confirm === 'mailcow' ? 'Update mailcow?' : 'Upgrade CrowdSec?'}</h3>
            {confirm === 'mailcow' ? (
              <ul className="text-sm text-slate-300 space-y-1.5 cs-stagger">
                {opts.backup ? <li>• Back up everything to <code className="font-mono text-amber-200">{opts.path}</code>{opts.keepDays ? `, keeping ${opts.keepDays} days` : ''}</li> : <li className="text-amber-300">• No backup first (you switched it off)</li>}
                <li>• Download the new images, then run <code className="font-mono">update.sh</code></li>
                <li>• <b>Mail is offline for a few minutes</b> while containers restart</li>
                <li>• Check containers, the edge, the firewall, log reading and certificates</li>
              </ul>
            ) : (
              <ul className="text-sm text-slate-300 space-y-1.5 cs-stagger">
                <li>• Back up /etc/crowdsec</li>
                <li>• Upgrade {upgradable.map((p) => p.name).join(', ')} (your config files are kept)</li>
                <li>• Test the configuration before restarting anything</li>
                <li>• Bans keep working; the WAF pauses for a few seconds</li>
              </ul>
            )}
            <div className="flex justify-end gap-2">
              <button onClick={() => setConfirm('')} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
              <button onClick={() => start(confirm === 'mailcow' ? 'mailcow-update' : 'upgrade-crowdsec')}
                className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 cursor-pointer">
                <ShieldCheck className="w-4 h-4" /> Moo, let's go
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
