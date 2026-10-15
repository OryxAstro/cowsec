import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ArrowUpCircle, CheckCircle2, Clock, Download, Loader2, Package, RefreshCw, Terminal } from 'lucide-react';
import { Card, Tile } from './HostPanel';

interface Pkg { name: string; installed: string | null; candidate: string | null; upgradable: boolean; managed: boolean }
interface Job { name: string; state: 'never' | 'running' | 'ok' | 'failed'; started?: string; finished?: string; rc?: number; log?: string }
interface Updates {
  packages: Pkg[];
  aptListsUpdated: string | null;
  hub: { counts: Record<string, number>; pending: { type: string; name: string; version: string }[]; tainted: { type: string; name: string }[]; indexUpdated: string | null };
  hubAutoUpdate: { enabled: boolean; active: boolean; last: string | null; next: string | null; lastResult: string | null };
  jobs: Record<string, Job>;
}

const JOBS: Record<string, { label: string; hint: string }> = {
  'apt-refresh': { label: 'Check for new versions', hint: 'apt-get update' },
  'upgrade-crowdsec': { label: 'Upgrade CrowdSec & bouncers', hint: 'Backs up /etc/crowdsec, upgrades the packages (keeping your config), tests and restarts' },
  'hub-upgrade': { label: 'Update hub now', hint: 'cscli hub update && cscli hub upgrade, then reload' },
};

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

export default function UpdatesPanel() {
  const [u, setU] = useState<Updates | null>(null);
  const [error, setError] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [openLog, setOpenLog] = useState('');
  const timer = useRef<number | undefined>(undefined);

  const load = async () => {
    try {
      const res = await fetch('/api/crowdsec/host/updates', { cache: 'no-store' });
      if (!res.ok) throw new Error(await res.text());
      const d: Updates = await res.json();
      setU(d);
      setError('');
      return d;
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      return null;
    }
  };

  // Poll quickly while a job runs, slowly otherwise.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      const d = await load();
      if (!alive) return;
      const running = d && Object.values(d.jobs).some((j) => j.state === 'running');
      timer.current = window.setTimeout(tick, running ? 3000 : 30000);
    };
    tick();
    return () => {
      alive = false;
      window.clearTimeout(timer.current);
    };
  }, []);

  const post = async (url: string, body: unknown, label: string) => {
    setBusy(label);
    setMsg(null);
    try {
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      if (!res.ok) throw new Error(await res.text());
      setMsg({ ok: true, text: `${label}: started` });
      window.clearTimeout(timer.current);
      const d = await load();
      const running = d && Object.values(d.jobs).some((j) => j.state === 'running');
      timer.current = window.setTimeout(async function again() {
        const n = await load();
        timer.current = window.setTimeout(again, n && Object.values(n.jobs).some((j) => j.state === 'running') ? 3000 : 30000);
      }, running ? 3000 : 30000);
    } catch (e) {
      setMsg({ ok: false, text: String(e instanceof Error ? e.message : e) });
    } finally {
      setBusy('');
      setConfirm('');
    }
  };

  const runJob = (job: string) => {
    if (job === 'upgrade-crowdsec' && confirm !== job) {
      setConfirm(job);
      return;
    }
    post('/api/crowdsec/host/jobs', { job }, JOBS[job].label);
    setOpenLog(job);
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
  const anyRunning = Object.values(u.jobs).some((j) => j.state === 'running');
  const hubTotal = Object.values(u.hub.counts).reduce((a, b) => a + b, 0);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tile
          label="CrowdSec packages"
          value={upgradable.length ? `${upgradable.length} update${upgradable.length > 1 ? 's' : ''}` : 'Up to date'}
          sub={`versions checked ${ago(u.aptListsUpdated)}`}
          tone={upgradable.length ? 'amber' : 'emerald'}
          icon={<Package className="w-4 h-4" />}
        />
        <Tile
          label="Hub items"
          value={u.hub.pending.length ? `${u.hub.pending.length} to update` : 'All fresh'}
          sub={`${hubTotal} installed · index ${ago(u.hub.indexUpdated)}`}
          tone={u.hub.pending.length ? 'amber' : 'emerald'}
          icon={<ArrowUpCircle className="w-4 h-4" />}
        />
        <Tile
          label="Nightly hub update"
          value={u.hubAutoUpdate.enabled ? 'On' : 'Off'}
          sub={u.hubAutoUpdate.enabled ? `last run: ${u.hubAutoUpdate.lastResult ?? '—'}` : 'hub items only update when you ask'}
          tone={u.hubAutoUpdate.enabled ? 'emerald' : 'amber'}
          icon={<Clock className="w-4 h-4" />}
        />
        <Tile
          label="Locally modified"
          value={String(u.hub.tainted.length)}
          sub={u.hub.tainted.length ? 'tainted items are skipped by upgrades' : 'no tainted hub items'}
          tone={u.hub.tainted.length ? 'amber' : 'sky'}
          icon={<AlertTriangle className="w-4 h-4" />}
        />
      </div>

      {msg && (
        <p className={`text-sm flex items-center space-x-2 ${msg.ok ? 'text-emerald-300' : 'text-rose-300'}`}>
          {msg.ok ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
          <span>{msg.text}</span>
        </p>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card
          title="CrowdSec engine & bouncers"
          icon={<Package className="w-4 h-4 text-sky-400" />}
          right={
            <button
              onClick={() => runJob('apt-refresh')}
              disabled={anyRunning || !!busy}
              className="inline-flex items-center space-x-1.5 text-xs font-semibold text-sky-300 border border-sky-800 rounded-lg px-2.5 py-1.5 hover:bg-sky-950 disabled:opacity-40 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${u.jobs['apt-refresh']?.state === 'running' ? 'animate-spin' : ''}`} />
              <span>{JOBS['apt-refresh'].label}</span>
            </button>
          }
        >
          <table className="w-full text-xs">
            <thead className="text-slate-500 text-left">
              <tr>
                <th className="py-1 font-semibold">Package</th>
                <th className="py-1 font-semibold">Installed</th>
                <th className="py-1 font-semibold">Available</th>
                <th className="py-1 font-semibold text-right">Status</th>
              </tr>
            </thead>
            <tbody className="text-slate-300">
              {u.packages.map((p) => (
                <tr key={p.name} className="border-t border-slate-800/60">
                  <td className="py-1.5 font-mono">{p.name}</td>
                  <td className="py-1.5 font-mono text-slate-400">{p.installed ?? '—'}</td>
                  <td className="py-1.5 font-mono text-slate-400">{p.candidate ?? '—'}</td>
                  <td className="py-1.5 text-right whitespace-nowrap">
                    {p.upgradable ? (
                      <span className="text-amber-300">{p.managed ? 'update available' : 'via system updates'}</span>
                    ) : (
                      <span className="text-emerald-400">up to date</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="text-[11px] text-slate-500">
            Signed packages from CrowdSec's apt repository. The upgrade keeps your config files (and backs up /etc/crowdsec first), tests the config, restarts the engine and firewall bouncer, and reloads OpenResty only if its config passes. OpenResty itself updates with normal system updates.
          </p>
          <button
            onClick={() => runJob('upgrade-crowdsec')}
            disabled={anyRunning || !!busy || upgradable.length === 0}
            title={JOBS['upgrade-crowdsec'].hint}
            className={`inline-flex items-center space-x-2 text-sm font-semibold rounded-xl px-4 py-2 cursor-pointer disabled:cursor-default disabled:bg-slate-800 disabled:text-slate-500 ${
              confirm === 'upgrade-crowdsec' ? 'bg-amber-600 hover:bg-amber-500 text-white' : 'bg-emerald-600 hover:bg-emerald-500 text-white'
            }`}
          >
            <Download className="w-4 h-4" />
            <span>{confirm === 'upgrade-crowdsec' ? 'Moo again to confirm' : upgradable.length ? `${JOBS['upgrade-crowdsec'].label} (${upgradable.length})` : 'Nothing to upgrade'}</span>
          </button>
        </Card>

        <Card
          title="Hub: collections, parsers, scenarios, WAF rules"
          icon={<ArrowUpCircle className="w-4 h-4 text-amber-400" />}
          right={
            <button
              onClick={() => runJob('hub-upgrade')}
              disabled={anyRunning || !!busy}
              className="inline-flex items-center space-x-1.5 text-xs font-semibold text-amber-300 border border-amber-800 rounded-lg px-2.5 py-1.5 hover:bg-amber-950 disabled:opacity-40 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${u.jobs['hub-upgrade']?.state === 'running' ? 'animate-spin' : ''}`} />
              <span>{JOBS['hub-upgrade'].label}</span>
            </button>
          }
        >
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(u.hub.counts).map(([k, v]) => (
              <span key={k} className="text-[11px] bg-slate-950/60 border border-slate-800 rounded-md px-2 py-0.5 text-slate-300">
                {k} <span className="font-mono text-white">{v}</span>
              </span>
            ))}
          </div>
          {u.hub.pending.length > 0 ? (
            <ul className="text-xs space-y-1 max-h-40 overflow-auto">
              {u.hub.pending.map((p) => (
                <li key={p.type + p.name} className="flex justify-between text-slate-300">
                  <span className="font-mono">{p.name}</span>
                  <span className="text-slate-500">{p.type}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-emerald-300 flex items-center space-x-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Every installed hub item is on its latest version.</span>
            </p>
          )}
          {u.hub.tainted.length > 0 && (
            <p className="text-[11px] text-amber-300">Locally modified (not upgraded): {u.hub.tainted.map((t) => t.name).join(', ')}</p>
          )}
          <div className="flex items-center justify-between border-t border-slate-800 pt-3">
            <div className="text-xs text-slate-400 space-y-0.5">
              <p className="text-slate-200 font-semibold">Nightly auto-update</p>
              <p>
                Last run {when(u.hubAutoUpdate.last)} ({u.hubAutoUpdate.lastResult ?? '—'}) · next {u.hubAutoUpdate.enabled ? when(u.hubAutoUpdate.next) : 'off'}
              </p>
            </div>
            <button
              onClick={() => post('/api/crowdsec/host/action', { action: u.hubAutoUpdate.enabled ? 'disable-hub-autoupdate' : 'enable-hub-autoupdate' }, u.hubAutoUpdate.enabled ? 'Turn off nightly update' : 'Turn on nightly update')}
              disabled={!!busy}
              className="text-xs font-semibold text-slate-300 border border-slate-700 rounded-lg px-2.5 py-1.5 hover:bg-slate-800 disabled:opacity-40 cursor-pointer"
            >
              {u.hubAutoUpdate.enabled ? 'Turn off' : 'Turn on'}
            </button>
          </div>
        </Card>
      </div>

      <Card title="Recent jobs" icon={<Terminal className="w-4 h-4 text-indigo-400" />}>
        <div className="space-y-2">
          {Object.keys(JOBS).map((name) => {
            const j = u.jobs[name] ?? { name, state: 'never' };
            const tone = j.state === 'ok' ? 'text-emerald-400' : j.state === 'failed' ? 'text-rose-400' : j.state === 'running' ? 'text-sky-300' : 'text-slate-500';
            return (
              <div key={name} className="border border-slate-800 rounded-xl">
                <button onClick={() => setOpenLog(openLog === name ? '' : name)} className="w-full flex items-center justify-between px-3 py-2 text-xs cursor-pointer">
                  <span className="text-slate-200 font-semibold">{JOBS[name].label}</span>
                  <span className={`flex items-center space-x-2 ${tone}`}>
                    {j.state === 'running' && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    <span>{j.state === 'never' ? 'not run yet' : j.state === 'ok' ? `done ${when(j.finished)}` : j.state === 'failed' ? `failed ${when(j.finished)}` : `running since ${when(j.started)}`}</span>
                  </span>
                </button>
                {openLog === name && j.log !== undefined && (
                  <pre className="text-[11px] leading-relaxed text-slate-300 bg-slate-950/70 border-t border-slate-800 px-3 py-2 max-h-72 overflow-auto whitespace-pre-wrap">{j.log || '(no output yet)'}</pre>
                )}
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
}
