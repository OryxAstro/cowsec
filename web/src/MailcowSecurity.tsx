// Mailbox security for The Farm: sign-ins and failed attempts per mailbox (with flags and
// CrowdSec ban status), the "lock down this mailbox" playbook and its undo, and the
// Lookout page (outbound volume, lockdowns, admins and 2FA, password policy, forwarding hosts).
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  AlertTriangle, Ban, Binoculars, CheckCircle2, CircleDashed, Clock, Gavel, KeyRound, Loader2, Lock, LockOpen, Mail, MapPin, Plus,
  RefreshCw, Send, Shield, ShieldAlert, ShieldCheck, Smartphone, Trash2, Undo2, UserX, Users, XCircle,
} from 'lucide-react';
import Flag from './Flag';
import { Card, Tile } from './HostPanel';
import { Labelled, Modal, Segmented, SwitchRow } from './MailcowForms';
import { list } from './MailcowExtras';
import { btn, Confirm, Header, input, Loading, NotConfigured, Pill, Problem, send, useApi, useToast } from './MailcowPanels';

type Run = (fn: () => Promise<string>, after?: () => void) => Promise<void>;

interface Geo { cc: string; country: string; org: string; lan: boolean }
interface BanInfo { banned: boolean; duration?: string; origin?: string }
interface SignIn { time: number; service: string; ip: string; app_password?: string; geo?: Geo; new_country: boolean; ban?: BanInfo }
interface Failure { time: number; source: 'smtp' | 'imap'; ip: string; tried: string; geo?: Geo; ban?: BanInfo }
interface Step { step: string; ok: boolean; message: string }
interface Lockdown { user: string; since: string; prev_active?: string; throttled: boolean; paused_apps: string[]; cleared_devices: boolean; banned: string[]; steps?: Step[] }
interface Security { user: string; days: number; logins: SignIn[]; failures: Failure[]; countries: Record<string, number>; home: string; mailbox?: { active?: number | string }; lockdown: Lockdown | null; can_ban: boolean }

export const ago = (t: number | string) => {
  const n = typeof t === 'number' ? t * 1000 : Date.parse(t);
  if (!n) return '—';
  const s = (Date.now() - n) / 1000;
  if (s < 90) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
};

const SERVICE: Record<string, string> = { imap: 'IMAP', smtp: 'SMTP', pop3: 'POP3', sieve: 'Sieve', eas: 'ActiveSync', dav: 'DAV', sogo: 'Webmail', ui: 'Web' };
const STEP_LABEL: Record<string, [string, ReactNode]> = {
  disable_login: ['Sign-in disabled', <UserX key="i" className="w-4 h-4" />], force_password: ['New password required', <KeyRound key="i" className="w-4 h-4" />],
  pause_app_passwords: ['App passwords paused', <Lock key="i" className="w-4 h-4" />], clear_devices: ['Phones and tablets signed out', <Smartphone key="i" className="w-4 h-4" />],
  throttle: ['Sending throttled', <Send key="i" className="w-4 h-4" />], ban: ['Addresses banned in CrowdSec', <Gavel key="i" className="w-4 h-4" />],
  record: ['Saved for undo', <Undo2 key="i" className="w-4 h-4" />], restore_login: ['Sign-in allowed again', <LockOpen key="i" className="w-4 h-4" />],
  resume_app_passwords: ['App passwords resumed', <KeyRound key="i" className="w-4 h-4" />], remove_throttle: ['Sending limit restored', <Send key="i" className="w-4 h-4" />],
  unban: ['Addresses unbanned', <ShieldCheck key="i" className="w-4 h-4" />],
};

function Where({ geo, ip }: { geo?: Geo; ip: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 min-w-0">
      {geo && !geo.lan ? <Flag code={geo.cc} /> : <MapPin className="w-4 h-4 text-slate-500" />}
      <span className="font-mono text-slate-200">{ip || 'unknown'}</span>
      <span className="text-slate-500 truncate">{geo ? (geo.lan ? 'local network' : `${geo.country}${geo.org ? ` · ${geo.org}` : ''}`) : ''}</span>
    </span>
  );
}

// Steps appear one after another, so a run reads like a checklist being ticked off.
function StepList({ steps }: { steps: Step[] }) {
  const [shown, setShown] = useState(0);
  useEffect(() => {
    setShown(0);
    const t = window.setInterval(() => setShown((n) => (n >= steps.length ? n : n + 1)), 280);
    return () => window.clearInterval(t);
  }, [steps]);
  return (
    <ol className="space-y-1.5">
      {steps.map((s, i) => {
        const [label, icon] = STEP_LABEL[s.step] || [s.step, null];
        const on = i < shown;
        return (
          <li key={s.step + i} className={`flex items-start gap-3 rounded-xl border px-3 py-2 text-sm transition-all duration-300 ${on ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-1'} ${s.ok ? 'border-emerald-800/60 bg-emerald-950/30' : 'border-rose-900/70 bg-rose-950/30'}`}>
            <span className={`mt-0.5 ${s.ok ? 'text-emerald-300' : 'text-rose-300'}`}>{on ? (s.ok ? <CheckCircle2 className="w-4 h-4 cs-pop" /> : <XCircle className="w-4 h-4 cs-pop" />) : <CircleDashed className="w-4 h-4" />}</span>
            <span className="text-slate-400">{icon}</span>
            <span className="flex-1"><span className="font-semibold text-white">{label}</span>{s.message && <span className="block text-xs text-slate-400">{s.message}</span>}</span>
          </li>
        );
      })}
    </ol>
  );
}

// ---------------------------------------------------------------- the playbook

function LockdownPlan({ user, sec, onDone, onCancel }: { user: string; sec: Security; onDone: (ld: Lockdown) => void; onCancel: () => void }) {
  const suspects = useMemo(() => {
    const m = new Map<string, { ip: string; geo?: Geo; why: string }>();
    sec.failures.forEach((f) => { if (f.ip && !f.ban?.banned && !f.geo?.lan) m.set(f.ip, { ip: f.ip, geo: f.geo, why: 'failed sign-ins' }); });
    sec.logins.forEach((l) => { if (l.new_country && l.ip && !l.ban?.banned) m.set(l.ip, { ip: l.ip, geo: l.geo, why: 'signed in from an unusual country' }); });
    return [...m.values()];
  }, [sec]);
  const [f, setF] = useState({ disable_login: true, force_password: true, pause_app_passwords: true, clear_devices: true, throttle: true });
  const [ips, setIps] = useState<string[]>(suspects.map((s) => s.ip));
  const [dur, setDur] = useState('7d');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const go = async () => {
    setBusy(true); setErr('');
    try {
      const r = await fetch(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/lockdown`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...f, ban_ips: ips, ban_duration: dur }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || `HTTP ${r.status}`);
      onDone(d as Lockdown);
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };
  const set = (k: keyof typeof f) => (v: boolean) => setF({ ...f, [k]: v });
  return (
    <div className="rounded-2xl border border-rose-800/70 bg-rose-950/20 p-5 space-y-4 cs-pop">
      <div className="flex items-start gap-3">
        <span className="w-10 h-10 rounded-xl bg-rose-500/15 text-rose-300 flex items-center justify-center shrink-0"><ShieldAlert className="w-5 h-5" /></span>
        <div>
          <p className="font-semibold text-white">Lock down {user}</p>
          <p className="text-xs text-slate-400">For when the account may be in someone else's hands. Mail keeps arriving; everything here can be undone afterwards.</p>
        </div>
      </div>
      <div className="grid sm:grid-cols-2 gap-2">
        <SwitchRow value={f.disable_login} onChange={set('disable_login')} label="Disable sign-in" hint="Nobody can sign in, but mail still arrives." />
        <SwitchRow value={f.force_password} onChange={set('force_password')} label="Require a new password" hint="When sign-in comes back, the owner must change it." />
        <SwitchRow value={f.pause_app_passwords} onChange={set('pause_app_passwords')} label="Pause app passwords" hint="Paused, not deleted, so they can be resumed." />
        <SwitchRow value={f.clear_devices} onChange={set('clear_devices')} label="Sign out phones and tablets" hint="Clears ActiveSync devices." />
        <SwitchRow value={f.throttle} onChange={set('throttle')} label="Throttle sending" hint="1 message an hour, in case it's sending spam." />
      </div>
      {sec.can_ban && (
        <div className="space-y-2">
          <p className="text-xs font-semibold text-slate-300">Ban in CrowdSec</p>
          {suspects.length === 0 ? <p className="text-xs text-slate-500">No unbanned addresses look suspicious for this mailbox.</p> : (
            <div className="rounded-xl border border-slate-800 divide-y divide-slate-800/70">
              {suspects.map((s) => (
                <label key={s.ip} className="flex items-center gap-3 px-3 py-2 text-xs cursor-pointer">
                  <input type="checkbox" checked={ips.includes(s.ip)} onChange={(e) => setIps(e.target.checked ? [...ips, s.ip] : ips.filter((x) => x !== s.ip))} />
                  <Where geo={s.geo} ip={s.ip} />
                  <span className="ml-auto text-amber-300/90 shrink-0">{s.why}</span>
                </label>
              ))}
            </div>
          )}
          <Labelled label="For"><Segmented value={dur} onChange={setDur} options={[['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days']]} /></Labelled>
        </div>
      )}
      {err && <Problem text={err} />}
      <div className="flex justify-end gap-2">
        <button onClick={onCancel} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
        <button disabled={busy || (!Object.values(f).some(Boolean) && !ips.length)} onClick={go} className={`${btn} bg-rose-600 hover:bg-rose-500 text-white px-4 py-2`}>
          {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />} Lock it down
        </button>
      </div>
    </div>
  );
}

function UndoPanel({ user, ld, onDone }: { user: string; ld: Lockdown; onDone: () => void }) {
  const [f, setF] = useState({ restore_login: true, resume_app_passwords: ld.paused_apps.length > 0, remove_throttle: ld.throttled, unban: false });
  const [steps, setSteps] = useState<Step[] | null>(null);
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      const r = await fetch(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/lockdown/undo`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f) });
      const d = await r.json().catch(() => ({}));
      setSteps(d.steps || [{ step: 'undo', ok: false, message: d.error || 'Undo failed' }]);
      window.setTimeout(onDone, 1800);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="rounded-2xl border border-amber-700/60 bg-amber-950/20 p-5 space-y-3">
      <div className="flex items-center gap-2 text-sm"><Lock className="w-4 h-4 text-amber-300" /><span className="font-semibold text-white">Locked down {ago(ld.since)}</span></div>
      <ul className="text-xs text-slate-400 grid sm:grid-cols-2 gap-1">
        {ld.prev_active !== undefined && <li>• Sign-in disabled</li>}
        {ld.paused_apps.length > 0 && <li>• {ld.paused_apps.length} app password{ld.paused_apps.length === 1 ? '' : 's'} paused</li>}
        {ld.throttled && <li>• Sending throttled to 1 an hour</li>}
        {ld.cleared_devices && <li>• Phones and tablets signed out</li>}
        {ld.banned.length > 0 && <li>• {ld.banned.length} address{ld.banned.length === 1 ? '' : 'es'} banned: <span className="font-mono">{ld.banned.join(', ')}</span></li>}
      </ul>
      {steps ? <StepList steps={steps} /> : (
        <>
          <p className="text-xs font-semibold text-slate-300 pt-1">When it's safe again, undo:</p>
          <div className="grid sm:grid-cols-2 gap-2">
            <SwitchRow value={f.restore_login} onChange={(v) => setF({ ...f, restore_login: v })} label="Allow sign-in again" hint="The new-password requirement stays if you set one." />
            {ld.paused_apps.length > 0 && <SwitchRow value={f.resume_app_passwords} onChange={(v) => setF({ ...f, resume_app_passwords: v })} label="Resume the paused app passwords" />}
            {ld.throttled && <SwitchRow value={f.remove_throttle} onChange={(v) => setF({ ...f, remove_throttle: v })} label="Put the sending limit back" />}
            {ld.banned.length > 0 && <SwitchRow value={f.unban} onChange={(v) => setF({ ...f, unban: v })} label="Unban the addresses" hint="Usually best left to expire." />}
          </div>
          <div className="flex justify-end"><button disabled={busy} onClick={go} className={`${btn} bg-amber-600 hover:bg-amber-500 text-white px-4 py-2`}>{busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Undo2 className="w-3.5 h-3.5" />} Undo selected</button></div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- per-mailbox security

export function SecurityTab({ user, run }: { user: string; run: Run }) {
  const { data, error, loading, reload } = useApi<Security>(`/api/mailcow/mailboxes/${encodeURIComponent(user)}/security`);
  const [plan, setPlan] = useState(false);
  const [result, setResult] = useState<Lockdown | null>(null);
  if (error) return <Problem text={error} />;
  if (!data) return <p className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Reading sign-ins and logs…</p>;
  const failIPs = new Map<string, { ip: string; n: number; last: number; geo?: Geo; ban?: BanInfo; sources: Set<string>; tried: Set<string> }>();
  data.failures.forEach((f) => {
    const k = f.ip || 'unknown';
    const e = failIPs.get(k) || { ip: f.ip, n: 0, last: 0, geo: f.geo, ban: f.ban, sources: new Set(), tried: new Set() };
    e.n++; e.last = Math.max(e.last, f.time); e.sources.add(f.source.toUpperCase()); e.tried.add(f.tried);
    failIPs.set(k, e);
  });
  const groups = [...failIPs.values()].sort((a, b) => b.n - a.n);
  const bannable = groups.filter((g) => g.ip && !g.geo?.lan);
  const banned = bannable.filter((g) => g.ban?.banned).length;
  const countries = Object.entries(data.countries).sort((a, b) => b[1] - a[1]);
  const total = countries.reduce((n, [, c]) => n + c, 0) || 1;
  const unusual = data.logins.filter((l) => l.new_country).length;
  const locked = String(data.mailbox?.active) === '2';
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Tile label="Sign-ins" value={String(data.logins.length)} sub={`last ${data.days} days`} tone="sky" icon={<KeyRound className="w-4 h-4" />} />
        <Tile label="Countries" value={String(countries.length)} sub={unusual ? `${unusual} unusual sign-in${unusual === 1 ? '' : 's'}` : 'nothing unusual'} tone={unusual ? 'amber' : 'emerald'} icon={<MapPin className="w-4 h-4" />} />
        <Tile label="Failed attempts" value={String(data.failures.length)} sub={`from ${groups.length} address${groups.length === 1 ? '' : 'es'}`} tone={data.failures.length ? 'rose' : 'emerald'} icon={<ShieldAlert className="w-4 h-4" />} />
        <Tile label="Already banned" value={`${banned}/${bannable.length}`} sub={bannable.length ? 'public addresses, by CrowdSec' : 'no public addresses involved'} tone="indigo" icon={<Gavel className="w-4 h-4" />} />
      </div>

      {(result || data.lockdown) && !plan && (result ? (
        <div className="rounded-2xl border border-emerald-800/60 bg-emerald-950/20 p-5 space-y-3">
          <p className="flex items-center gap-2 text-sm font-semibold text-white"><ShieldCheck className="w-4 h-4 text-emerald-300" /> {user} is locked down</p>
          <StepList steps={result.steps || []} />
          <div className="flex justify-end"><button onClick={() => { setResult(null); reload(); }} className={`${btn} border border-slate-700 text-slate-300`}>Done</button></div>
        </div>
      ) : <UndoPanel user={user} ld={data.lockdown!} onDone={reload} />)}
      {!data.lockdown && !result && !plan && (
        <div className="flex flex-wrap items-center gap-3 rounded-2xl border border-slate-800 bg-slate-950/40 px-4 py-3">
          <Shield className={`w-5 h-5 ${locked ? 'text-amber-300' : 'text-emerald-300'}`} />
          <p className="flex-1 text-sm text-slate-300">{locked ? 'Sign-in is currently disabled for this mailbox.' : 'Think this account has been taken over? One button closes every door, and you can undo it later.'}</p>
          <button onClick={() => setPlan(true)} className={`${btn} bg-rose-600 hover:bg-rose-500 text-white px-4 py-2`}><Lock className="w-3.5 h-3.5" /> Lock down this mailbox</button>
        </div>
      )}
      {plan && <LockdownPlan user={user} sec={data} onCancel={() => setPlan(false)} onDone={(ld) => { setPlan(false); setResult(ld); }} />}

      {countries.length > 0 && (
        <section className="space-y-2">
          <h4 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">Where it signs in from</h4>
          <div className="flex h-3 rounded-full overflow-hidden bg-slate-800">
            {countries.map(([cc, n], i) => (
              <div key={cc} title={`${cc}: ${n}`} className={`h-full transition-all duration-700 ${['bg-sky-400', 'bg-indigo-400', 'bg-amber-400', 'bg-rose-400', 'bg-emerald-400'][i % 5]}`} style={{ width: `${(n / total) * 100}%` }} />
            ))}
          </div>
          <div className="flex flex-wrap gap-3 text-xs text-slate-300">
            {countries.map(([cc, n]) => <span key={cc} className="inline-flex items-center gap-1.5"><Flag code={cc} /> {cc} <span className="text-slate-500">{Math.round((n / total) * 100)}%</span>{cc === data.home && <span className="text-[10px] text-emerald-300">usual</span>}</span>)}
          </div>
        </section>
      )}

      <section className="space-y-2">
        <h4 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400 flex items-center gap-2">Recent sign-ins <button onClick={reload} className="text-slate-500 hover:text-white cursor-pointer" title="Refresh"><RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} /></button></h4>
        {data.logins.length === 0 ? <p className="text-xs text-slate-500">No sign-ins recorded in the last {data.days} days.</p> : (
          <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70 max-h-72 overflow-y-auto cs-stagger">
            {data.logins.slice(0, 100).map((l, i) => (
              <div key={i} className={`flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-xs ${l.new_country ? 'bg-amber-950/25' : ''}`}>
                <Where geo={l.geo} ip={l.ip} />
                <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">{SERVICE[l.service] || l.service}</span>
                {l.app_password && <span className="px-1.5 py-0.5 rounded bg-indigo-950/60 text-indigo-200">app password: {l.app_password}</span>}
                {l.new_country && <span className="px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-200 font-semibold">unusual country</span>}
                {l.ban?.banned && <span className="px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-200 font-semibold">banned</span>}
                <span className="ml-auto text-slate-500 shrink-0">{ago(l.time)}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="space-y-2">
        <h4 className="text-[11px] font-semibold uppercase tracking-widest text-slate-400">Failed attempts</h4>
        {groups.length === 0 ? <p className="text-xs text-slate-500">No failed sign-ins for this address in mailcow's recent logs.</p> : (
          <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/70 max-h-72 overflow-y-auto">
            {groups.map((g) => (
              <div key={g.ip || 'u'} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 text-xs">
                <Where geo={g.geo} ip={g.ip} />
                <span className="font-mono text-rose-300 font-semibold">{g.n}×</span>
                <span className="text-slate-500">{[...g.sources].join(' · ')} · last {ago(g.last)}</span>
                <span className="ml-auto shrink-0">
                  {g.ban?.banned ? <Pill ok yes={`banned${g.ban.duration ? ` · ${g.ban.duration}` : ''}`} /> : data.can_ban && g.ip && !g.geo?.lan ? (
                    <button onClick={() => run(() => send('POST', '/api/mailcow/security/ban', { ip: g.ip, duration: '7d', reason: user }), reload)} className={`${btn} border border-rose-900 text-rose-300 hover:bg-rose-950/50`}><Gavel className="w-3.5 h-3.5" /> Ban 7 days</button>
                  ) : null}
                </span>
              </div>
            ))}
          </div>
        )}
        <p className="text-[11px] text-slate-500">From the most recent 5,000 lines of mailcow's Postfix and Dovecot logs.</p>
      </section>
    </div>
  );
}

export function SecurityModal({ user, onClose }: { user: string; onClose: () => void }) {
  const { toast, run } = useToast();
  return (
    <Modal wide title={`Security · ${user}`} sub="Sign-ins, failed attempts and the lock-down playbook" icon={<Shield className="w-5 h-5" />} onClose={onClose}>
      {toast}
      <SecurityTab user={user} run={run} />
    </Modal>
  );
}

// ---------------------------------------------------------------- Lookout

interface Sender { user: string; count: number; ips: number; first: number; last: number; per_hour: number; unusual: boolean }
interface Admin { username: string; active?: unknown; tfa_active?: unknown; attributes?: { force_tfa?: string } }
interface Lookout {
  window: { from: number; to: number }; senders: Sender[]; queued: { sender: string; count: number }[]; queue_total: number;
  ratelimited: Record<string, unknown>[] | { error: string }; admins: Admin[] | { error: string }; domain_admins: Admin[] | { error: string };
  password_policy: { length?: string; chars?: string; special_chars?: string; lowerupper?: string; numbers?: string };
  fwdhosts: { host: string; source: string; keep_spam: string }[] | { error: string }; lockdowns: Lockdown[];
}
const yes = (v: unknown) => v === 1 || v === '1' || v === true;

function PasswordPolicy({ p, run, reload }: { p: Lookout['password_policy']; run: Run; reload: () => void }) {
  const [f, setF] = useState({ length: Number(p.length || 6), chars: yes(p.chars), special_chars: yes(p.special_chars), lowerupper: yes(p.lowerupper), numbers: yes(p.numbers) });
  const strength = Math.min(100, (f.length - 6) * 4 + (f.chars ? 10 : 0) + (f.special_chars ? 18 : 0) + (f.lowerupper ? 14 : 0) + (f.numbers ? 12 : 0) + 20);
  return (
    <div className="space-y-4">
      <Labelled label={`Minimum length: ${f.length} characters`}>
        <input type="range" min={6} max={32} value={f.length} onChange={(e) => setF({ ...f, length: +e.target.value })} className="w-full accent-sky-400" />
      </Labelled>
      <div className="grid sm:grid-cols-2 gap-2">
        <SwitchRow value={f.lowerupper} onChange={(v) => setF({ ...f, lowerupper: v })} label="Upper- and lower-case letters" />
        <SwitchRow value={f.numbers} onChange={(v) => setF({ ...f, numbers: v })} label="At least one number" />
        <SwitchRow value={f.special_chars} onChange={(v) => setF({ ...f, special_chars: v })} label="At least one symbol" />
        <SwitchRow value={f.chars} onChange={(v) => setF({ ...f, chars: v })} label="At least one letter" />
      </div>
      <div className="flex items-center gap-3">
        <div className="flex-1 h-2 rounded-full bg-slate-800 overflow-hidden"><div className={`h-full transition-all duration-500 ${strength > 70 ? 'bg-emerald-400' : strength > 45 ? 'bg-amber-400' : 'bg-rose-400'}`} style={{ width: `${strength}%` }} /></div>
        <span className="text-xs text-slate-400 w-16 text-right">{strength > 70 ? 'strong' : strength > 45 ? 'fair' : 'weak'}</span>
        <button onClick={() => run(() => send('PUT', '/api/mailcow/password-policy', f), reload)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}>Save policy</button>
      </div>
      <p className="text-[11px] text-slate-500">Applies to new and changed passwords for mailboxes and admins. App passwords made by CowSec always meet it.</p>
    </div>
  );
}

function FwdHosts({ hosts, run, reload }: { hosts: Lookout['fwdhosts']; run: Run; reload: () => void }) {
  const [h, setH] = useState('');
  const [spam, setSpam] = useState(true);
  const rows = Array.isArray(hosts) ? hosts : [];
  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">Servers allowed to pass mail on to this one, such as a backup MX or a forwarding service. Their mail skips greylisting and some sender checks.</p>
      <div className="flex flex-wrap items-end gap-2">
        <input className={`${input} w-64`} value={h} onChange={(e) => setH(e.target.value.trim())} placeholder="mx2.example.org or 203.0.113.0/24" />
        <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={spam} onChange={(e) => setSpam(e.target.checked)} /> Still check for spam</label>
        <button disabled={!h} onClick={() => run(() => send('POST', '/api/mailcow/fwdhosts', { hostname: h, filter_spam: spam }), () => { setH(''); reload(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add</button>
      </div>
      {rows.length === 0 ? <p className="text-xs text-slate-500">No forwarding hosts.</p> : (
        <div className="rounded-xl border border-slate-800 divide-y divide-slate-800/70">
          {rows.map((r) => (
            <div key={r.host} className="flex items-center gap-3 px-3 py-2 text-xs">
              <span className="font-mono text-slate-200">{r.host}</span><span className="text-slate-500">{r.source !== r.host ? r.source : ''}</span>
              <span className="ml-auto text-slate-400">{yes(r.keep_spam) ? 'spam not checked' : 'spam checked'}</span>
              <Confirm label="Remove" onConfirm={() => run(() => send('DELETE', `/api/mailcow/fwdhosts/${encodeURIComponent(r.host)}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function LookoutPanel() {
  const { data, error, notConfigured, loading, reload } = useApi<Lookout>('/api/mailcow/lookout');
  const { toast, run } = useToast();
  const [open, setOpen] = useState('');
  if (notConfigured) return <NotConfigured />;
  const admins = list(data?.admins as Admin[]), dadmins = list(data?.domain_admins as Admin[]);
  const noTfa = [...admins, ...dadmins].filter((a) => !yes(a.tfa_active)).length;
  const max = Math.max(1, ...(data?.senders || []).map((s) => s.count));
  const hours = data ? Math.max(1, Math.round((data.window.to - data.window.from) / 3600)) : 0;
  const rl = list(data?.ratelimited as Record<string, unknown>[]);
  return (
    <div className="space-y-6">
      {toast}
      {open && <SecurityModal user={open} onClose={() => { setOpen(''); reload(); }} />}
      <Header title="Lookout (Mail security)" sub="Who's sending, who's locked down, and who's guarding the gate"
        action={<button onClick={reload} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh</button>} />
      {error && <Problem text={error} />}
      {!data ? <Loading text="Climbing the lookout tower…" /> : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Tile label="Lockdowns" value={String(data.lockdowns.length)} sub={data.lockdowns.length ? 'mailboxes locked' : 'none active'} tone={data.lockdowns.length ? 'amber' : 'emerald'} icon={<Lock className="w-4 h-4" />} />
            <Tile label="Unusual senders" value={String(data.senders.filter((s) => s.unusual).length)} sub={`in the last ~${hours} h of logs`} tone={data.senders.some((s) => s.unusual) ? 'rose' : 'emerald'} icon={<Send className="w-4 h-4" />} />
            <Tile label="Mail queue" value={String(data.queue_total)} sub={data.queue_total ? 'waiting to go out' : 'empty'} tone={data.queue_total > 20 ? 'amber' : 'indigo'} icon={<Mail className="w-4 h-4" />} />
            <Tile label="Admins without 2FA" value={String(noTfa)} sub={`of ${admins.length + dadmins.length} admin${admins.length + dadmins.length === 1 ? '' : 's'}`} tone={noTfa ? 'rose' : 'emerald'} icon={<Users className="w-4 h-4" />} />
          </div>

          {data.lockdowns.length > 0 && (
            <Card title="Locked-down mailboxes" icon={<Lock className="w-4 h-4 text-amber-300" />}>
              <div className="divide-y divide-slate-800/70">
                {data.lockdowns.map((l) => (
                  <div key={l.user} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                    <span className="font-semibold text-white">{l.user}</span>
                    <span className="text-xs text-slate-500">since {ago(l.since)}{l.banned.length ? ` · ${l.banned.length} banned` : ''}{l.throttled ? ' · throttled' : ''}</span>
                    <button onClick={() => setOpen(l.user)} className={`${btn} ml-auto border border-amber-800 text-amber-200 hover:bg-amber-950/40`}><Undo2 className="w-3.5 h-3.5" /> Review or undo</button>
                  </div>
                ))}
              </div>
            </Card>
          )}

          <Card title="Outbound mail by sender" icon={<Send className="w-4 h-4 text-sky-400" />}>
            <p className="text-xs text-slate-500 mb-3">Messages sent by signed-in users in the last ~{hours} hours of Postfix logs. A sudden jump, or one account sending from many addresses, is how a stolen password usually shows up.</p>
            {data.senders.length === 0 ? <p className="text-sm text-slate-500">Nobody has sent mail in this window.</p> : (
              <div className="space-y-2">
                {data.senders.map((s) => (
                  <div key={s.user} className="grid grid-cols-[minmax(0,14rem)_1fr_auto] items-center gap-3 text-xs">
                    <span className="truncate font-semibold text-slate-200" title={s.user}>{s.user}</span>
                    <div className="h-2.5 rounded-full bg-slate-800 overflow-hidden"><div className={`h-full rounded-full transition-all duration-700 ${s.unusual ? 'bg-rose-400' : 'bg-sky-400'}`} style={{ width: `${(s.count / max) * 100}%` }} /></div>
                    <span className="flex items-center gap-2 shrink-0">
                      <span className="font-mono text-slate-300 w-10 text-right">{s.count}</span>
                      <span className="text-slate-500 w-24">{s.per_hour.toFixed(1)}/h · {s.ips} IP{s.ips === 1 ? '' : 's'}</span>
                      {s.unusual && <AlertTriangle className="w-3.5 h-3.5 text-rose-300" />}
                      <button onClick={() => setOpen(s.user)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`} title="Security"><Shield className="w-3.5 h-3.5" /></button>
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Queue by sender" icon={<Clock className="w-4 h-4 text-cyan-300" />}>
              {data.queued.length === 0 ? <p className="text-sm text-slate-500">Nothing waiting.</p> : (
                <div className="divide-y divide-slate-800/70 text-xs">
                  {data.queued.slice(0, 15).map((q) => <div key={q.sender} className="flex items-center gap-3 py-1.5"><span className="truncate text-slate-200">{q.sender || '(bounce)'}</span><span className="ml-auto font-mono text-slate-300">{q.count}</span></div>)}
                </div>
              )}
            </Card>
            <Card title="Hit the rate limit" icon={<Ban className="w-4 h-4 text-amber-300" />}>
              {rl.length === 0 ? <p className="text-sm text-slate-500">No messages were held back by a sending limit.</p> : (
                <div className="divide-y divide-slate-800/70 text-xs max-h-64 overflow-y-auto">
                  {rl.slice(0, 50).map((r, i) => (
                    <div key={i} className="flex items-center gap-3 py-1.5">
                      <span className="truncate text-slate-200">{String(r.from || r.user || r.header_from || '')}</span>
                      <span className="text-slate-500 truncate">{String(r.rl_name || r.rl_info || '')}</span>
                      <span className="ml-auto text-slate-500 shrink-0">{r.time ? ago(Number(r.time)) : ''}</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            <Card title="Admins and two-factor sign-in" icon={<Users className="w-4 h-4 text-indigo-300" />}>
              <div className="divide-y divide-slate-800/70 text-sm">
                {[...admins.map((a) => ({ ...a, role: 'mailcow admin' })), ...dadmins.map((a) => ({ ...a, role: 'domain admin' }))].map((a) => (
                  <div key={a.role + a.username} className="flex items-center gap-3 py-2">
                    {yes(a.tfa_active) ? <ShieldCheck className="w-4 h-4 text-emerald-300" /> : <ShieldAlert className="w-4 h-4 text-rose-300" />}
                    <span className="font-semibold text-white">{a.username}</span>
                    <span className="text-xs text-slate-500">{a.role}</span>
                    <span className="ml-auto"><Pill ok={yes(a.tfa_active)} yes="2FA on" no="no 2FA" /></span>
                  </div>
                ))}
              </div>
              {noTfa > 0 && <p className="text-[11px] text-slate-500 mt-2">Admins set up 2FA themselves in mailcow's own interface, under their account.</p>}
            </Card>
            <Card title="Password policy" icon={<KeyRound className="w-4 h-4 text-amber-300" />}>
              <PasswordPolicy p={data.password_policy || {}} run={run} reload={reload} />
            </Card>
          </div>

          <Card title="Forwarding hosts" icon={<Binoculars className="w-4 h-4 text-sky-300" />}>
            <FwdHosts hosts={data.fwdhosts} run={run} reload={reload} />
          </Card>
        </>
      )}
    </div>
  );
}
