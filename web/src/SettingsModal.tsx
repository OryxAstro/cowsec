import { useEffect, useState, type ReactNode } from 'react';
import {
  Activity, Check, Clock, Copy, Eye, EyeOff, KeyRound, Loader2, Lock, LogOut, MonitorSmartphone, ShieldCheck, Smartphone, Sparkles, User, X,
} from 'lucide-react';
import CowSecLogo, { BESSIE, currentLook, LOOKS, mascotPreference, seasonalLook, setMascotPreference, type Look } from './CowSecLogo';
import { Card } from './HostPanel';
import { postJSON, type MeResponse } from './session';

type Tab = 'account' | 'security' | 'activity' | 'mascot';

interface AuditEntry {
  time: string;
  event: string;
  user?: string;
  ip?: string;
  method?: string;
  path?: string;
  status?: number;
  detail?: string;
}

const EVENT_LABEL: Record<string, string> = {
  login_success: 'Signed in',
  login_failed: 'Sign-in failed',
  mfa_failed: '2FA failed',
  totp_enrolled: 'Authenticator enrolled',
  totp_reset: 'Authenticator reset',
  totp_reenrol_failed: 'New authenticator refused',
  password_changed: 'Password changed',
  password_change_failed: 'Password change refused',
  sessions_ended: 'Other sessions signed out',
  logout: 'Signed out',
};

const field = 'bg-slate-950/60 border border-slate-700 rounded-xl px-3 py-2.5 text-sm text-white focus:outline-none focus:border-indigo-500';
const input = `w-full ${field}`;
const primary = 'inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 disabled:opacity-40 cursor-pointer';
const quiet = 'inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-semibold border border-slate-700 text-slate-200 hover:bg-white/5 disabled:opacity-40 cursor-pointer';

function when(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

// Like the console's stat tiles, sized for dates rather than big counts.
function Stat({ label, value, sub, tone, icon }: { label: string; value: string; sub: string; tone: 'sky' | 'indigo' | 'emerald'; icon: ReactNode }) {
  const tones = { sky: 'from-sky-500/15 border-sky-500/30', indigo: 'from-indigo-500/15 border-indigo-500/30', emerald: 'from-emerald-500/15 border-emerald-500/30' }[tone];
  return (
    <div className={`rounded-2xl border bg-gradient-to-br to-transparent p-4 ${tones}`}>
      <div className="flex items-center justify-between text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        <span>{label}</span>
        {icon}
      </div>
      <p className="mt-2 text-lg font-bold text-white tabular-nums">{value}</p>
      <p className="text-[11px] text-slate-400 mt-0.5">{sub}</p>
    </div>
  );
}

function Note({ tone, children }: { tone: 'ok' | 'bad'; children: ReactNode }) {
  return <p className={`text-sm ${tone === 'ok' ? 'text-emerald-300' : 'text-rose-300'}`}>{children}</p>;
}

function PasswordField({ label, value, onChange, auto }: { label: string; value: string; onChange: (v: string) => void; auto: string }) {
  const [show, setShow] = useState(false);
  return (
    <label className="block space-y-1.5">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{label}</span>
      <span className="relative block">
        <input type={show ? 'text' : 'password'} value={value} onChange={(e) => onChange(e.target.value)} autoComplete={auto} className={`${input} pr-10`} />
        <button type="button" onClick={() => setShow(!show)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 cursor-pointer" aria-label={show ? 'Hide password' : 'Show password'}>
          {show ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
        </button>
      </span>
    </label>
  );
}

function CodeInput({ value, onChange, placeholder = '6-digit code' }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input value={value} onChange={(e) => onChange(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code"
      placeholder={placeholder} className={`${field} w-44 font-mono tracking-[0.3em] text-center`} />
  );
}

export default function SettingsModal({ onClose, onLogout }: { onClose: () => void; onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>('account');
  const [me, setMe] = useState<MeResponse | null>(null);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);

  const loadMe = () =>
    fetch('/api/auth/me', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then(setMe)
      .catch(() => {});
  useEffect(() => { loadMe(); }, []);

  useEffect(() => {
    if (tab === 'activity' && audit === null) {
      fetch('/api/auth/audit', { cache: 'no-store' })
        .then((r) => (r.ok ? r.json() : []))
        .then(setAudit)
        .catch(() => setAudit([]));
    }
  }, [tab, audit]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const tabs: { key: Tab; label: string; hint: string; icon: typeof User }[] = [
    { key: 'account', label: 'Account', hint: 'Profile, password, sessions', icon: User },
    { key: 'security', label: 'Security', hint: 'Two-factor sign-in', icon: ShieldCheck },
    { key: 'activity', label: 'Activity', hint: 'Sign-ins and changes', icon: Activity },
    { key: 'mascot', label: 'Mascot', hint: "Bessie's wardrobe", icon: Sparkles },
  ];

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="relative bg-slate-900 border border-slate-800 rounded-3xl max-w-5xl w-full h-[min(760px,90vh)] shadow-2xl flex overflow-hidden"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Settings"
      >
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(60%_50%_at_0%_0%,rgba(99,102,241,0.12),transparent_70%)]" />
        <nav className="relative w-60 shrink-0 border-r border-slate-800 p-4 flex flex-col">
          <div className="flex items-center gap-3 px-2 pb-5">
            <CowSecLogo className="w-11 h-11 drop-shadow-[0_4px_12px_rgba(56,189,248,0.35)]" />
            <div>
              <p className="text-base font-bold text-white leading-tight">Settings</p>
              <p className="text-xs text-slate-500">Your CowSec account</p>
            </div>
          </div>
          <div className="space-y-1">
            {tabs.map(({ key, label, hint, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-left transition-colors cursor-pointer border ${
                  tab === key ? 'bg-indigo-500/15 text-white border-indigo-400/25' : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border-transparent'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="min-w-0">
                  <span className="block text-sm font-semibold">{label}</span>
                  <span className="block text-[11px] text-slate-500 truncate">{hint}</span>
                </span>
              </button>
            ))}
          </div>
          <button onClick={onLogout} className="mt-auto flex items-center gap-2 px-3 py-2.5 rounded-xl border border-rose-800/60 bg-rose-950/30 text-rose-200 text-sm font-semibold hover:bg-rose-900/40 cursor-pointer">
            <LogOut className="w-4 h-4" /> Sign out
          </button>
        </nav>

        <div className="relative flex-1 min-w-0 overflow-y-auto p-7">
          <button onClick={onClose} className="absolute right-5 top-5 text-slate-500 hover:text-slate-300 cursor-pointer" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
          {!me ? (
            <Loader2 className="w-5 h-5 animate-spin text-slate-400" />
          ) : (
            <>
              {tab === 'account' && <AccountTab me={me} reload={loadMe} />}
              {tab === 'security' && <SecurityTab me={me} reload={loadMe} />}
              {tab === 'activity' && <ActivityTab audit={audit} />}
              {tab === 'mascot' && <MascotPicker />}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function Heading({ title, sub }: { title: string; sub: string }) {
  return (
    <div className="pr-8">
      <h3 className="text-xl font-bold text-white tracking-tight">{title}</h3>
      <p className="text-sm text-slate-400 mt-0.5">{sub}</p>
    </div>
  );
}

function AccountTab({ me, reload }: { me: MeResponse; reload: () => void }) {
  const id = me.identity;
  const ldap = id.source === 'ldap';
  const others = Math.max(0, (me.sessions || 1) - 1);
  const [ending, setEnding] = useState(false);
  const [endedMsg, setEndedMsg] = useState('');

  const endOthers = async () => {
    setEnding(true);
    const { ok, data } = await postJSON<{ endedSessions?: number; error?: string }>('/api/auth/sessions/end-others', {});
    setEnding(false);
    setEndedMsg(ok ? `Signed out ${data.endedSessions} other session${data.endedSessions === 1 ? '' : 's'}.` : data.error || 'That didn\'t work.');
    reload();
  };

  return (
    <div className="space-y-6">
      <Heading title="Account" sub="Your profile, password and where you're signed in." />
      <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-gradient-to-br from-indigo-500/15 via-sky-500/5 to-transparent p-5 flex items-center gap-5">
        <span className="w-16 h-16 shrink-0 rounded-2xl flex items-center justify-center text-xl font-bold text-white bg-gradient-to-br from-indigo-500 to-sky-500 shadow-[0_0_24px_-4px_var(--accent-glow)]">
          {(id.displayName || id.user).slice(0, 2).toUpperCase()}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-lg font-bold text-white truncate">{id.displayName || id.user}</p>
          <p className="text-sm text-slate-400 font-mono truncate">{id.email || id.user}</p>
          <div className="flex flex-wrap gap-1.5 mt-2 text-[11px] font-semibold">
            <span className="px-2 py-0.5 rounded-md border border-indigo-400/30 bg-indigo-500/10 text-indigo-200">{ldap ? 'Directory (LDAP)' : 'Local account'}</span>
            <span className="px-2 py-0.5 rounded-md border border-emerald-400/30 bg-emerald-500/10 text-emerald-200">{id.method === 'duo' ? 'Duo Push' : 'Authenticator app'}</span>
            <span className="px-2 py-0.5 rounded-md border border-slate-700 text-slate-300 font-mono">{id.user}</span>
          </div>
        </div>
        <img src={BESSIE[currentLook()]} alt="" className="hidden md:block w-28 h-28 -my-4 -mr-2 object-contain drop-shadow-[0_8px_20px_rgba(56,189,248,0.35)]" />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Stat label="Signed in" value={when(id.createdAt)} sub="this session" tone="sky" icon={<Clock className="w-4 h-4" />} />
        <Stat label="Session ends" value={when(id.expiresAt)} sub={`or after ${Math.round((me.idleTimeoutSec || 0) / 3600)}h idle`} tone="indigo" icon={<Lock className="w-4 h-4" />} />
        <Stat label="Signed in on" value={String(me.sessions || 1)} sub={others ? `this and ${others} other session${others === 1 ? '' : 's'}` : 'just this session'} tone="emerald" icon={<MonitorSmartphone className="w-4 h-4" />} />
      </div>
      {others > 0 && (
        <div className="flex items-center gap-3 -mt-2">
          <button onClick={endOthers} disabled={ending} className={quiet}>
            <LogOut className="w-4 h-4" /> {ending ? 'Signing out…' : 'Sign out my other sessions'}
          </button>
          {endedMsg && <Note tone="ok">{endedMsg}</Note>}
        </div>
      )}

      <PasswordCard ldap={ldap} reload={reload} />
    </div>
  );
}

function PasswordCard({ ldap, reload }: { ldap: boolean; reload: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null);
  const strength = Math.min(4, Math.floor(next.length / 4) - 2 + (/[^A-Za-z0-9]/.test(next) ? 1 : 0) + (/\d/.test(next) && /[A-Za-z]/.test(next) ? 1 : 0));
  const problem = next && next.length < 12 ? 'At least 12 characters.' : again && next !== again ? "The two new passwords don't match." : '';

  const save = async () => {
    setBusy(true);
    setMsg(null);
    const { ok, data } = await postJSON<{ error?: string; endedSessions?: number }>('/api/auth/password', { current, next });
    setBusy(false);
    if (ok) {
      setCurrent(''); setNext(''); setAgain('');
      setMsg({ tone: 'ok', text: `Password changed${data.endedSessions ? `; ${data.endedSessions} other session${data.endedSessions === 1 ? '' : 's'} signed out` : ''}.` });
      reload();
    } else {
      setMsg({ tone: 'bad', text: data.error || 'That didn\'t work.' });
    }
  };

  return (
    <Card title="Password" icon={<KeyRound className="w-4 h-4 text-indigo-300" />}>
      <p className="text-sm text-slate-400 leading-relaxed">
        {ldap
          ? 'This changes your directory (LDAP) password, so it changes everywhere the directory signs you in. Your directory may ask for more than CowSec does.'
          : 'Your local CowSec password. Other sessions are signed out when it changes.'}
      </p>
      <div className="grid sm:grid-cols-3 gap-3">
        <PasswordField label="Current password" value={current} onChange={setCurrent} auto="current-password" />
        <PasswordField label="New password" value={next} onChange={setNext} auto="new-password" />
        <PasswordField label="Repeat new password" value={again} onChange={setAgain} auto="new-password" />
      </div>
      {next && (
        <div className="flex items-center gap-3">
          <div className="flex gap-1 w-40">
            {[0, 1, 2, 3].map((i) => (
              <span key={i} className={`h-1.5 flex-1 rounded-full ${i < strength ? ['bg-rose-400', 'bg-amber-400', 'bg-sky-400', 'bg-emerald-400'][Math.max(0, strength - 1)] : 'bg-slate-800'}`} />
            ))}
          </div>
          <span className="text-xs text-slate-500">{problem || ['Weak', 'Weak', 'Fair', 'Good', 'Strong'][Math.max(0, strength)]}</span>
        </div>
      )}
      <div className="flex items-center gap-3">
        <button onClick={save} disabled={busy || !current || next.length < 12 || next !== again} className={primary}>
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Change password
        </button>
        {msg && <Note tone={msg.tone}>{msg.text}</Note>}
      </div>
    </Card>
  );
}

type Setup = { token: string; secret: string; qr: string };

function SecurityTab({ me, reload }: { me: MeResponse; reload: () => void }) {
  const enrolled = me.totpEnrolled;
  const [step, setStep] = useState<'idle' | 'prove' | 'scan' | 'done'>('idle');
  const [proof, setProof] = useState('');
  const [code, setCode] = useState('');
  const [setup, setSetup] = useState<Setup | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [copied, setCopied] = useState(false);
  const [ended, setEnded] = useState(0);

  const begin = async () => {
    setBusy(true);
    setErr('');
    const { ok, data } = await postJSON<Setup & { error?: string }>('/api/auth/totp/begin', enrolled ? { code: proof } : { password: proof });
    setBusy(false);
    if (!ok) return setErr(data.error || 'That didn\'t work.');
    setSetup(data);
    setStep('scan');
  };
  const confirm = async () => {
    setBusy(true);
    setErr('');
    const { ok, data } = await postJSON<{ error?: string; restart?: boolean; endedSessions?: number }>('/api/auth/totp/confirm', { token: setup?.token, code });
    setBusy(false);
    if (!ok) {
      setErr(data.error || 'That didn\'t work.');
      if (data.restart) { setStep('prove'); setSetup(null); setCode(''); }
      return;
    }
    setEnded(data.endedSessions || 0);
    setStep('done');
    setProof(''); setCode(''); setSetup(null);
    reload();
  };
  const cancel = () => { setStep('idle'); setProof(''); setCode(''); setSetup(null); setErr(''); };

  return (
    <div className="space-y-6">
      <Heading title="Security" sub="How you prove it's you after your password." />
      <Card
        title="Authenticator app (TOTP)"
        icon={<KeyRound className="w-4 h-4 text-indigo-300" />}
        right={<span className={`text-[11px] font-semibold px-2 py-0.5 rounded ${enrolled ? 'text-emerald-400 bg-emerald-950/60' : 'text-slate-400 bg-slate-800/80'}`}>{enrolled ? 'Enrolled' : 'Not enrolled'}</span>}
      >
        {step === 'idle' && (
          <>
            <p className="text-sm text-slate-400 leading-relaxed">
              {enrolled
                ? 'New phone, or moving to another app? Set up a new authenticator here. The old one keeps working until the new one has given a correct code.'
                : me.identity.method === 'duo'
                  ? 'You sign in with Duo. Add an authenticator app as a backup for when Duo is unavailable.'
                  : 'No authenticator is enrolled yet.'}
            </p>
            <button onClick={() => setStep('prove')} className={primary}>
              <Smartphone className="w-4 h-4" /> {enrolled ? 'Set up a new authenticator' : 'Add an authenticator app'}
            </button>
          </>
        )}
        {step === 'prove' && (
          <div className="space-y-3">
            <p className="text-sm text-slate-300">{enrolled ? 'First, a code from your current authenticator app.' : 'First, your password.'}</p>
            <div className="flex flex-wrap items-center gap-3">
              {enrolled ? <CodeInput value={proof} onChange={setProof} placeholder="current code" />
                : <input type="password" value={proof} onChange={(e) => setProof(e.target.value)} autoComplete="current-password" placeholder="Password" className={`${field} w-64`} />}
              <button onClick={begin} disabled={busy || (enrolled ? proof.length !== 6 : !proof)} className={primary}>
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : null} Continue
              </button>
              <button onClick={cancel} className={quiet}>Cancel</button>
            </div>
            {err && <Note tone="bad">{err}</Note>}
          </div>
        )}
        {step === 'scan' && setup && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-5">
              <div className="shrink-0 rounded-2xl bg-white p-3 shadow-[0_0_30px_-8px_var(--accent-glow)]">
                <img src={setup.qr} alt="Authenticator QR code" className="w-40 h-40 [image-rendering:pixelated]" />
              </div>
              <div className="min-w-0 space-y-2">
                <p className="text-sm text-slate-300">Scan this with your authenticator app, then enter the code it shows.</p>
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Can't scan? Enter this key</p>
                <p className="font-mono text-sm text-slate-200 break-all">{setup.secret.match(/.{1,4}/g)?.join(' ')}</p>
                <button onClick={() => { navigator.clipboard?.writeText(setup.secret); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
                  className="flex items-center gap-1 text-xs text-indigo-300 hover:text-indigo-200 cursor-pointer">
                  {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />} {copied ? 'Copied' : 'Copy key'}
                </button>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <CodeInput value={code} onChange={setCode} placeholder="new code" />
              <button onClick={confirm} disabled={busy || code.length !== 6} className={primary}>
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />} Use this authenticator
              </button>
              <button onClick={cancel} className={quiet}>Cancel</button>
            </div>
            {err && <Note tone="bad">{err}</Note>}
          </div>
        )}
        {step === 'done' && (
          <div className="flex flex-wrap items-center gap-3">
            <Note tone="ok">New authenticator in use{ended ? `; ${ended} other session${ended === 1 ? '' : 's'} signed out` : ''}. The old one no longer works.</Note>
            <button onClick={cancel} className={quiet}>Done</button>
          </div>
        )}
      </Card>
      {me.duo && (
        <Card title="Duo Push" icon={<Smartphone className="w-4 h-4 text-emerald-300" />}>
          <p className="text-sm text-slate-400 leading-relaxed">
            Offered at sign-in for directory accounts, through the Duo application configured for CowSec. Local accounts always use their
            authenticator app, so they keep working without outside services.
          </p>
        </Card>
      )}
      <p className="text-xs text-slate-500 leading-relaxed">
        Lost your phone and can't sign in? On the server, <span className="font-mono text-slate-400">sudo cowsec auth totp reset &lt;user&gt;</span> clears the
        authenticator and you set up a new one at your next sign-in.
      </p>
    </div>
  );
}

function ActivityTab({ audit }: { audit: AuditEntry[] | null }) {
  return (
    <div className="space-y-5">
      <Heading title="Activity" sub="Sign-ins and every change made through the console, newest first." />
      {audit === null ? (
        <Loader2 className="w-5 h-5 animate-spin text-slate-400" />
      ) : audit.length === 0 ? (
        <p className="text-sm text-slate-400">No activity recorded yet.</p>
      ) : (
        <div className="rounded-2xl border border-slate-800 bg-slate-950/40 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-semibold">When</th>
                <th className="px-4 py-3 font-semibold">User</th>
                <th className="px-4 py-3 font-semibold">Action</th>
                <th className="px-4 py-3 font-semibold">From</th>
              </tr>
            </thead>
            <tbody>
              {audit.map((e, i) => {
                const failed = e.event.endsWith('_failed') || (e.status ?? 0) >= 400;
                return (
                  <tr key={i} className="border-t border-slate-800/80 align-top hover:bg-white/[0.02]">
                    <td className="px-4 py-2.5 text-slate-400 whitespace-nowrap">{when(e.time)}</td>
                    <td className="px-4 py-2.5 text-slate-200 font-mono whitespace-nowrap">{e.user || '-'}</td>
                    <td className={`px-4 py-2.5 ${failed ? 'text-rose-300' : 'text-slate-200'}`}>
                      {e.event === 'api' ? (
                        <span className="font-mono break-all">
                          {e.method} {e.path} <span className={failed ? 'text-rose-400' : 'text-slate-500'}>{e.status}</span>
                        </span>
                      ) : (
                        <>
                          {EVENT_LABEL[e.event] || e.event}
                          {e.detail && <span className="text-slate-500"> · {e.detail}</span>}
                        </>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-slate-500 font-mono whitespace-nowrap">{e.ip}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function MascotPicker() {
  const [pref, setPref] = useState<Look | 'auto'>(mascotPreference);
  const pick = (v: Look | 'auto') => {
    setPref(v);
    setMascotPreference(v);
  };
  const today = seasonalLook();
  return (
    <div className="space-y-5">
      <Heading title="Mascot" sub="Choose how Bessie the Bouncer, CowSec's head of security, dresses. Saved in this browser." />
      <button onClick={() => pick('auto')}
        className={`w-full flex items-center gap-5 rounded-2xl border p-4 text-left cursor-pointer transition-colors ${pref === 'auto' ? 'border-sky-400/50 bg-sky-500/10' : 'border-slate-800 hover:border-slate-700'}`}>
        <CowSecLogo look={today} className="w-20 h-20 drop-shadow-[0_6px_16px_rgba(56,189,248,0.35)]" />
        <span>
          <span className="block text-base font-semibold text-white">Follow the calendar</span>
          <span className="block text-sm text-slate-400">Swaps her outfit for the season. Today: {LOOKS.find((l) => l.id === today)?.name}</span>
        </span>
      </button>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 cs-stagger">
        {LOOKS.map((l) => (
          <button key={l.id} onClick={() => pick(l.id)}
            className={`group flex flex-col items-center gap-2 rounded-2xl border p-4 cursor-pointer transition-colors ${pref === l.id ? 'border-sky-400/50 bg-sky-500/10' : 'border-slate-800 hover:border-slate-700 hover:bg-white/[0.02]'}`}>
            <CowSecLogo look={l.id} className="w-24 h-24 transition-transform duration-200 group-hover:-translate-y-0.5" />
            <span className="text-sm font-semibold text-white">{l.name}</span>
            <span className="text-[11px] text-slate-500 text-center">{l.when}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
