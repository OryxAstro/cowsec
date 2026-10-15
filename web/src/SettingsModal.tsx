import { useEffect, useState, type ReactNode } from 'react';
import {
  Activity, KeyRound, Loader2, LogOut, ShieldCheck, Smartphone, Sparkles, User, X,
} from 'lucide-react';
import CowSecLogo, { LOOKS, mascotPreference, seasonalLook, setMascotPreference, type Look } from './CowSecLogo';
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
  logout: 'Signed out',
};

function when(iso: string) {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-slate-800/80 last:border-0">
      <span className="text-slate-400">{label}</span>
      <span className="text-slate-200 font-medium text-right">{value}</span>
    </div>
  );
}

export default function SettingsModal({ onClose, onLogout }: { onClose: () => void; onLogout: () => void }) {
  const [tab, setTab] = useState<Tab>('account');
  const [me, setMe] = useState<MeResponse | null>(null);
  const [audit, setAudit] = useState<AuditEntry[] | null>(null);
  const [resetCode, setResetCode] = useState('');
  const [resetMsg, setResetMsg] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch('/api/auth/me', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then(setMe)
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (tab === 'activity' && audit === null) {
      fetch('/api/auth/audit', { cache: 'no-store' })
        .then((r) => (r.ok ? r.json() : []))
        .then(setAudit)
        .catch(() => setAudit([]));
    }
  }, [tab, audit]);

  const resetAuthenticator = async () => {
    setBusy(true);
    setResetMsg('');
    const { ok, data } = await postJSON<{ error?: string }>('/api/auth/totp/reset', { code: resetCode });
    setBusy(false);
    if (ok) {
      onLogout(); // all sessions ended server-side; re-enrol at next sign-in
      return;
    }
    setResetMsg(data.error || 'Reset failed.');
  };

  const id = me?.identity;
  const tabs: { key: Tab; label: string; icon: typeof User }[] = [
    { key: 'account', label: 'Account', icon: User },
    { key: 'security', label: 'Security', icon: ShieldCheck },
    { key: 'activity', label: 'Activity', icon: Activity },
    { key: 'mascot', label: 'Mascot', icon: Sparkles },
  ];

  return (
    <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full shadow-2xl flex flex-col max-h-[86vh]"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <h3 className="font-bold text-base text-white flex items-center space-x-2">
            <ShieldCheck className="w-5 h-5 text-indigo-400" />
            <span>Settings</span>
          </h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300 cursor-pointer" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="flex min-h-0 flex-1">
          <nav className="w-44 shrink-0 border-r border-slate-800 p-3 space-y-1">
            {tabs.map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`w-full flex items-center space-x-2 px-3 py-2 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  tab === key ? 'bg-indigo-500/15 text-white border border-indigo-400/25' : 'text-slate-400 hover:text-slate-200 hover:bg-white/5 border border-transparent'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{label}</span>
              </button>
            ))}
          </nav>

          <div className="flex-1 min-w-0 overflow-y-auto p-6 text-xs">
            {tab === 'account' &&
              (id ? (
                <div className="space-y-5">
                  <div className="flex items-center space-x-3">
                    <span className="w-12 h-12 rounded-2xl flex items-center justify-center text-base font-bold text-white bg-gradient-to-br from-indigo-500 to-sky-500 shadow-[0_0_20px_-4px_var(--accent-glow)]">
                      {(id.displayName || id.user).slice(0, 2).toUpperCase()}
                    </span>
                    <div>
                      <p className="text-sm font-bold text-white">{id.displayName || id.user}</p>
                      <p className="text-slate-400 font-mono">{id.email || id.user}</p>
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-800 bg-slate-950/40 px-4">
                    <Row label="Username" value={<span className="font-mono">{id.user}</span>} />
                    <Row label="Account type" value={id.source === 'ldap' ? 'Directory (LDAP)' : 'Local account'} />
                    <Row label="Second factor used" value={id.method === 'duo' ? 'Duo Push' : 'Authenticator app'} />
                    <Row label="Signed in" value={when(id.createdAt)} />
                    <Row label="Session expires" value={`${when(id.expiresAt)} (or after ${Math.round((me!.idleTimeoutSec || 0) / 3600)}h idle)`} />
                  </div>
                  <button
                    onClick={onLogout}
                    className="flex items-center space-x-2 px-4 py-2 rounded-xl border border-rose-800/60 bg-rose-950/30 text-rose-200 font-semibold hover:bg-rose-900/40 cursor-pointer"
                  >
                    <LogOut className="w-4 h-4" />
                    <span>Sign out</span>
                  </button>
                </div>
              ) : (
                <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
              ))}

            {tab === 'security' && (
              <div className="space-y-5">
                <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-3">
                  <div className="flex items-center space-x-2">
                    <KeyRound className="w-4 h-4 text-indigo-300" />
                    <p className="font-semibold text-slate-200">Authenticator app (TOTP)</p>
                    <span
                      className={`ml-auto text-[11px] font-semibold px-2 py-0.5 rounded ${
                        me?.totpEnrolled ? 'text-emerald-400 bg-emerald-950/60' : 'text-slate-400 bg-slate-800/80'
                      }`}
                    >
                      {me?.totpEnrolled ? 'Enrolled' : 'Not enrolled'}
                    </span>
                  </div>
                  {me?.totpEnrolled ? (
                    <>
                      <p className="text-slate-400 leading-relaxed">
                        New phone? Reset the authenticator with a current code. All your sessions end and you'll scan a new QR code at
                        your next sign-in.
                      </p>
                      <div className="flex items-center gap-2">
                        <input
                          value={resetCode}
                          onChange={(e) => setResetCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                          inputMode="numeric"
                          placeholder="Current code"
                          className="w-36 bg-slate-950/60 border border-slate-700 rounded-lg px-3 py-2 font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                        />
                        <button
                          onClick={resetAuthenticator}
                          disabled={busy || resetCode.length !== 6}
                          className="px-3 py-2 rounded-lg border border-amber-700/50 bg-amber-950/30 text-amber-200 font-semibold disabled:opacity-40 cursor-pointer"
                        >
                          {busy ? 'Resetting…' : 'Reset authenticator'}
                        </button>
                      </div>
                      {resetMsg && <p className="text-rose-300">{resetMsg}</p>}
                    </>
                  ) : (
                    <p className="text-slate-400">You sign in with Duo. An authenticator app is set up automatically if Duo is ever unavailable for your account.</p>
                  )}
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/40 p-4 space-y-2">
                  <div className="flex items-center space-x-2">
                    <Smartphone className="w-4 h-4 text-emerald-300" />
                    <p className="font-semibold text-slate-200">Duo Push</p>
                  </div>
                  <p className="text-slate-400 leading-relaxed">
                    Offered at sign-in for directory accounts when a Duo application is configured for CowSec
                    (<span className="font-mono">COWSEC_DUO_*</span>). Local accounts always use their authenticator app, so they
                    keep working without external services.
                  </p>
                </div>
              </div>
            )}

            {tab === 'activity' &&
              (audit === null ? (
                <Loader2 className="w-4 h-4 animate-spin text-slate-400" />
              ) : audit.length === 0 ? (
                <p className="text-slate-400">No activity recorded yet.</p>
              ) : (
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-[11px] uppercase tracking-wider text-slate-500">
                      <th className="pb-2 font-semibold">When</th>
                      <th className="pb-2 font-semibold">User</th>
                      <th className="pb-2 font-semibold">Action</th>
                      <th className="pb-2 font-semibold">From</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.map((e, i) => {
                      const failed = e.event.endsWith('_failed') || (e.status ?? 0) >= 400;
                      return (
                        <tr key={i} className="border-t border-slate-800/80 align-top">
                          <td className="py-2 pr-3 text-slate-400 whitespace-nowrap">{when(e.time)}</td>
                          <td className="py-2 pr-3 text-slate-200 font-mono whitespace-nowrap">{e.user || '-'}</td>
                          <td className={`py-2 pr-3 ${failed ? 'text-rose-300' : 'text-slate-200'}`}>
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
                          <td className="py-2 text-slate-500 font-mono whitespace-nowrap">{e.ip}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ))}

            {tab === 'mascot' && <MascotPicker />}
          </div>
        </div>
      </div>
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
    <div className="space-y-4">
      <p className="text-slate-400">Choose how <b className="text-white">Bessie the Bouncer</b>, CowSec's head of security, dresses. "Follow the calendar" swaps her hat and collar charm for the season; the choice is saved in this browser.</p>
      <button onClick={() => pick('auto')}
        className={`w-full flex items-center gap-3 rounded-xl border p-3 text-left cursor-pointer ${pref === 'auto' ? 'border-sky-400/50 bg-sky-500/10' : 'border-slate-800 hover:border-slate-700'}`}>
        <CowSecLogo look={today} className="w-12 h-12" />
        <span><span className="block text-sm font-semibold text-white">Follow the calendar</span><span className="block text-slate-400">Today: {LOOKS.find((l) => l.id === today)?.name}</span></span>
      </button>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 cs-stagger">
        {LOOKS.map((l) => (
          <button key={l.id} onClick={() => pick(l.id)}
            className={`flex flex-col items-center gap-1.5 rounded-xl border p-3 cursor-pointer transition-colors ${pref === l.id ? 'border-sky-400/50 bg-sky-500/10' : 'border-slate-800 hover:border-slate-700'}`}>
            <CowSecLogo look={l.id} className="w-14 h-14" />
            <span className="text-xs font-semibold text-white">{l.name}</span>
            <span className="text-[10px] text-slate-500 text-center">{l.when}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
