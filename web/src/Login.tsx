import { useEffect, useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent } from 'react';
import {
  AlertTriangle, ArrowLeft, Check, Copy, Eye, EyeOff, KeyRound, Loader2, Lock, ShieldCheck, Smartphone, User,
} from 'lucide-react';
import CowSecLogo from './CowSecLogo';
import { postJSON, type AuthConfig, type Identity } from './session';

type Stage =
  | { kind: 'credentials' }
  | { kind: 'mfa'; pendingToken: string; user: string; displayName: string; methods: ('totp' | 'duo')[] }
  | { kind: 'enroll'; pendingToken: string; user: string; displayName: string; secret: string; otpauthUrl: string; qr: string };

interface LoginResponse {
  error?: string;
  restart?: boolean;
  stage?: 'mfa' | 'enroll';
  pendingToken?: string;
  user?: string;
  displayName?: string;
  methods?: ('totp' | 'duo')[];
  secret?: string;
  otpauthUrl?: string;
  qr?: string;
}

// Six single-digit boxes: auto-advance, backspace to previous, paste a full code.
function CodeInput({ onComplete, disabled }: { onComplete: (code: string) => void; disabled: boolean }) {
  const [digits, setDigits] = useState<string[]>(Array(6).fill(''));
  const refs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    refs.current[0]?.focus();
  }, []);

  const set = (next: string[]) => {
    setDigits(next);
    if (next.every((d) => d !== '')) onComplete(next.join(''));
  };

  const onChange = (i: number, v: string) => {
    const d = v.replace(/\D/g, '').slice(-1);
    const next = [...digits];
    next[i] = d;
    set(next);
    if (d && i < 5) refs.current[i + 1]?.focus();
  };

  const onKeyDown = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) refs.current[i - 1]?.focus();
  };

  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const code = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (code.length === 6) {
      e.preventDefault();
      set(code.split(''));
      refs.current[5]?.focus();
    }
  };

  // Clear after a failed attempt so the next code can be typed straight away.
  useEffect(() => {
    if (!disabled && digits.every((d) => d !== '')) {
      setDigits(Array(6).fill(''));
      refs.current[0]?.focus();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [disabled]);

  return (
    <div className="flex justify-center gap-1.5 sm:gap-2">
      {digits.map((d, i) => (
        <input
          key={i}
          ref={(el) => {
            refs.current[i] = el;
          }}
          value={d}
          disabled={disabled}
          inputMode="numeric"
          autoComplete={i === 0 ? 'one-time-code' : 'off'}
          maxLength={1}
          onChange={(e) => onChange(i, e.target.value)}
          onKeyDown={(e) => onKeyDown(i, e)}
          onPaste={onPaste}
          aria-label={`Digit ${i + 1}`}
          className={`w-10 sm:w-11 h-12 sm:h-14 text-center text-xl font-mono font-bold rounded-xl border bg-slate-950/70 text-white
            focus:outline-none focus:border-indigo-400 focus:shadow-[0_0_0_3px_rgba(99,102,241,0.25)] transition-all
            disabled:opacity-50 ${i === 2 ? 'mr-1.5 sm:mr-2' : ''} ${d ? 'border-indigo-500/60' : 'border-slate-700'}`}
        />
      ))}
    </div>
  );
}

export default function Login({ onSignedIn, notice }: { onSignedIn: (id: Identity) => void; notice?: string }) {
  const [stage, setStage] = useState<Stage>({ kind: 'credentials' });
  const [username, setUsername] = useState(() => {
    try {
      return localStorage.getItem('cowsec_last_user') || '';
    } catch {
      return '';
    }
  });
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [method, setMethod] = useState<'totp' | 'duo'>('totp');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [configError, setConfigError] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    try {
      const theme = localStorage.getItem('cowsec_theme');
      if (theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.body.setAttribute('data-theme', theme);
      }
    } catch {
      // ignore
    }
    fetch('/api/auth/config', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : Promise.reject()))
      .then(setConfig)
      .catch(() => setConfigError(true));
  }, []);

  const restart = (msg: string) => {
    setStage({ kind: 'credentials' });
    setPassword('');
    setError(msg);
  };

  const submitCredentials = async (e: FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) return;
    setBusy(true);
    setError('');
    const { ok, data } = await postJSON<LoginResponse>('/api/auth/login', { username: username.trim(), password });
    setBusy(false);
    if (!ok || !data.pendingToken) {
      setError(data.error || 'Sign-in failed.');
      return;
    }
    try {
      localStorage.setItem('cowsec_last_user', username.trim());
    } catch {
      // ignore
    }
    setPassword('');
    const base = { pendingToken: data.pendingToken, user: data.user || username, displayName: data.displayName || username };
    if (data.stage === 'enroll') {
      setStage({ kind: 'enroll', ...base, secret: data.secret!, otpauthUrl: data.otpauthUrl!, qr: data.qr! });
    } else {
      const methods = data.methods || ['totp'];
      setMethod(methods.includes('duo') && !methods.includes('totp') ? 'duo' : 'totp');
      setStage({ kind: 'mfa', ...base, methods });
    }
  };

  const finish = async (path: string, body: object) => {
    setBusy(true);
    setError('');
    const { ok, data } = await postJSON<Identity & LoginResponse>(path, body);
    setBusy(false);
    if (ok && data.user) {
      onSignedIn(data);
      return;
    }
    if (data.restart) restart(data.error || 'Please sign in again.');
    else setError(data.error || 'Verification failed.');
  };

  const pending = stage.kind === 'credentials' ? '' : stage.pendingToken;
  const noMethods = config && !config.ldap && !config.localAdmin;

  return (
    <div className="min-h-screen relative overflow-hidden flex items-center justify-center px-4 py-10" style={{ backgroundColor: 'var(--bg-app)' }}>
      {/* Ambient strata glow + fine grid, echoing the logo's three layers */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-40 -left-32 w-[560px] h-[560px] rounded-full blur-[120px] opacity-40" style={{ background: 'var(--accent-from)' }} />
        <div className="absolute top-1/3 -right-40 w-[520px] h-[520px] rounded-full blur-[130px] opacity-25 bg-sky-500" />
        <div className="absolute -bottom-48 left-1/4 w-[560px] h-[460px] rounded-full blur-[140px] opacity-20 bg-emerald-500" />
        <div
          className="absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              'linear-gradient(rgba(148,163,184,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,0.6) 1px, transparent 1px)',
            backgroundSize: '44px 44px',
            maskImage: 'radial-gradient(ellipse at center, black 30%, transparent 75%)',
            WebkitMaskImage: 'radial-gradient(ellipse at center, black 30%, transparent 75%)',
          }}
        />
      </div>

      <div className="relative w-full max-w-[440px]">
        {/* Brand */}
        <div className="flex flex-col items-center text-center mb-7">
          <div className="relative mb-4">
            <div className="absolute inset-0 rounded-3xl blur-2xl opacity-60" style={{ background: 'var(--accent-glow)' }} />
            <CowSecLogo className="relative w-20 h-20 drop-shadow-[0_8px_24px_rgba(16,185,129,0.5)]" />
          </div>
          <div className="flex items-center space-x-2.5">
            <h1 className="font-extrabold text-3xl tracking-tight bg-gradient-to-r from-white via-sky-100 to-indigo-300 bg-clip-text text-transparent">
              CowSec
            </h1>
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest px-2 py-0.5 rounded-full bg-indigo-500/15 border border-indigo-400/30 text-indigo-300 shadow-[0_0_12px_rgba(99,102,241,0.25)]">
              Herd Protection
            </span>
          </div>
          <p className="text-xs text-slate-400 font-medium mt-1.5">
            Moo-ving bad actors off the mailcow pasture
          </p>
        </div>

        {/* Card */}
        <div className="relative rounded-3xl p-[1px] bg-gradient-to-b from-white/15 via-white/5 to-transparent shadow-[0_30px_80px_-20px_rgba(0,0,0,0.85)]">
          <div className="rounded-3xl bg-slate-900/70 backdrop-blur-2xl px-5 sm:px-8 py-7">
            {notice && stage.kind === 'credentials' && !error && (
              <div className="mb-5 flex items-start space-x-2 rounded-xl border border-amber-700/40 bg-amber-950/30 px-3 py-2.5 text-xs text-amber-200">
                <AlertTriangle className="w-4 h-4 mt-px shrink-0 text-amber-400" />
                <span>{notice}</span>
              </div>
            )}
            {error && (
              <div className="mb-5 flex items-start space-x-2 rounded-xl border border-rose-700/40 bg-rose-950/40 px-3 py-2.5 text-xs text-rose-200">
                <AlertTriangle className="w-4 h-4 mt-px shrink-0 text-rose-400" />
                <span>{error}</span>
              </div>
            )}

            {stage.kind === 'credentials' && (
              <form onSubmit={submitCredentials} className="space-y-4">
                <div>
                  <h2 className="text-lg font-bold text-white">Open the barn door</h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {config?.ldap ? `Use your CowSec account, or a directory account in the ${config.group} herd.` : 'Use your CowSec account to enter the barn.'}
                  </p>
                </div>
                <label className="block">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Username or email</span>
                  <div className="mt-1.5 relative">
                    <User className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                      autoFocus={!username}
                      className="w-full pl-10 pr-3 py-3 rounded-xl bg-slate-950/60 border border-slate-700 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-indigo-400 focus:shadow-[0_0_0_3px_rgba(99,102,241,0.2)] transition-all"
                      placeholder="you@example.com"
                    />
                  </div>
                </label>
                <label className="block">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Password</span>
                  <div className="mt-1.5 relative">
                    <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      autoFocus={!!username}
                      className="w-full pl-10 pr-11 py-3 rounded-xl bg-slate-950/60 border border-slate-700 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-indigo-400 focus:shadow-[0_0_0_3px_rgba(99,102,241,0.2)] transition-all"
                      placeholder="••••••••••••"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 cursor-pointer"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </label>
                <button
                  type="submit"
                  disabled={busy || !username.trim() || !password}
                  className="w-full flex items-center justify-center space-x-2 py-3 rounded-xl font-semibold text-sm text-white cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_10px_30px_-10px_var(--accent-glow)] hover:brightness-110 transition-all"
                  style={{ background: 'linear-gradient(135deg, var(--accent-from), var(--accent-to))' }}
                >
                  {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                  <span>{busy ? 'Checking your ear tag…' : 'Moo-ve in'}</span>
                </button>
                {noMethods && (
                  <p className="text-[11px] text-amber-300/90 leading-relaxed">
                    No account exists yet. On the server run{' '}
                    <code className="font-mono text-amber-200">sudo cowsec auth local-admin set &lt;name&gt;</code>.
                  </p>
                )}
                {configError && <p className="text-[11px] text-rose-300/90">This server didn't answer. Check the connection below.</p>}
              </form>
            )}

            {stage.kind === 'mfa' && (
              <div className="space-y-5">
                <div>
                  <h2 className="text-lg font-bold text-white">Prove you are not a wolf</h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Signing in as <span className="text-slate-200 font-semibold">{stage.displayName}</span>
                  </p>
                </div>
                {stage.methods.length > 1 && (
                  <div className="grid grid-cols-2 gap-1 p-1 rounded-xl bg-slate-950/60 border border-slate-800">
                    {(['totp', 'duo'] as const).map((m) => (
                      <button
                        key={m}
                        onClick={() => {
                          setMethod(m);
                          setError('');
                        }}
                        className={`flex items-center justify-center space-x-1.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                          method === m ? 'bg-indigo-500/20 text-white shadow-inner border border-indigo-400/30' : 'text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {m === 'totp' ? <KeyRound className="w-3.5 h-3.5" /> : <Smartphone className="w-3.5 h-3.5" />}
                        <span>{m === 'totp' ? 'Authenticator code' : 'Duo Push'}</span>
                      </button>
                    ))}
                  </div>
                )}
                {method === 'totp' ? (
                  <div className="space-y-3">
                    <p className="text-xs text-slate-400 text-center">Enter the 6-digit code from your authenticator app.</p>
                    <CodeInput disabled={busy} onComplete={(code) => finish('/api/auth/verify', { pendingToken: pending, method: 'totp', code })} />
                    {busy && (
                      <div className="flex justify-center text-xs text-slate-400 items-center space-x-2">
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>Verifying…</span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="space-y-4 text-center">
                    <div className="relative mx-auto w-20 h-20 flex items-center justify-center">
                      {busy && <span className="absolute inset-0 rounded-full bg-emerald-400/20 animate-ping" />}
                      <span className="relative w-16 h-16 rounded-2xl flex items-center justify-center bg-emerald-500/10 border border-emerald-400/30">
                        <Smartphone className="w-7 h-7 text-emerald-300" />
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">
                      {busy ? 'Push sent. Approve the request in the Duo Mobile app…' : 'Send a push notification to your phone.'}
                    </p>
                    <button
                      onClick={() => finish('/api/auth/verify', { pendingToken: pending, method: 'duo' })}
                      disabled={busy}
                      className="w-full flex items-center justify-center space-x-2 py-3 rounded-xl font-semibold text-sm text-white cursor-pointer disabled:opacity-60 bg-emerald-600 hover:bg-emerald-500 shadow-[0_10px_30px_-12px_rgba(16,185,129,0.7)] transition-all"
                    >
                      {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Smartphone className="w-4 h-4" />}
                      <span>{busy ? 'Waiting for approval…' : 'Send Duo Push'}</span>
                    </button>
                  </div>
                )}
                <button onClick={() => restart('')} className="flex items-center space-x-1.5 text-xs text-slate-400 hover:text-slate-200 cursor-pointer">
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Use a different account</span>
                </button>
              </div>
            )}

            {stage.kind === 'enroll' && (
              <div className="space-y-5">
                <div>
                  <h2 className="text-lg font-bold text-white">Get your ear tag (2FA)</h2>
                  <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
                    Scan this code with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden…), then
                    enter the 6-digit code it shows.
                  </p>
                </div>
                <div className="flex items-center gap-4">
                  <div className="shrink-0 rounded-2xl bg-white p-2.5 shadow-[0_0_30px_-8px_var(--accent-glow)]">
                    <img src={stage.qr} alt="Authenticator QR code" className="w-32 h-32 [image-rendering:pixelated]" />
                  </div>
                  <div className="min-w-0 space-y-1.5">
                    <p className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Can't scan? Enter this key</p>
                    <p className="font-mono text-[12px] text-slate-200 break-all leading-relaxed">{stage.secret.match(/.{1,4}/g)?.join(' ')}</p>
                    <button
                      onClick={() => {
                        navigator.clipboard?.writeText(stage.secret);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 1500);
                      }}
                      className="flex items-center space-x-1 text-[11px] text-indigo-300 hover:text-indigo-200 cursor-pointer"
                    >
                      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>{copied ? 'Copied' : 'Copy key'}</span>
                    </button>
                  </div>
                </div>
                <CodeInput disabled={busy} onComplete={(code) => finish('/api/auth/enroll', { pendingToken: pending, code })} />
                <button onClick={() => restart('')} className="flex items-center space-x-1.5 text-xs text-slate-400 hover:text-slate-200 cursor-pointer">
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Cancel</span>
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="mt-5 flex items-center justify-center text-[11px] text-slate-500">
          <span className="flex items-center space-x-1.5">
            <Lock className="w-3 h-3" />
            <span>{window.location.protocol === 'https:' ? 'Encrypted connection' : 'Unencrypted connection: prefer the HTTPS address'}</span>
          </span>
        </div>
      </div>
    </div>
  );
}
