import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import {
  AlertTriangle, ArrowLeft, ArrowRight, CheckCircle2, Circle, Cloud, Globe, KeyRound, Loader2, Lock, Network, PartyPopper,
  Search, Server, ShieldCheck, Terminal, User, XCircle,
} from 'lucide-react';
import CowSecLogo from './CowSecLogo';
import { postJSON } from './session';

interface Check { id: string; title: string; status: 'ok' | 'warn' | 'fail' | 'info'; detail: string }
interface Mailcow { found: boolean; dir?: string; hostname?: string; domains?: string[]; skipLetsEncrypt?: boolean }
interface Existing {
  certbot?: { name: string; certPath: string; keyPath: string; names: string[]; authenticator: string };
  edgeSites?: { files: string[]; consoleHostname: string | null; adminLanOnly: boolean };
  cloudflareRealIP?: object;
  chronyPtp?: object;
  policy?: { homeCountries?: string[] };
}
interface Fresh { timezone: string; memKiB: number; clamavPrompt: boolean; hostname: string; dockerMajor: number; branches: string[]; timezones: string[] }
interface Preflight { checks: Check[]; mailcow: Mailcow; ok: boolean; ipv6: boolean; existing?: Existing; fresh?: Fresh | null }
interface MailcowAdmin { username: string; password: string; url: string }
interface Cred { name: string; description: string; alias: boolean }
interface ProviderHelp { code: string; name: string; credentials: Cred[]; additional: Cred[]; docs: string | null }
interface JobStep { id: string; title: string; state: 'pending' | 'running' | 'ok' | 'failed' }
interface Job { state: 'never' | 'running' | 'ok' | 'failed'; steps?: JobStep[]; log?: string; error?: string }

type Access = 'local' | 'lan' | 'wan' | 'tunnel';
const STEPS = ['Checks', 'Mail server', 'Protection', 'Certificates', 'Access', 'Account', 'Install'] as const;

const guessCountry = () => {
  const m = (navigator.language || '').match(/-([A-Z]{2})$/i);
  return m ? m[1].toUpperCase() : 'GB';
};

function Shell({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="min-h-screen relative overflow-hidden flex items-start justify-center px-4 py-10" style={{ backgroundColor: 'var(--bg-app)' }}>
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-40 -left-32 w-[560px] h-[560px] rounded-full blur-[120px] opacity-40" style={{ background: 'var(--accent-from)' }} />
        <div className="absolute top-1/3 -right-40 w-[520px] h-[520px] rounded-full blur-[130px] opacity-25 bg-sky-500" />
        <div className="absolute -bottom-48 left-1/4 w-[560px] h-[460px] rounded-full blur-[140px] opacity-20 bg-emerald-500" />
      </div>
      <div className={`relative w-full ${wide ? 'max-w-3xl' : 'max-w-[460px]'}`}>
        <div className="flex flex-col items-center text-center mb-7">
          <CowSecLogo className="w-16 h-16 mb-3 drop-shadow-[0_8px_24px_rgba(16,185,129,0.5)]" />
          <div className="flex items-center space-x-2.5">
            <h1 className="font-extrabold text-3xl tracking-tight bg-gradient-to-r from-white via-sky-100 to-indigo-300 bg-clip-text text-transparent">CowSec</h1>
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest px-2 py-0.5 rounded-full bg-indigo-500/15 border border-indigo-400/30 text-indigo-300">Barn raising</span>
          </div>
          <p className="text-xs text-slate-400 font-medium mt-1.5">First-time setup for CrowdSec on your mailcow server</p>
        </div>
        <div className="rounded-3xl p-[1px] bg-gradient-to-b from-white/15 via-white/5 to-transparent shadow-[0_30px_80px_-20px_rgba(0,0,0,0.85)]">
          <div className="rounded-3xl bg-slate-900/70 backdrop-blur-2xl px-5 sm:px-8 py-7">{children}</div>
        </div>
      </div>
    </div>
  );
}

function Toggle({ on, onChange, label, hint, disabled, badge }: { on: boolean; onChange: (v: boolean) => void; label: string; hint: ReactNode; disabled?: boolean; badge?: string }) {
  return (
    <label className={`flex items-start justify-between gap-4 p-3.5 rounded-2xl border border-slate-800 bg-slate-950/40 ${disabled ? 'opacity-50' : 'cursor-pointer hover:border-slate-700'}`}>
      <div>
        <p className="text-sm font-semibold text-white flex items-center gap-2">
          {label}
          {badge && <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-emerald-950/70 text-emerald-300">{badge}</span>}
        </p>
        <p className="text-xs text-slate-400 mt-0.5">{hint}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={on}
        disabled={disabled}
        onClick={() => onChange(!on)}
        className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${on ? 'bg-emerald-500' : 'bg-slate-700'}`}
      >
        <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${on ? 'translate-x-5' : ''}`} />
      </button>
    </label>
  );
}

const input = 'w-full bg-slate-950/60 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500';
const label = 'block text-[11px] font-semibold uppercase tracking-wider text-slate-500 mb-1';

function Choice({ active, onClick, icon, title, children }: { active: boolean; onClick: () => void; icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-left p-3.5 rounded-2xl border transition-colors cursor-pointer ${active ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-800 bg-slate-950/40 hover:border-slate-700'}`}
    >
      <p className="text-sm font-semibold text-white flex items-center gap-2">{icon}{title}</p>
      <div className="text-xs text-slate-400 mt-1 space-y-1">{children}</div>
    </button>
  );
}

function ErrorLine({ text }: { text: string }) {
  if (!text) return null;
  return (
    <p className="text-sm text-rose-300 flex items-start gap-2 bg-rose-950/40 border border-rose-900/60 rounded-xl px-3 py-2">
      <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
      <span>{text}</span>
    </p>
  );
}

export default function SetupWizard() {
  const [unlocked, setUnlocked] = useState<boolean | null>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);

  const [pre, setPre] = useState<Preflight | null>(null);
  const [home, setHome] = useState<string[]>([guessCountry()]);
  const [newCountry, setNewCountry] = useState('');
  const [comp, setComp] = useState({ edge: true, adminLanOnly: true, cloudflareRealIP: false, chronyPtp: false, banPolicy: true, mailcowApi: true });

  const [mcMode, setMcMode] = useState<'existing' | 'install'>('existing');
  const [backupOk, setBackupOk] = useState(false);
  const [mcHost, setMcHost] = useState('');
  const [mcTz, setMcTz] = useState('');
  const [mcClamOff, setMcClamOff] = useState(false);
  const [mcBranch, setMcBranch] = useState<'master' | 'nightly'>('master');
  const [mcApex, setMcApex] = useState(false);
  const [mcAdmin, setMcAdmin] = useState<MailcowAdmin | null>(null);

  const [certMode, setCertMode] = useState<'mailcow' | 'dns01' | 'existing'>('dns01');
  const [providers, setProviders] = useState<string[] | null>(null);
  const [providerFilter, setProviderFilter] = useState('');
  const [provider, setProvider] = useState('');
  const [help, setHelp] = useState<ProviderHelp | null>(null);
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [showAliases, setShowAliases] = useState(false);
  const [email, setEmail] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [perDomain, setPerDomain] = useState(true);
  const [wildcard, setWildcard] = useState(true);
  const [staging, setStaging] = useState(false);

  const [access, setAccess] = useState<Access>('lan');
  const [hostname, setHostname] = useState('');
  const [tunnelToken, setTunnelToken] = useState('');

  const [user, setUser] = useState('');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [accountDone, setAccountDone] = useState(false);
  const [directory, setDirectory] = useState(false);

  const [job, setJob] = useState<Job | null>(null);
  const [finished, setFinished] = useState(false);
  const logRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    fetch('/api/setup/state', { cache: 'no-store' })
      .then((r) => r.json())
      .then((s) => {
        setUnlocked(!!s.unlocked);
        setAccountDone(!!s.accounts);
        setDirectory(!!s.directory);
      })
      .catch(() => setUnlocked(false));
  }, []);

  const loadChecks = async () => {
    setPre(null);
    setError('');
    try {
      const r = await fetch('/api/setup/check', { cache: 'no-store' });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error || 'check failed');
      setPre(d);
      if (d.mailcow?.domains) setDomains(d.mailcow.domains);
      if (!d.mailcow?.found && d.fresh) {
        setMcMode('install');
        setMcTz((t) => t || d.fresh.timezone);
        setMcHost((h) => h || d.fresh.hostname);
        setMcClamOff(d.fresh.clamavPrompt); // mailcow's own default at <= 2.5 GiB is "disable ClamAV"
      }
      if (d.mailcow?.hostname && !hostname) setHostname('cowsec.' + d.mailcow.hostname.split('.').slice(1).join('.'));
      setComp((c) => ({ ...c, chronyPtp: true }));
      // Debian 13: OpenResty's packages can't be verified yet, so the edge starts off
      if ((d.checks as Check[] | undefined)?.some((c) => c.id === 'openresty-key' && c.status === 'warn')) {
        setComp((c) => ({ ...c, edge: false }));
        setCertMode('mailcow'); // DNS-01 certificates are served by the edge
        setAccess('local'); // so are LAN and internet access to the console; an SSH tunnel or Cloudflare Tunnel still work
      }
      // an existing hand-built setup: start from the choices it already made
      const ex: Existing = d.existing || {};
      if (ex.edgeSites?.consoleHostname) setHostname(ex.edgeSites.consoleHostname);
      if (ex.edgeSites) setComp((c) => ({ ...c, edge: true, adminLanOnly: ex.edgeSites!.adminLanOnly || c.adminLanOnly }));
      if (ex.cloudflareRealIP) setComp((c) => ({ ...c, cloudflareRealIP: true }));
      if (ex.policy?.homeCountries?.length) setHome(ex.policy.homeCountries);
      if (ex.certbot && !['standalone', 'webroot', 'nginx', 'apache'].includes(ex.certbot.authenticator)) setCertMode('existing');
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  useEffect(() => {
    if (unlocked) loadChecks();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unlocked]);

  useEffect(() => {
    if (step === 3 && certMode === 'dns01' && providers === null) {
      fetch('/api/setup/dns/providers', { cache: 'no-store' })
        .then((r) => r.json())
        .then((d) => setProviders(d.providers || []))
        .catch(() => setProviders([]));
    }
  }, [step, certMode, providers]);

  useEffect(() => {
    if (!provider) return;
    setHelp(null);
    setCreds({});
    fetch(`/api/setup/dns/help?code=${encodeURIComponent(provider)}`, { cache: 'no-store' })
      .then((r) => r.json())
      .then(setHelp)
      .catch(() => {});
  }, [provider]);

  // Poll the installer while it runs.
  useEffect(() => {
    if (!job || job.state !== 'running') return;
    const t = window.setTimeout(async () => {
      const r = await fetch('/api/setup/job', { cache: 'no-store' });
      if (r.ok) setJob(await r.json());
    }, 2000);
    return () => window.clearTimeout(t);
  }, [job]);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [job?.log]);

  // Fresh install: certificates and the console name follow the new mail server's domain.
  const mcParent = mcHost.split('.').slice(1).join('.');
  useEffect(() => {
    if (mcMode !== 'install' || !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(mcHost)) return;
    const parent = mcHost.split('.').length > 2 ? mcParent : mcHost;
    setDomains([parent]);
    setHostname('cowsec.' + parent);
  }, [mcMode, mcHost, mcParent]);
  useEffect(() => {
    if (job?.state === 'ok' && mcMode === 'install' && !mcAdmin)
      fetch('/api/setup/mailcow-admin', { cache: 'no-store' }).then((r) => r.json()).then((d) => setMcAdmin(d.admin)).catch(() => {});
  }, [job?.state, mcMode, mcAdmin]);

  const config = useMemo(() => {
    const filled = Object.fromEntries(Object.entries(creds).filter(([, v]) => v.trim()));
    return {
      mailcow: mcMode === 'install' ? { mode: 'install', hostname: mcHost, timezone: mcTz, skipClamd: mcClamOff, branch: mcBranch, acceptNoSubdomain: mcApex } : { mode: 'existing' },
      homeCountries: home,
      components: { ...comp, cloudflareRealIP: comp.edge && comp.cloudflareRealIP },
      certs: certMode === 'dns01' ? { mode: 'dns01', provider, credentials: filled, email, domains, perDomain, wildcard, staging }
        : certMode === 'existing' && pre?.existing?.certbot ? { mode: 'existing', certPath: pre.existing.certbot.certPath, keyPath: pre.existing.certbot.keyPath }
        : { mode: 'mailcow' },
      access: access === 'tunnel' ? { mode: access, tunnelToken } : access === 'local' ? { mode: access } : { mode: access, hostname },
    };
  }, [mcMode, mcHost, mcTz, mcClamOff, mcBranch, mcApex, home, comp, certMode, provider, creds, email, domains, perDomain, wildcard, staging, access, hostname, tunnelToken, pre]);

  const stepError = (): string => {
    if (step === 0) return pre?.ok ? '' : 'Fix the failed checks first.';
    if (step === 1) {
      if (mcMode === 'existing') return pre?.mailcow.found ? '' : 'No mailcow found on this server. Choose to install it, or set MAILCOW_DIR.';
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(mcHost)) return 'Enter the mail server hostname, e.g. mail.example.com.';
      if (mcHost.split('.').length === 2 && !mcApex) return 'Use a subdomain (e.g. mail.' + mcHost + '), or confirm the warning.';
      if (!mcTz) return 'Choose a timezone.';
      if (pre?.checks.some((c) => c.id.startsWith('fresh-') && c.status === 'fail')) return 'Fix the failed checks for installing mailcow first.';
      return '';
    }
    if (step === 2) return home.length ? '' : 'Choose at least one home country.';
    if (step === 3 && certMode === 'dns01') {
      if (!comp.edge) return 'DNS-01 certificates need the OpenResty edge (Protection step).';
      if (!provider || !help) return 'Choose your DNS provider.';
      if (!Object.values(creds).some((v) => v.trim())) return 'Enter the DNS provider credentials.';
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return "Enter an e-mail address for Let's Encrypt.";
      if (!domains.length) return 'Choose at least one domain.';
    }
    if (step === 4) {
      if ((access === 'lan' || access === 'wan') && !comp.edge) return 'LAN and internet access are served by the OpenResty edge (Protection step).';
      if ((access === 'lan' || access === 'wan') && !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(hostname)) return 'Enter the hostname for the console.';
      if (access === 'tunnel' && tunnelToken.trim().length < 40) return 'Paste the Cloudflare Tunnel token.';
    }
    if (step === 5 && !accountDone && !directory) return 'Create the admin account.';
    return '';
  };

  const unlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    const r = await postJSON<{ error?: string }>('/api/setup/unlock', { token });
    setBusy(false);
    if (r.ok) setUnlocked(true);
    else setError(r.data.error || 'That token is not right.');
  };

  const createAccount = async () => {
    setError('');
    if (pw !== pw2) return setError('The passwords do not match.');
    setBusy(true);
    const r = await postJSON<{ error?: string }>('/api/setup/account', { username: user, password: pw });
    setBusy(false);
    if (r.ok) {
      setAccountDone(true);
      setPw('');
      setPw2('');
    } else setError(r.data.error || 'Could not create the account.');
  };

  const install = async () => {
    setError('');
    setBusy(true);
    const r = await postJSON<{ error?: string }>('/api/setup/install', config);
    setBusy(false);
    if (!r.ok) return setError(r.data.error || 'Could not start the installer.');
    setJob({ state: 'running', steps: [] });
  };

  const finish = async () => {
    setBusy(true);
    const r = await postJSON<{ error?: string }>('/api/setup/finish', {});
    setBusy(false);
    if (r.ok) setFinished(true);
    else setError(r.data.error || 'Could not finish setup.');
  };

  // ---------- unlock
  if (unlocked === null) {
    return (
      <Shell>
        <Loader2 className="w-6 h-6 animate-spin text-slate-500 mx-auto" />
      </Shell>
    );
  }
  if (!unlocked) {
    return (
      <Shell>
        <form onSubmit={unlock} className="space-y-5">
          <div>
            <h2 className="text-lg font-bold text-white">Open the gate</h2>
            <p className="text-sm text-slate-400 mt-1">
              On the server, run <code className="font-mono text-amber-200">sudo cowsec-setup</code> and paste the setup token it prints.
            </p>
          </div>
          <div>
            <span className={label}>Setup token</span>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input className={`${input} pl-9 font-mono`} value={token} onChange={(e) => setToken(e.target.value.trim())} autoFocus autoComplete="off" spellCheck={false} />
            </div>
          </div>
          <ErrorLine text={error} />
          <button disabled={busy || token.length < 20} className="w-full flex items-center justify-center gap-2 rounded-xl py-2.5 text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600 disabled:opacity-50 cursor-pointer">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
            <span>Unlock setup</span>
          </button>
          <p className="text-[11px] text-slate-500">
            This page uses a temporary self-signed certificate. <code className="font-mono">cowsec-setup</code> also prints its fingerprint so you can check it matches what your browser shows.
          </p>
        </form>
      </Shell>
    );
  }

  // ---------- finished
  if (finished) {
    const url = access === 'lan' || access === 'wan' ? `https://${hostname}` : null;
    return (
      <Shell wide>
        <div className="text-center space-y-4">
          <PartyPopper className="w-10 h-10 text-emerald-400 mx-auto" />
          <h2 className="text-xl font-bold text-white">The barn is built. Moo!</h2>
          <p className="text-sm text-slate-400">Setup is closed and this temporary page has stopped. Sign in to your console and enrol your authenticator app.</p>
          {url && (
            <a href={url} className="inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600">
              Open {url} <ArrowRight className="w-4 h-4" />
            </a>
          )}
          {access === 'local' && (
            <div className="text-left text-sm text-slate-300 bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-2">
              <p>The console only listens on the server itself. From your computer:</p>
              <pre className="font-mono text-xs text-amber-200 whitespace-pre-wrap">ssh -L 8090:127.0.0.1:8090 you@{window.location.hostname}</pre>
              <p>then open <code className="font-mono">http://localhost:8090</code>.</p>
            </div>
          )}
          {access === 'tunnel' && <p className="text-sm text-slate-300">Open the public hostname you gave the tunnel in Cloudflare Zero Trust.</p>}
        </div>
      </Shell>
    );
  }

  const err = stepError();
  const filteredProviders = (providers || []).filter((p) => p.includes(providerFilter.toLowerCase()));
  const mainCreds = help?.credentials.filter((c) => !c.alias) ?? [];
  const aliasCreds = help?.credentials.filter((c) => c.alias) ?? [];

  return (
    <Shell wide>
      {/* stepper */}
      <ol className="flex items-center justify-between mb-7 text-[11px] font-semibold">
        {STEPS.map((s, i) => (
          <li key={s} className={`flex items-center gap-1.5 ${i === step ? 'text-white' : i < step ? 'text-emerald-400' : 'text-slate-500'}`}>
            {i < step ? <CheckCircle2 className="w-4 h-4" /> : <span className={`w-5 h-5 rounded-full flex items-center justify-center border ${i === step ? 'border-indigo-400 bg-indigo-500/20' : 'border-slate-700'}`}>{i + 1}</span>}
            <span className="hidden sm:inline">{s}</span>
          </li>
        ))}
      </ol>

      <div key={step} className="cs-page">
      {step === 0 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">Checking the pasture</h2>
            <p className="text-sm text-slate-400">CowSec looks at this server before changing anything.</p>
          </div>
          {!pre ? (
            <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Running checks…</div>
          ) : (
            <ul className="divide-y divide-slate-800/80 border border-slate-800 rounded-2xl bg-slate-950/40">
              {pre.checks.map((c) => (
                <li key={c.id} className="flex items-start gap-3 px-4 py-2.5 text-sm">
                  {c.status === 'ok' ? <CheckCircle2 className="w-4 h-4 text-emerald-400 mt-0.5" /> : c.status === 'fail' ? <XCircle className="w-4 h-4 text-rose-400 mt-0.5" /> : c.status === 'warn' ? <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5" /> : <Circle className="w-4 h-4 text-slate-500 mt-0.5" />}
                  <div className="flex-1">
                    <p className="text-slate-200">{c.title}</p>
                    {c.detail && <p className="text-xs text-slate-500 break-all">{c.detail}</p>}
                  </div>
                </li>
              ))}
            </ul>
          )}
          {pre && (
            <button onClick={loadChecks} className="text-xs text-indigo-300 hover:text-white cursor-pointer">Run the checks again</button>
          )}
        </div>
      )}

      {step === 1 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">Your mail server</h2>
            <p className="text-sm text-slate-400">Protect the mailcow already on this server, or have CowSec install mailcow first.</p>
          </div>
          <div className="grid sm:grid-cols-2 gap-3">
            <Choice active={mcMode === 'existing'} onClick={() => pre?.mailcow.found && setMcMode('existing')} icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />} title="Protect my existing mailcow">
              <p>{pre?.mailcow.found ? <>Found <code className="font-mono">{pre.mailcow.dir}</code> · {pre.mailcow.hostname}. Mail and settings stay as they are.</> : 'No mailcow found on this server.'}</p>
            </Choice>
            <Choice active={mcMode === 'install'} onClick={() => !pre?.mailcow.found && setMcMode('install')} icon={<Server className="w-4 h-4 text-sky-400" />} title="Install mailcow, then protect it">
              <p>{pre?.mailcow.found ? 'mailcow is already installed here.' : <>Docker and mailcow-dockerized from their official sources, set up with mailcow's own installer and the answers below.</>}</p>
            </Choice>
          </div>
          {mcMode === 'install' && pre?.fresh && (
            <div className="space-y-4 cs-page">
              <p className="text-xs text-slate-500">These are the questions mailcow's <code className="font-mono">generate_config.sh</code> asks, with its defaults.</p>
              <div>
                <span className={label}>Mail server hostname (FQDN)</span>
                <input className={input} value={mcHost} onChange={(e) => { setMcHost(e.target.value.toLowerCase().trim()); setMcApex(false); }} placeholder="mail.example.com" />
                <p className="text-xs text-slate-500 mt-1">This is not your mail domain, but your mail server's own name. Its A (and AAAA) record must point at this server; mail for your domains is routed here with MX records.</p>
                {mcHost.split('.').length === 2 && (
                  <label className="mt-2 flex items-start gap-2 text-xs text-amber-200 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 cursor-pointer">
                    <input type="checkbox" checked={mcApex} onChange={(e) => setMcApex(e.target.checked)} className="mt-0.5" />
                    <span><b>{mcHost}</b> has no subdomain. mailcow warns this "is not fully tested and may cause issues" (mailcow issue #1572). Proceed anyway?</span>
                  </label>
                )}
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <span className={label}>Timezone</span>
                  <input className={input} list="cowsec-tz" value={mcTz} onChange={(e) => setMcTz(e.target.value.trim())} placeholder={pre.fresh.timezone || 'Europe/London'} />
                  <datalist id="cowsec-tz">{pre.fresh.timezones.map((t) => <option key={t} value={t} />)}</datalist>
                  <p className="text-xs text-slate-500 mt-1">Detected: {pre.fresh.timezone || 'none'}.</p>
                </div>
                <div>
                  <span className={label}>Branch</span>
                  <div className="grid grid-cols-2 gap-2">
                    {(['master', 'nightly'] as const).map((b) => (
                      <button key={b} onClick={() => setMcBranch(b)} className={`rounded-xl border px-3 py-2 text-left text-xs cursor-pointer ${mcBranch === b ? 'border-indigo-400 bg-indigo-500/10 text-white' : 'border-slate-700 text-slate-400 hover:text-white'}`}>
                        <b className="block text-sm">{b}</b>{b === 'master' ? 'stable updates · recommended' : 'testing · not production-ready'}
                      </button>
                    ))}
                  </div>
                  <p className="text-xs text-slate-500 mt-1">mailcow's "legacy" branch stopped getting updates in February 2026, so it isn't offered.</p>
                </div>
              </div>
              {pre.fresh.clamavPrompt ? (
                <Toggle on={mcClamOff} onChange={setMcClamOff} label="Disable ClamAV (virus scanning)"
                  hint={`This server has ${(pre.fresh.memKiB / 1048576).toFixed(1)} GiB of memory. mailcow recommends disabling ClamAV at 2.5 GiB or less to prevent out-of-memory problems. You can turn it back on later (SKIP_CLAMD=n in mailcow.conf).`} />
              ) : (
                <p className="text-xs text-slate-500">ClamAV virus scanning stays on ({(pre.fresh.memKiB / 1048576).toFixed(1)} GiB of memory; mailcow only asks at 2.5 GiB or less).</p>
              )}
              <p className="text-xs text-slate-500">IPv6: {pre.ipv6 ? 'mailcow will test this server\'s IPv6 connectivity and enable it if it works (updating Docker\'s daemon.json as its installer does).' : 'not available on this server, so mailcow runs IPv4-only.'}</p>
            </div>
          )}
        </div>
      )}

      {step === 2 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">Protection</h2>
            <p className="text-sm text-slate-400">CrowdSec, the mailcow log readers and the firewall bouncer are always installed. Choose the extras.</p>
          </div>
          <div>
            <span className={label}>Home countries</span>
            <div className="flex flex-wrap items-center gap-2">
              {home.map((c) => (
                <span key={c} className="inline-flex items-center gap-1.5 bg-sky-950/50 border border-sky-800 text-sky-200 rounded-lg px-2.5 py-1 text-xs font-mono font-semibold">
                  {c}
                  <button onClick={() => setHome(home.filter((x) => x !== c))} disabled={home.length === 1} className="text-sky-400 hover:text-white disabled:opacity-30 cursor-pointer">×</button>
                </span>
              ))}
              <input
                value={newCountry}
                onChange={(e) => setNewCountry(e.target.value.toUpperCase().replace(/[^A-Z]/g, '').slice(0, 2))}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && newCountry.length === 2 && !home.includes(newCountry)) {
                    setHome([...home, newCountry].sort());
                    setNewCountry('');
                  }
                }}
                placeholder="add, e.g. IE ↵"
                className="w-32 bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-white font-mono"
              />
            </div>
            <p className="text-xs text-slate-500 mt-1">Failed mail logins from these countries follow CrowdSec's normal rules; elsewhere is stricter, and repeat offenders get longer bans. You can change this later.</p>
          </div>
          {pre?.checks.some((c) => c.id === 'openresty-key' && c.status === 'warn') ? (
            <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-100 space-y-1">
              <p className="font-semibold">OpenResty edge with AppSec WAF: not available on Debian 13 yet</p>
              <p className="text-amber-100/80">Debian 13 rejects OpenResty's package signing key because it still uses SHA-1. CowSec won't weaken apt's checks to get around it. Everything else installs; you can add the edge later once OpenResty updates its key (or use Debian 12 or Ubuntu).</p>
            </div>
          ) : (
          <Toggle on={comp.edge} onChange={(v) => setComp({ ...comp, edge: v })} label="OpenResty edge with AppSec WAF" badge="recommended"
            hint="Puts a hardened reverse proxy in front of mailcow's web UI: every request is checked by CrowdSec and its WAF. mailcow's own web server moves to localhost (ports 8180/8443)." />
          )}
          <Toggle on={comp.edge && comp.adminLanOnly} disabled={!comp.edge} onChange={(v) => setComp({ ...comp, adminLanOnly: v })} label="mailcow admin pages on the local network only"
            hint="/admin and /domainadmin answer only from private addresses. Webmail, ActiveSync and autodiscover stay public." />
          <Toggle on={comp.edge && comp.cloudflareRealIP} disabled={!comp.edge} onChange={(v) => setComp({ ...comp, cloudflareRealIP: v })} label="Behind Cloudflare's proxy (orange cloud)"
            hint="Trusts CF-Connecting-IP from Cloudflare's published ranges (refreshed monthly) so bans hit visitors, not Cloudflare." />
          <Toggle on={comp.chronyPtp} onChange={(v) => setComp({ ...comp, chronyPtp: v })} label="Accurate clock (chrony)"
            hint={pre?.checks.some((c) => c.id === 'ptp' && c.status === 'ok')
              ? "Installs chrony and syncs to the hypervisor's clock (KVM PTP) as well as internet NTP. Accurate time matters for 2FA codes and log timestamps."
              : 'Installs chrony with internet NTP servers. Accurate time matters for 2FA codes and log timestamps.'} />
          <Toggle on={comp.mailcowApi} onChange={(v) => setComp({ ...comp, mailcowApi: v })} label="Manage mailcow from CowSec" badge="new"
            hint="Domains, mailboxes, aliases, DKIM, quarantine, mail queue and logs from the console, using mailcow's API (key kept root-only, allowed from this server only)." />
          <Toggle on={comp.banPolicy} onChange={(v) => setComp({ ...comp, banPolicy: v })} label="Smart ban policy" badge="recommended"
            hint="Bans password-spraying bots outside your home countries after 2 failed logins, and doubles ban length for repeat offenders (4h up to 7 days)." />
        </div>
      )}

      {step === 3 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">Certificates</h2>
            <p className="text-sm text-slate-400">How the web UI, IMAP and SMTP get their TLS certificates.</p>
          </div>
          <div className={`grid gap-3 ${pre?.existing?.certbot ? 'sm:grid-cols-3' : 'sm:grid-cols-2'}`}>
            {pre?.existing?.certbot && (
              <Choice active={certMode === 'existing'} onClick={() => setCertMode('existing')} icon={<KeyRound className="w-4 h-4 text-amber-400" />} title="Keep my current certificates">
                <p>Use <code className="font-mono">{pre.existing.certbot.name}</code> ({pre.existing.certbot.names.slice(0, 3).join(', ')}{pre.existing.certbot.names.length > 3 ? '…' : ''}). Its renewals keep running; the edge reloads after each one.</p>
              </Choice>
            )}
            <Choice active={certMode === 'dns01'} onClick={() => setCertMode('dns01')} icon={<Globe className="w-4 h-4 text-emerald-400" />} title="DNS-01 via your DNS provider">
              <p>No port 80 needed. Wildcards supported. Works with 190+ providers (lego).</p>
            </Choice>
            <Choice active={certMode === 'mailcow'} onClick={() => setCertMode('mailcow')} icon={<ShieldCheck className="w-4 h-4 text-sky-400" />} title="mailcow's own Let's Encrypt">
              <p>Keep what mailcow does today (HTTP-01). Port 80 must stay open to the internet.</p>
            </Choice>
          </div>
          {certMode === 'dns01' && (
            <div className="space-y-4">
              <div>
                <span className={label}>DNS provider</span>
                {providers === null ? (
                  <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Fetching the provider list…</div>
                ) : (
                  <div className="space-y-2">
                    <div className="relative">
                      <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input className={`${input} pl-9`} placeholder="Search, e.g. cloudflare, route53, ovh, hetzner…" value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)} />
                    </div>
                    <div className="flex flex-wrap gap-1.5 max-h-28 overflow-auto">
                      {filteredProviders.slice(0, 80).map((p) => (
                        <button key={p} onClick={() => setProvider(p)} className={`text-xs font-mono px-2 py-1 rounded-lg border cursor-pointer ${provider === p ? 'border-indigo-400 bg-indigo-500/20 text-white' : 'border-slate-800 text-slate-300 hover:border-slate-600'}`}>
                          {p}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              {provider && !help && <div className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Loading {provider}…</div>}
              {help && (
                <div className="space-y-3 border border-slate-800 rounded-2xl p-4 bg-slate-950/40">
                  <p className="text-sm text-white font-semibold">{help.name}</p>
                  <p className="text-xs text-slate-400">
                    Fill in what your provider needs (usually one API token). Stored only in <code className="font-mono">/etc/cowsec/dns.env</code>, readable by root.
                    {help.docs && <> <a href={help.docs} target="_blank" rel="noreferrer" className="text-indigo-300 hover:text-white">Provider guide</a></>}
                  </p>
                  {[...mainCreds, ...(showAliases ? aliasCreds : [])].map((c) => (
                    <div key={c.name}>
                      <span className={label}>{c.name}</span>
                      <input type={/KEY|TOKEN|SECRET|PASS/.test(c.name) ? 'password' : 'text'} autoComplete="off" className={`${input} font-mono`} placeholder={c.description}
                        value={creds[c.name] || ''} onChange={(e) => setCreds({ ...creds, [c.name]: e.target.value })} />
                    </div>
                  ))}
                  {aliasCreds.length > 0 && (
                    <button onClick={() => setShowAliases(!showAliases)} className="text-xs text-indigo-300 hover:text-white cursor-pointer">{showAliases ? 'Hide' : 'Show'} alternative variable names</button>
                  )}
                </div>
              )}
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <span className={label}>E-mail for Let's Encrypt</span>
                  <input className={input} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
                </div>
                <div>
                  <span className={label}>Domains</span>
                  <div className="flex flex-wrap gap-1.5">
                    {(pre?.mailcow.domains || []).map((d) => (
                      <label key={d} className="inline-flex items-center gap-1.5 text-xs text-slate-200 bg-slate-950/60 border border-slate-800 rounded-lg px-2 py-1 cursor-pointer">
                        <input type="checkbox" checked={domains.includes(d)} onChange={(e) => setDomains(e.target.checked ? [...domains, d] : domains.filter((x) => x !== d))} />
                        {d}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <Toggle on={perDomain} onChange={setPerDomain} label="One certificate per domain" badge="private"
                hint="Each domain only ever shows its own name. With one shared certificate, anyone can read every domain you host from it." />
              <Toggle on={wildcard} onChange={setWildcard} label="Wildcard certificates"
                hint="Covers mail., autodiscover., autoconfig. and any future name. Needs DNS-01 (which this is)." />
              <Toggle on={staging} onChange={setStaging} label="Test run (Let's Encrypt staging)"
                hint="Issues untrusted test certificates to check your provider settings without hitting rate limits. Re-run setup without it afterwards." />
            </div>
          )}
        </div>
      )}

      {step === 4 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">How you reach the console</h2>
            <p className="text-sm text-slate-400">Sign-in always needs your password and a 2FA code. You can change this later with <code className="font-mono">cowsec-setup access</code>.</p>
          </div>
          <div className="grid sm:grid-cols-2 gap-3">
            <Choice active={access === 'lan'} onClick={() => setAccess('lan')} icon={<Network className="w-4 h-4 text-emerald-400" />} title="Local network">
              <p>A hostname on your LAN, served by the edge, refused from the internet.</p>
              <p className="text-emerald-300/80">Recommended for most homes and offices.</p>
            </Choice>
            <Choice active={access === 'tunnel'} onClick={() => setAccess('tunnel')} icon={<Cloud className="w-4 h-4 text-amber-400" />} title="Internet via Cloudflare Tunnel">
              <p>No open ports: the server connects out to Cloudflare. Add a Cloudflare Access policy for an extra login in front.</p>
              <p className="text-amber-300/80">Safest way to reach it from anywhere.</p>
            </Choice>
            <Choice active={access === 'wan'} onClick={() => setAccess('wan')} icon={<Globe className="w-4 h-4 text-rose-400" />} title="Internet, directly">
              <p>Served on port 443 like webmail, protected by CrowdSec, the WAF and 2FA. Anyone can reach the sign-in page.</p>
            </Choice>
            <Choice active={access === 'local'} onClick={() => setAccess('local')} icon={<Terminal className="w-4 h-4 text-sky-400" />} title="This server only">
              <p>Listens on 127.0.0.1. Reach it through an SSH tunnel. Nothing exposed at all.</p>
            </Choice>
          </div>
          {(access === 'lan' || access === 'wan') && (
            <div>
              <span className={label}>Console hostname</span>
              <input className={input} value={hostname} onChange={(e) => setHostname(e.target.value.toLowerCase().trim())} placeholder="cowsec.example.com" />
              <p className="text-xs text-slate-500 mt-1">
                Point this name at the server{access === 'lan' ? ' in your local DNS' : ''}. {certMode === 'dns01' ? 'Covered by your DNS-01 certificates.' : certMode === 'existing' ? 'Must be covered by your current certificate.' : "Added to mailcow's certificate (ADDITIONAL_SAN), so its DNS record must resolve publicly."}
              </p>
            </div>
          )}
          {access === 'tunnel' && (
            <div className="space-y-2">
              <span className={label}>Tunnel token</span>
              <input className={`${input} font-mono`} type="password" autoComplete="off" value={tunnelToken} onChange={(e) => setTunnelToken(e.target.value.trim())} placeholder="eyJh…" />
              <p className="text-xs text-slate-500">
                In Cloudflare Zero Trust: Networks → Tunnels → Create a tunnel (cloudflared) → copy the token. Then add a public hostname pointing to <code className="font-mono">http://127.0.0.1:8090</code>, and an Access application for that hostname.
              </p>
            </div>
          )}
        </div>
      )}

      {step === 5 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">Your admin account</h2>
            <p className="text-sm text-slate-400">A local CowSec account. You'll enrol an authenticator app the first time you sign in.</p>
          </div>
          {directory && !accountDone && (
            <div className="rounded-xl border border-sky-500/30 bg-sky-500/10 p-3 text-sm text-sky-200 flex gap-2">
              <Network className="w-4 h-4 mt-0.5 shrink-0" />
              <span>Sign-in through your directory (LDAP) is already set up, so this step is optional. A local account is still handy as a break-glass login if the directory is ever unreachable.</span>
            </div>
          )}
          {accountDone ? (
            <p className="text-sm text-emerald-300 flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> Account created. You can add more later with <code className="font-mono">sudo cowsec auth local-admin set &lt;name&gt;</code>.</p>
          ) : (
            <div className="space-y-3">
              <div>
                <span className={label}>Username</span>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input className={`${input} pl-9`} value={user} onChange={(e) => setUser(e.target.value.trim())} autoComplete="username" />
                </div>
              </div>
              <div className="grid sm:grid-cols-2 gap-3">
                <div>
                  <span className={label}>Password (12+ characters)</span>
                  <input className={input} type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
                </div>
                <div>
                  <span className={label}>Repeat password</span>
                  <input className={input} type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} autoComplete="new-password" />
                </div>
              </div>
              <button onClick={createAccount} disabled={busy || user.length < 2 || pw.length < 12} className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 cursor-pointer">
                {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <User className="w-4 h-4" />} Create account
              </button>
            </div>
          )}
        </div>
      )}

      {step === 6 && (
        <div className="space-y-4">
          <div>
            <h2 className="text-lg font-bold text-white">{job ? (job.state === 'ok' ? 'All done' : job.state === 'failed' ? 'Installation stopped' : 'Raising the barn…') : 'Ready to install'}</h2>
            {!job && <p className="text-sm text-slate-400">Every changed file is backed up first (<code className="font-mono">*.cowsec-bak-*</code>). If the edge can't start, mailcow's web settings are put back automatically.</p>}
          </div>
          {!job && mcMode === 'existing' && (
            <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4 space-y-3">
              <p className="flex items-center gap-2 text-sm font-semibold text-amber-100"><ShieldCheck className="w-4 h-4 text-amber-300" /> This server already handles mail</p>
              <ul className="text-xs text-slate-300 space-y-1.5">
                <li>• Mail keeps flowing during setup. The web interface is briefly unavailable while the edge takes over ports 80 and 443.</li>
                <li>• Before changing anything, CowSec saves mailcow's settings and certificates, CrowdSec's configuration and the firewall rules to <code className="font-mono">/var/backups/cowsec/pre-install-…tar.gz</code>.</li>
                <li>• To put mailcow back exactly as it was at any time: <code className="font-mono text-amber-200">sudo cowsec-setup restore-mailcow</code></li>
              </ul>
              <label className="flex items-start gap-2 text-sm text-white cursor-pointer">
                <input type="checkbox" className="mt-1" checked={backupOk} onChange={(e) => setBackupOk(e.target.checked)} />
                <span>I have a recent backup of this server.<span className="block text-xs text-slate-400">A VM or cloud snapshot, your usual backup, or mailcow's own: <code className="font-mono">helper-scripts/backup_and_restore.sh backup all</code>. CowSec's snapshot covers its own changes, not your mail.</span></span>
              </label>
            </div>
          )}
          {!job && (
            <ul className="text-sm text-slate-300 space-y-1.5 border border-slate-800 rounded-2xl p-4 bg-slate-950/40">
              <li>• Mail server: <b>{mcMode === 'install' ? `install mailcow (${mcBranch}) as ${mcHost} · ${mcTz}${mcClamOff ? ' · ClamAV off' : ''}` : `protect ${pre?.mailcow.hostname || 'the existing mailcow'}`}</b></li>
              <li>• Home countries: <b className="font-mono">{home.join(', ')}</b></li>
              <li>• OpenResty edge + WAF: <b>{comp.edge ? 'yes' : 'no'}</b>{comp.edge && comp.adminLanOnly ? ' · admin pages LAN-only' : ''}{comp.edge && comp.cloudflareRealIP ? ' · Cloudflare real IP' : ''}</li>
              <li>• Certificates: <b>{certMode === 'dns01' ? `DNS-01 via ${provider} · ${domains.length} domain(s) · ${perDomain ? 'per domain' : 'shared'}${wildcard ? ' · wildcard' : ''}${staging ? ' · STAGING' : ''}` : certMode === 'existing' ? `your current certificates (${pre?.existing?.certbot?.name})` : "mailcow's own"}</b></li>
              <li>• Console: <b>{access === 'lan' ? `LAN at ${hostname}` : access === 'wan' ? `internet at ${hostname}` : access === 'tunnel' ? 'Cloudflare Tunnel' : 'this server only'}</b></li>
              <li>• Smart ban policy: <b>{comp.banPolicy ? 'yes' : 'no'}</b> · Accurate clock: <b>{comp.chronyPtp ? 'yes' : 'no'}</b> · mailcow management: <b>{comp.mailcowApi ? 'yes' : 'no'}</b></li>
            </ul>
          )}
          {job && (
            <>
              {(() => {
                const st = job.steps || [];
                const done = st.filter((x) => x.state === 'ok').length + (st.some((x) => x.state === 'running') ? 0.5 : 0);
                const pct = st.length ? Math.round((done / st.length) * 100) : 3;
                return (
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                      <div className={`h-full transition-all duration-700 ${job.state === 'failed' ? 'bg-rose-500' : 'bg-gradient-to-r from-indigo-500 via-sky-400 to-emerald-400'} ${job.state === 'running' ? 'cs-shimmer' : ''}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-sm font-mono font-bold text-white w-12 text-right">{pct}%</span>
                  </div>
                );
              })()}
              <ul className="space-y-1.5 cs-stagger">
                {(job.steps || []).map((s) => (
                  <li key={s.id} className={`flex items-center gap-2.5 text-sm rounded-lg px-2 py-1 transition-colors duration-500 ${s.state === 'running' ? 'bg-sky-500/10' : ''}`}>
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center ${s.state === 'running' ? 'cs-ring' : ''}`}>
                      {s.state === 'ok' ? <CheckCircle2 key="ok" className="w-4 h-4 text-emerald-400 cs-pop" /> : s.state === 'failed' ? <XCircle className="w-4 h-4 text-rose-400 cs-pop" /> : s.state === 'running' ? <Loader2 className="w-4 h-4 animate-spin text-sky-300" /> : <Circle className="w-4 h-4 text-slate-600" />}
                    </span>
                    <span className={s.state === 'pending' ? 'text-slate-500' : s.state === 'running' ? 'text-white font-semibold' : 'text-slate-200'}>{s.title}</span>
                  </li>
                ))}
                {!job.steps?.length && <li className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Starting…</li>}
              </ul>
              <pre ref={logRef} className="text-[11px] leading-relaxed text-slate-300 bg-slate-950/80 border border-slate-800 rounded-xl p-3 h-64 overflow-auto whitespace-pre-wrap">{job.log || ''}</pre>
              {job.error && <ErrorLine text={job.error} />}
              {job.state === 'ok' && mcAdmin && (
                <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 p-4 space-y-2 cs-pop">
                  <p className="text-sm font-semibold text-amber-100 flex items-center gap-2"><KeyRound className="w-4 h-4" /> Your mailcow admin login: save it now, it's only shown here</p>
                  <div className="grid sm:grid-cols-3 gap-2 text-sm">
                    <div><span className={label}>Admin page</span><code className="font-mono text-xs text-white break-all">{mcAdmin.url}</code></div>
                    <div><span className={label}>Username</span><code className="font-mono text-white">{mcAdmin.username}</code></div>
                    <div><span className={label}>Password</span><code className="font-mono text-white select-all">{mcAdmin.password}</code></div>
                  </div>
                  <p className="text-xs text-amber-200/80">CowSec replaced mailcow's well-known default password with this random one. Change it and turn on 2FA in mailcow after you sign in.</p>
                  <p className="text-xs text-amber-200/80">DNS: point <b>{mcHost}</b> (A/AAAA) at this server, then add each mail domain in The Farm, which shows its MX, SPF and DKIM records.</p>
                </div>
              )}
            </>
          )}
        </div>
      )}

      </div>

      {step !== 6 || !job || job.state !== 'running' ? <div className="mt-5"><ErrorLine text={error} /></div> : null}

      <div className="mt-6 flex items-center justify-between">
        <button
          onClick={() => { setError(''); setStep(Math.max(0, step - 1)); }}
          disabled={step === 0 || (job?.state === 'running')}
          className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-white disabled:opacity-30 cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" /> Back
        </button>
        {step < 6 && (
          <button
            onClick={() => { setError(''); setStep(step + 1); }}
            disabled={!!err}
            title={err}
            className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600 disabled:opacity-40 cursor-pointer"
          >
            Next <ArrowRight className="w-4 h-4" />
          </button>
        )}
        {step === 6 && !job && (
          <button onClick={install} disabled={busy || (mcMode === 'existing' && !backupOk)} className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 cursor-pointer">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <Server className="w-4 h-4" />} Install
          </button>
        )}
        {step === 6 && job?.state === 'failed' && (
          <button onClick={() => { setJob(null); }} className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-slate-700 hover:bg-slate-600 cursor-pointer">
            Review settings and retry
          </button>
        )}
        {step === 6 && job?.state === 'ok' && (
          <button onClick={finish} disabled={busy} className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-emerald-600 hover:bg-emerald-500 cursor-pointer">
            {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <PartyPopper className="w-4 h-4" />} Finish and close setup
          </button>
        )}
      </div>
      {err && step < 6 && <p className="text-[11px] text-slate-500 text-right mt-2">{err}</p>}
    </Shell>
  );
}
