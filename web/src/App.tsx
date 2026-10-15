import { useEffect, useState, type ReactNode } from 'react';
import {
  AlertTriangle, Ban, Check, CheckCircle2, ChevronDown, Download, LogOut, Network, Package, Palette, Scale, Server,
  Settings as SettingsIcon, Shield, ShieldAlert, Sparkles, Home, Globe, Inbox, AtSign, KeyRound, ShieldQuestion, Send, ScrollText,
  Dog, Gauge, Lock, Route, Users,
} from 'lucide-react';
import CowSecLogo from './CowSecLogo';
import CrowdSecConsole, { type CsSubTabType } from './CrowdSecConsole';
import ErrorBoundary from './ErrorBoundary';
import { AliasesPanel, DkimPanel, DomainsPanel, FarmOverview, LogsPanel, MailboxesPanel, QuarantinePanel, QueuePanel } from './MailcowPanels';
import { CattleRoutesPanel, FarmhandsPanel, GrazingLimitsPanel, GuardDogPanel, LockedLanesPanel } from './FarmAdminPanels';
import { THEME_PALETTES, type ThemePalette } from './themes';
import type { Identity } from './session';

type MailTab = 'farm' | 'domains' | 'mailboxes' | 'aliases' | 'dkim' | 'quarantine' | 'queue' | 'maillogs' | 'farmhands' | 'ratelimits' | 'tls' | 'routes' | 'netfilter';
type Tab = CsSubTabType | MailTab;

const MAIL_PAGES: Record<MailTab, () => ReactNode> = {
  farm: () => <FarmOverview />, domains: () => <DomainsPanel />, mailboxes: () => <MailboxesPanel />, aliases: () => <AliasesPanel />,
  dkim: () => <DkimPanel />, quarantine: () => <QuarantinePanel />, queue: () => <QueuePanel />, maillogs: () => <LogsPanel />,
  farmhands: () => <FarmhandsPanel />, ratelimits: () => <GrazingLimitsPanel />, tls: () => <LockedLanesPanel />, routes: () => <CattleRoutesPanel />,
  netfilter: () => <GuardDogPanel />,
};

const NAV: [string, string, [Tab, string, ReactNode][]][] = [
  ['The Barn', 'Host', [
    ['host', 'Barn Status', <Server key="i" className="w-4 h-4 shrink-0 text-sky-400" />],
    ['updates', 'Fresh Hay (Updates)', <Download key="i" className="w-4 h-4 shrink-0 text-lime-400" />],
  ]],
  ['Fence & Gate', 'Protection', [
    ['decisions', 'Banned from the Herd', <Ban key="i" className="w-4 h-4 shrink-0 text-rose-400" />],
    ['policy', 'Herd Rules (Ban policy)', <Scale key="i" className="w-4 h-4 shrink-0 text-amber-300" />],
    ['appsec', 'Electric Fence (WAF)', <ShieldAlert key="i" className="w-4 h-4 shrink-0 text-indigo-400" />],
    ['whitelists', 'Trusted Herd', <CheckCircle2 key="i" className="w-4 h-4 shrink-0 text-emerald-400" />],
    ['netfilter', 'Guard Dog (netfilter)', <Dog key="i" className="w-4 h-4 shrink-0 text-orange-300" />],
  ]],
  ['The Farm', 'Mail', [
    ['farm', 'Farmhouse (Overview)', <Home key="i" className="w-4 h-4 shrink-0 text-sky-300" />],
    ['domains', 'Paddocks (Domains)', <Globe key="i" className="w-4 h-4 shrink-0 text-sky-400" />],
    ['mailboxes', 'Stalls (Mailboxes)', <Inbox key="i" className="w-4 h-4 shrink-0 text-indigo-300" />],
    ['aliases', 'Ear Tags (Aliases)', <AtSign key="i" className="w-4 h-4 shrink-0 text-violet-300" />],
    ['dkim', 'Brand Irons (DKIM)', <KeyRound key="i" className="w-4 h-4 shrink-0 text-amber-300" />],
    ['farmhands', 'Farmhands (Domain admins)', <Users key="i" className="w-4 h-4 shrink-0 text-indigo-300" />],
    ['ratelimits', 'Grazing Limits (Rate limits)', <Gauge key="i" className="w-4 h-4 shrink-0 text-amber-300" />],
    ['tls', 'Locked Lanes (TLS policy)', <Lock key="i" className="w-4 h-4 shrink-0 text-emerald-300" />],
    ['routes', 'Cattle Routes (Relays)', <Route key="i" className="w-4 h-4 shrink-0 text-sky-300" />],
    ['quarantine', 'Quarantine Pen', <ShieldQuestion key="i" className="w-4 h-4 shrink-0 text-amber-400" />],
    ['queue', 'Milk Queue (Mail queue)', <Send key="i" className="w-4 h-4 shrink-0 text-cyan-300" />],
    ['maillogs', 'Farm Log (Logs)', <ScrollText key="i" className="w-4 h-4 shrink-0 text-slate-300" />],
  ]],
  ['Herd Watch', 'Detection', [
    ['alerts', 'Moo Alerts', <AlertTriangle key="i" className="w-4 h-4 shrink-0 text-orange-400" />],
    ['hub', 'Feed Store (Hub)', <Package key="i" className="w-4 h-4 shrink-0 text-amber-400" />],
    ['topology', 'Bouncers & Herd Dogs', <Network key="i" className="w-4 h-4 shrink-0 text-emerald-400" />],
  ]],
];
const VALID = NAV.flatMap(([, , items]) => items.map(([id]) => id));

function initialTab(): Tab {
  const h = window.location.hash.replace(/^#\/?/, '').split('/')[0] as Tab;
  if (VALID.includes(h)) return h;
  try {
    const s = localStorage.getItem('cowsec_tab') as Tab;
    if (VALID.includes(s)) return s;
  } catch {
    /* storage unavailable */
  }
  return 'host';
}

export default function App({ session, onLogout, onOpenSettings }: { session: Identity; onLogout: () => void; onOpenSettings: () => void }) {
  const [tab, setTab] = useState<Tab>(initialTab);
  const [theme, setTheme] = useState<ThemePalette>(() => {
    try {
      const t = localStorage.getItem('cowsec_theme') as ThemePalette;
      if (THEME_PALETTES.some((p) => p.id === t)) return t;
    } catch {
      /* storage unavailable */
    }
    return 'indigo';
  });
  const [themeOpen, setThemeOpen] = useState(false);
  const current = THEME_PALETTES.find((p) => p.id === theme) ?? THEME_PALETTES[0];

  useEffect(() => {
    document.title = 'CowSec · Moo-ving bad actors along';
  }, []);
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    document.body.setAttribute('data-theme', theme);
    try {
      localStorage.setItem('cowsec_theme', theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  useEffect(() => {
    const onHash = () => setTab(initialTab());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const navigate = (t: Tab) => {
    setTab(t);
    if (window.location.hash !== `#/${t}`) window.history.pushState(null, '', `#/${t}`);
    try {
      localStorage.setItem('cowsec_tab', t);
    } catch {
      /* storage unavailable */
    }
    window.scrollTo({ top: 0 });
  };

  return (
    <div className="cowsec-shell min-h-screen text-slate-100 flex flex-col font-sans transition-colors duration-300">
      <header
        className="border-b sticky top-0 z-30 px-6 py-3 flex items-center justify-between backdrop-blur-xl shadow-[0_8px_32px_-8px_rgba(0,0,0,0.65)]"
        style={{ backgroundColor: 'var(--bg-sidebar)', borderColor: 'var(--border-app)' }}
      >
        <div onClick={() => navigate('host')} className="flex items-center space-x-3.5 cursor-pointer group select-none" title="CowSec">
          <div className="relative w-11 h-11 rounded-2xl flex items-center justify-center group-hover:scale-105 transition-transform duration-300 shadow-[0_0_28px_-4px_var(--accent-glow)]">
            <CowSecLogo />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="font-extrabold text-xl tracking-tight bg-gradient-to-r from-white via-sky-100 to-indigo-300 bg-clip-text text-transparent">CowSec</h1>
              <span className="text-[10px] font-mono font-bold uppercase tracking-widest px-2 py-0.5 rounded-full bg-indigo-500/15 border border-indigo-400/30 text-indigo-300">
                Herd Protection
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium">Guarding the mailcow pasture · Electric fence WAF · Firewall gate</p>
          </div>
        </div>

        <div className="hidden md:flex items-center space-x-2.5 text-xs">
          <div className="relative">
            <button
              onClick={() => setThemeOpen(!themeOpen)}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-xl border cursor-pointer text-slate-200"
              style={{ backgroundColor: 'var(--bg-card)', borderColor: themeOpen ? 'var(--accent-solid)' : 'var(--border-app)' }}
              title="Colour palette"
            >
              <Palette className="w-3.5 h-3.5" style={{ color: 'var(--accent-light)' }} />
              <span className="font-semibold">{current.name}</span>
              <ChevronDown className={`w-3 h-3 text-slate-400 transition-transform ${themeOpen ? 'rotate-180' : ''}`} />
            </button>
            {themeOpen && (
              <div className="absolute right-0 mt-2 w-72 rounded-2xl p-2.5 shadow-2xl z-50 border backdrop-blur-2xl" style={{ backgroundColor: 'rgba(10, 16, 32, 0.94)', borderColor: 'var(--border-app-hover)' }}>
                <div className="px-2.5 py-1.5 border-b mb-1.5 flex items-center space-x-1.5" style={{ borderColor: 'var(--border-app)' }}>
                  <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-[11px] font-bold text-slate-200 tracking-wider uppercase">Palettes</span>
                </div>
                {THEME_PALETTES.map((p) => (
                  <button
                    key={p.id}
                    onClick={() => {
                      setTheme(p.id);
                      setThemeOpen(false);
                    }}
                    className={`w-full flex items-center justify-between p-2 rounded-xl text-left cursor-pointer border ${theme === p.id ? 'bg-white/10' : 'hover:bg-white/5 border-transparent'}`}
                    style={theme === p.id ? { borderColor: 'var(--accent-solid)' } : {}}
                  >
                    <div className="flex items-center space-x-2.5">
                      <div className="flex -space-x-1.5 p-1 rounded-lg border border-black/40" style={{ backgroundColor: p.previewColors[0] }}>
                        {p.previewColors.map((c, i) => (
                          <span key={i} className="w-2.5 h-2.5 rounded-full border border-black/50" style={{ backgroundColor: c }} />
                        ))}
                      </div>
                      <div>
                        <span className="text-xs font-semibold text-slate-200">{p.name}</span>
                        <p className="text-[10px] text-slate-400 truncate max-w-[155px]">{p.tagline}</p>
                      </div>
                    </div>
                    {theme === p.id && <Check className="w-3.5 h-3.5 text-white" />}
                  </button>
                ))}
              </div>
            )}
          </div>
          <div className="flex items-center space-x-2 bg-emerald-950/50 border border-emerald-500/40 text-emerald-300 px-3 py-1.5 rounded-xl font-semibold">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span>AppSec WAF + CrowdSec</span>
          </div>
          <div className="flex items-center border rounded-xl overflow-hidden" style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-app)' }}>
            <button onClick={onOpenSettings} className="flex items-center space-x-2 pl-1.5 pr-2.5 py-1 hover:bg-white/5 cursor-pointer" title={`Signed in as ${session.user}. Open settings.`}>
              <span className="w-6 h-6 rounded-lg flex items-center justify-center text-[10px] font-bold text-white bg-gradient-to-br from-indigo-500 to-sky-500">
                {(session.displayName || session.user).slice(0, 2).toUpperCase()}
              </span>
              <span className="hidden 2xl:inline text-slate-200 font-semibold max-w-[140px] truncate">{session.displayName || session.user}</span>
              <SettingsIcon className="w-3.5 h-3.5 text-slate-400" />
            </button>
            <button onClick={onLogout} className="px-2 py-1.5 border-l text-slate-400 hover:text-rose-300 hover:bg-rose-500/10 cursor-pointer" style={{ borderColor: 'var(--border-app)' }} title="Sign out">
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex-1 flex flex-col md:flex-row">
        <aside className="w-full md:w-72 shrink-0 border-b md:border-b-0 md:border-r p-4 space-y-5 backdrop-blur-xl" style={{ backgroundColor: 'var(--bg-sidebar)', borderColor: 'var(--border-app)' }}>
          {NAV.map(([section, meaning, items]) => (
            <div key={section} className="space-y-1">
              <p className="px-3 text-[10px] font-mono font-bold uppercase tracking-widest text-slate-500 mb-1.5">
                {section} <span className="text-slate-600">· {meaning}</span>
              </p>
              {items.map(([id, label, icon]) => (
                <button
                  key={id}
                  onClick={() => navigate(id)}
                  className={`w-full flex items-center space-x-3 px-3.5 py-2.5 rounded-xl text-sm font-semibold transition-all cursor-pointer border border-transparent ${
                    tab === id ? 'cowsec-nav-active text-white' : 'text-slate-400 hover:text-slate-100 hover:bg-white/[0.04]'
                  }`}
                >
                  {icon}
                  <span className="whitespace-nowrap">{label}</span>
                </button>
              ))}
            </div>
          ))}
        </aside>
        <main className="flex-1 p-6 max-w-7xl mx-auto w-full">
          <ErrorBoundary resetKey={tab}>
            <div key={tab} className="cs-page">
            {tab in MAIL_PAGES ? MAIL_PAGES[tab as MailTab]() : <CrowdSecConsole csSubTab={tab as CsSubTabType} />}
            </div>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
