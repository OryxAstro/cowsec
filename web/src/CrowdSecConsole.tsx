// CrowdSec pages: decisions, AppSec WAF, hub, alerts, bouncers & machines, whitelists.
import Flag from './Flag';
import MailWafPanel from './MailWafPanel';
import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Server, Shield, Layers, CheckCircle2, Activity, Radio, RefreshCw, Download, X, Unlock, Globe, ShieldAlert, ExternalLink, Search, Trash2, RotateCcw, Boxes, AlertTriangle, ShieldCheck, Ban, Clock, Copy, Check, Package, Library,
} from 'lucide-react';
import HostPanel from './HostPanel';
import PolicyPanel from './PolicyPanel';
import UpdatesPanel from './UpdatesPanel';
import WhitelistsPanel from './WhitelistsPanel';

export type CsSubTabType = 'host' | 'updates' | 'policy' | 'decisions' | 'appsec' | 'hub' | 'alerts' | 'topology' | 'whitelists';

interface CrowdSecOverview {
  activeBansTotal: number;
  localBans: number;
  capiBans: number;
  totalAlerts: number;
  bouncersCount: number;
  machinesCount: number;
  appsecRules: number;
  appsecBlock?: number;
  appsecWatch?: number;
  appsecConfig?: string | null;
  scenariosCount: number;
  parsersCount: number;
  collections: number;
  appsecStatus: string;
}

interface CrowdSecDecision {
  id: number;
  value: string;
  scope: string;
  type: string;
  duration: string;
  scenario: string;
  origin: string;
  simulated: boolean;
  alertId?: number;
  createdAt?: string;
  geo?: {
    query: string;
    status: string;
    countryCode: string;
    country: string;
    city: string;
    as: string;
    org: string;
    isLan: boolean;
  };
}

interface CrowdSecAlert {
  id: number;
  uuid: string;
  scenario: string;
  message: string;
  ip: string;
  scope: string;
  createdAt: string;
  eventsCount: number;
  simulated: boolean;
  decisions?: CrowdSecDecision[];
  geo?: {
    query: string;
    status: string;
    countryCode: string;
    country: string;
    city: string;
    as: string;
    org: string;
    isLan: boolean;
  };
}

interface CrowdSecBouncer {
  name: string;
  ip_address: string;
  valid: boolean;
  last_pull: string | null;
  updated_at?: string | null;
  type: string;
  version: string;
  auth_type: string;
  created_at: string;
  auto_created: boolean;
}

interface CrowdSecMachine {
  machineId: string;
  ipAddress: string;
  version: string;
  isValidated: boolean;
  last_heartbeat: string | null;
  last_push?: string | null;
  updated_at?: string | null;
  os: string;
  auth_type: string;
  created_at: string;
}

function formatRelativeTime(dateString?: string | null): string {
  if (!dateString) return 'never';
  const date = new Date(dateString);
  const now = new Date();
  const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (isNaN(diffSec) || diffSec < 0) return 'just now';
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHours = Math.floor(diffMin / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

interface CrowdSecRule {
  name: string;
  local_version: string;
  description: string;
  status: string;
}


// Emoji flag from an ISO code (regional indicator symbols): no external image requests.

function CountryFlagBadge({ geo }: { geo?: CrowdSecDecision['geo'] }) {
  if (!geo || !geo.countryCode || geo.countryCode === 'UN' || geo.countryCode === 'UNKNOWN') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-400 border border-slate-700/60 font-mono">
        <Globe className="w-3.5 h-3.5 text-slate-500" />
        <span>Unknown</span>
      </span>
    );
  }
  if (geo.isLan || geo.countryCode === 'LAN') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs bg-emerald-950/70 text-emerald-300 border border-emerald-700/60 font-mono font-medium" title="Local network">
        <span className="text-sm">🏠</span>
        <span>Local network</span>
      </span>
    );
  }
  const code = geo.countryCode.toUpperCase();
  return (
    <div className="inline-flex flex-col gap-0.5">
      <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs bg-slate-800/90 text-slate-200 border border-slate-700/80" title={`${geo.country || code} (${code})`}>
        <Flag code={code} className="w-4 h-4" />
        <span className="font-semibold text-slate-100">{code}</span>
        {geo.country && <span className="text-slate-400 font-sans text-xs truncate max-w-[110px]">{geo.country}</span>}
      </div>
      {(geo.city || geo.as || geo.org) && (
        <span className="text-[10px] text-slate-500 truncate max-w-[180px] font-mono pl-1">
          {geo.city ? `${geo.city} • ` : ''}{geo.as || geo.org}
        </span>
      )}
    </div>
  );
}

export default function CrowdSecConsole({ csSubTab }: { csSubTab: CsSubTabType }) {
  const activeTab = 'crowdsec';
  const [csOverview, setCsOverview] = useState<CrowdSecOverview | null>(null);
  const [csDecisions, setCsDecisions] = useState<CrowdSecDecision[]>([]);
  const [csTotalDecisions, setCsTotalDecisions] = useState(0);
  const [csOriginFilter] = useState<'local'>('local');
  const [csSearch, setCsSearch] = useState('');
  const [csPage, setCsPage] = useState(1);
  const csSearchTimeoutRef = useRef<any>(null);
  const [hubItems, setHubItems] = useState<any[]>([]);
  const [hubCategory, setHubCategory] = useState<'all' | 'collections' | 'scenarios' | 'parsers' | 'postoverflows' | 'appsec-configs' | 'appsec-rules'>('collections');
  const [hubStatusFilter, setHubStatusFilter] = useState<'all' | 'enabled' | 'available'>('all');
  const [hubSearch, setHubSearch] = useState('');
  const [hubLoading, setHubLoading] = useState(false);
  const [hubActionLoading, setHubActionLoading] = useState<string | null>(null);
  const [hubCounts, setHubCounts] = useState<Record<string, number>>({});
  const [hubTotal, setHubTotal] = useState(0);
  const [hubEnabledCount, setHubEnabledCount] = useState(0);
  const [csAlerts, setCsAlerts] = useState<CrowdSecAlert[]>([]);
  const [csBouncers, setCsBouncers] = useState<CrowdSecBouncer[]>([]);
  const [csMachines, setCsMachines] = useState<CrowdSecMachine[]>([]);
  const [csRules, setCsRules] = useState<CrowdSecRule[]>([]);
  const [csLoading, setCsLoading] = useState(false);
  const [isManualBlockModalOpen, setIsManualBlockModalOpen] = useState(false);
  const [manualBlockForm, setManualBlockForm] = useState({ ip: '', duration: '4h', reason: 'manual-admin-ban', type: 'ban' });
  const [unblockTarget, setUnblockTarget] = useState<CrowdSecDecision | null>(null);
  const [isUpdatingHub, setIsUpdatingHub] = useState(false);
  const [isPruningMachines, setIsPruningMachines] = useState(false);
  const [deletingMachine, setDeletingMachine] = useState<string | null>(null);
  const [csActionToast, setCsActionToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null);
  const [copiedIP, setCopiedIP] = useState<string | null>(null);

  const handlePruneMachines = async () => {
    setIsPruningMachines(true);
    try {
      const res = await fetch('/api/crowdsec/machines/prune', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setCsActionToast({ message: data.message || 'Stale machines pruned successfully!', type: 'success' });
        fetchCrowdSecTopology();
      } else {
        setCsActionToast({ message: data.error || 'Failed to prune machines', type: 'error' });
      }
    } catch (e: any) {
      setCsActionToast({ message: e.message, type: 'error' });
    } finally {
      setIsPruningMachines(false);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const handleDeleteMachine = async (machineName: string) => {
    setDeletingMachine(machineName);
    try {
      const res = await fetch(`/api/crowdsec/machines?name=${encodeURIComponent(machineName)}`, { method: 'DELETE' });
      const data = await res.json();
      if (res.ok) {
        setCsActionToast({ message: data.message || `Machine ${machineName} removed`, type: 'success' });
        fetchCrowdSecTopology();
      } else {
        setCsActionToast({ message: data.error || `Failed to remove machine`, type: 'error' });
      }
    } catch (e: any) {
      setCsActionToast({ message: e.message, type: 'error' });
    } finally {
      setDeletingMachine(null);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const fetchCrowdSecOverview = async () => {
    try {
      const res = await fetch('/api/crowdsec/overview');
      if (res.ok) setCsOverview(await res.json());
    } catch {
      // ignore
    }
  };

  const fetchCrowdSecDecisions = async (
    origin = csOriginFilter,
    search = csSearch,
    silent = false,
    page = csPage
  ) => {
    if (!silent) setCsLoading(true);
    try {
      const q = new URLSearchParams();
      q.set('origin', origin || 'all');
      if (search && search.trim()) q.set('search', search.trim());
      q.set('limit', '50');
      q.set('offset', String((page - 1) * 50));
      const res = await fetch(`/api/crowdsec/decisions?${q.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setCsDecisions(data.decisions || []);
        setCsTotalDecisions(data.total || 0);
      }
    } catch {
      // ignore
    } finally {
      if (!silent) setCsLoading(false);
    }
  };

  const fetchCrowdSecAlerts = async () => {
    try {
      const res = await fetch('/api/crowdsec/alerts?limit=50');
      if (res.ok) {
        const a = await res.json();
        setCsAlerts(Array.isArray(a) ? a : []);
      }
    } catch {
      // ignore
    }
  };

  const fetchCrowdSecAppSec = async () => {
    try {
      const res = await fetch('/api/crowdsec/appsec');
      if (res.ok) {
        const data = await res.json();
        setCsRules(data.rules || []);
      }
    } catch {
      // ignore
    }
  };

  const fetchCrowdSecTopology = async () => {
    try {
      const [bRes, mRes] = await Promise.all([
        fetch('/api/crowdsec/bouncers'),
        fetch('/api/crowdsec/machines')
      ]);
      if (bRes.ok) {
        const b = await bRes.json();
        setCsBouncers(Array.isArray(b) ? b : []);
      }
      if (mRes.ok) {
        const m = await mRes.json();
        setCsMachines(Array.isArray(m) ? m : []);
      }
    } catch {
      // ignore
    }
  };


  const handleUpdateHub = async () => {
    setIsUpdatingHub(true);
    try {
      const res = await fetch('/api/crowdsec/hub/update', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        setCsActionToast({ message: data.message || 'Threat definitions successfully updated!', type: 'success' });
        fetchCrowdSecOverview();
        if (csSubTab === 'appsec') fetchCrowdSecAppSec();
      } else {
        setCsActionToast({ message: data.error || 'Failed to update hub', type: 'error' });
      }
    } catch (e: any) {
      setCsActionToast({ message: e.message, type: 'error' });
    } finally {
      setIsUpdatingHub(false);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const handleManualBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualBlockForm.ip) return;
    setCsLoading(true);
    try {
      const res = await fetch('/api/crowdsec/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(manualBlockForm)
      });
      const data = await res.json();
      if (res.ok) {
        setIsManualBlockModalOpen(false);
        setManualBlockForm({ ip: '', duration: '4h', reason: 'manual-admin-ban', type: 'ban' });
        setCsActionToast({ message: `Decision enforced: ${manualBlockForm.ip} blocked (${manualBlockForm.duration})`, type: 'success' });
        fetchCrowdSecOverview();
        fetchCrowdSecDecisions();
      } else {
        setCsActionToast({ message: data.error || 'Failed to add decision', type: 'error' });
      }
    } catch (e: any) {
      setCsActionToast({ message: e.message, type: 'error' });
    } finally {
      setCsLoading(false);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const handleUnblock = async (decision: CrowdSecDecision) => {
    setCsLoading(true);
    try {
      const res = await fetch(`/api/crowdsec/decisions?ip=${encodeURIComponent(decision.value)}&id=${decision.id}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (res.ok) {
        setUnblockTarget(null);
        setCsActionToast({ message: `Successfully unblocked ${decision.value}`, type: 'success' });
        fetchCrowdSecOverview();
        fetchCrowdSecDecisions();
      } else {
        setCsActionToast({ message: data.error || 'Failed to unblock decision', type: 'error' });
      }
    } catch (e: any) {
      setCsActionToast({ message: e.message, type: 'error' });
    } finally {
      setCsLoading(false);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const handleCopyIP = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIP(ip);
    setTimeout(() => setCopiedIP(null), 2000);
  };

  const fetchCrowdSecHub = async (cat = hubCategory, search = hubSearch, status = hubStatusFilter) => {
    setHubLoading(true);
    try {
      const q = new URLSearchParams();
      if (cat !== 'all') q.set('category', cat);
      else q.set('category', 'all');
      q.set('all', 'true');
      if (search) q.set('search', search);
      if (status === 'enabled') q.set('status', 'enabled');
      if (status === 'available') q.set('status', 'disabled');

      const res = await fetch(`/api/crowdsec/hub?${q.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setHubItems(data.items || []);
        setHubCounts(data.counts || {});
        setHubTotal(data.total || 0);
        setHubEnabledCount(data.enabledCount || 0);
      }
    } catch (e: any) {
      console.error('Failed to fetch hub items', e);
    } finally {
      setHubLoading(false);
    }
  };

  const handleInstallHubItem = async (item: any) => {
    setHubActionLoading(item.name);
    try {
      const res = await fetch('/api/crowdsec/hub/install', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: item.type, name: item.name })
      });
      if (res.ok) {
        setCsActionToast({ type: 'success', message: `Installed and enabled ${item.name}! CrowdSec reloaded.` });
        fetchCrowdSecHub();
        fetchCrowdSecOverview();
      } else {
        const err = await res.text();
        setCsActionToast({ type: 'error', message: `Failed to install ${item.name}: ${err}` });
      }
    } catch (e: any) {
      setCsActionToast({ type: 'error', message: `Error: ${e.message}` });
    } finally {
      setHubActionLoading(null);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const handleRemoveHubItem = async (item: any) => {
    setHubActionLoading(item.name);
    try {
      const res = await fetch('/api/crowdsec/hub/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: item.type, name: item.name })
      });
      if (res.ok) {
        setCsActionToast({ type: 'success', message: `Removed ${item.name}! CrowdSec reloaded.` });
        fetchCrowdSecHub();
        fetchCrowdSecOverview();
      } else {
        const err = await res.text();
        setCsActionToast({ type: 'error', message: `Failed to remove ${item.name}: ${err}` });
      }
    } catch (e: any) {
      setCsActionToast({ type: 'error', message: `Error: ${e.message}` });
    } finally {
      setHubActionLoading(null);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  const handleUpgradeHubItem = async (item: any) => {
    setHubActionLoading(item.name);
    try {
      const res = await fetch('/api/crowdsec/hub/upgrade', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: item.type, name: item.name })
      });
      if (res.ok) {
        setCsActionToast({ type: 'success', message: `Upgraded ${item.name}! CrowdSec reloaded.` });
        fetchCrowdSecHub();
        fetchCrowdSecOverview();
      } else {
        const err = await res.text();
        setCsActionToast({ type: 'error', message: `Failed to upgrade ${item.name}: ${err}` });
      }
    } catch (e: any) {
      setCsActionToast({ type: 'error', message: `Error: ${e.message}` });
    } finally {
      setHubActionLoading(null);
      setTimeout(() => setCsActionToast(null), 4000);
    }
  };

  useEffect(() => {
    if (activeTab === 'crowdsec') {
      fetchCrowdSecOverview();
      if (csSubTab === 'decisions') fetchCrowdSecDecisions();
      if (csSubTab === 'appsec') fetchCrowdSecAppSec();
      if (csSubTab === 'hub') fetchCrowdSecHub();
      if (csSubTab === 'alerts') fetchCrowdSecAlerts();
      if (csSubTab === 'topology') fetchCrowdSecTopology();
    }
  }, [activeTab, csSubTab]);


  const enabledRulesCount = useMemo(() => csRules.filter((r) => r.status && r.status.includes('enabled')).length, [csRules]);

  return (
    <>
            <div className="space-y-6">
              {/* Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <ShieldAlert className="w-6 h-6 text-rose-400" />
                    <h2 className="text-xl font-bold tracking-tight text-white">Pasture Security Console 🐮</h2>
                  </div>
                  <p className="text-sm text-slate-400 mt-1">
                    CrowdSec keeps the mailcow pasture safe: an electric fence (OpenResty AppSec WAF) round the webmail, a sturdy firewall gate (ipset) for the whole field, herd dogs sniffing postfix, dovecot, nginx and SSH logs, and community blocklists to keep the wolves away. Moo.
                  </p>
                </div>
                <div className="flex items-center space-x-2.5">
                  <button
                    onClick={() => setIsManualBlockModalOpen(true)}
                    className="flex items-center space-x-1.5 px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-rose-600/20 transition-all cursor-pointer"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>Manual Block IP</span>
                  </button>
                  <button
                    onClick={handleUpdateHub}
                    disabled={isUpdatingHub}
                    className="flex items-center space-x-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-xl text-xs font-medium transition-all cursor-pointer disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isUpdatingHub ? 'animate-spin text-rose-400' : ''}`} />
                    <span>{isUpdatingHub ? 'Updating Hub...' : 'Update Feeds'}</span>
                  </button>
                  <button
                    onClick={() => {
                      fetchCrowdSecOverview();
                      if (csSubTab === 'decisions') fetchCrowdSecDecisions();
                      if (csSubTab === 'appsec') fetchCrowdSecAppSec();
                      if (csSubTab === 'hub') fetchCrowdSecHub();
                      if (csSubTab === 'alerts') fetchCrowdSecAlerts();
                      if (csSubTab === 'topology') fetchCrowdSecTopology();
                                    }}
                    className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl border border-slate-700 transition-all cursor-pointer"
                    title="Refresh Data"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>

              {/* Toast Notification */}
              {csActionToast && (
                <div className={`p-3.5 rounded-xl border flex items-center space-x-2 text-xs font-medium animate-fadeIn ${
                  csActionToast.type === 'success'
                    ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300'
                    : 'bg-rose-950/60 border-rose-800 text-rose-300'
                }`}>
                  {csActionToast.type === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  )}
                  <span>{csActionToast.message}</span>
                </div>
              )}

              {/* 5 Top Feature Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
                {/* Active Bans */}
                <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 space-y-2 relative overflow-hidden group hover:border-rose-500/40 transition-all shadow-lg">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-medium">Active Decisions</span>
                    <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-white tracking-tight">
                    {csOverview ? csOverview.activeBansTotal.toLocaleString() : '15,000'}
                  </div>
                  <div className="text-[11px] text-slate-400 flex items-center justify-between pt-1 border-t border-slate-800/60">
                    <span>Local: <strong className="text-rose-400 font-mono">{csOverview?.localBans || 0}</strong></span>
                    <span>CAPI: <strong className="text-slate-300 font-mono">{csOverview?.capiBans || 15000}</strong></span>
                  </div>
                </div>

                {/* AppSec WAF */}
                <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 space-y-2 relative overflow-hidden group hover:border-indigo-500/40 transition-all shadow-lg">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-medium">AppSec Layer 7 WAF</span>
                    <ShieldCheck className="w-3.5 h-3.5 text-indigo-400" />
                  </div>
                  <div className="text-xl font-bold text-emerald-400 tracking-tight flex items-center gap-1.5">
                    <span>Active</span>
                    {csOverview?.appsecBlock !== undefined ? (
                      <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800/60 text-emerald-300 font-mono">
                        {csOverview.appsecBlock} block · {csOverview.appsecWatch} watch
                      </span>
                    ) : (
                      <span className="text-xs px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800/60 text-emerald-300 font-mono">
                        {(csOverview?.appsecRules !== undefined ? csOverview.appsecRules : enabledRulesCount)} Rules
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/60 font-mono truncate">
                    HTTP Filter: port 7422
                  </div>
                </div>

                {/* Bouncers */}
                <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 space-y-2 relative overflow-hidden group hover:border-emerald-500/40 transition-all shadow-lg">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-medium">Fence & Gate Bouncers</span>
                    <Globe className="w-3.5 h-3.5 text-emerald-400" />
                  </div>
                  <div className="text-xl font-bold text-white tracking-tight flex items-center gap-1.5">
                    <span>Holding the Line</span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-slate-800 text-emerald-400 font-mono">
                      Live
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/60 font-mono truncate">
                    ipset gate · OpenResty fence :443
                  </div>
                </div>

                {/* Security Agents */}
                <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 space-y-2 relative overflow-hidden group hover:border-sky-500/40 transition-all shadow-lg">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-medium">Protected Machines</span>
                    <Server className="w-3.5 h-3.5 text-sky-400" />
                  </div>
                  <div className="text-2xl font-bold font-mono text-white tracking-tight">
                    {csOverview?.machinesCount || 5}
                  </div>
                  <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/60 truncate">
                    Local herd dog · LAPI
                  </div>
                </div>

                {/* Detection Hub */}
                <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 space-y-2 relative overflow-hidden group hover:border-amber-500/40 transition-all shadow-lg">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-medium">Detection Hub</span>
                    <Layers className="w-3.5 h-3.5 text-amber-400" />
                  </div>
                  <div className="text-xl font-bold text-white tracking-tight">
                    {csOverview?.scenariosCount || 48} <span className="text-xs font-normal text-slate-400">Scenarios</span>
                  </div>
                  <div className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/60 truncate">
                    {csOverview?.parsersCount || 10} Parsers • {csOverview?.collections || 7} Collections
                  </div>
                </div>
              </div>


              {csSubTab === 'host' && <HostPanel />}
              {csSubTab === 'updates' && <UpdatesPanel />}
              {csSubTab === 'policy' && <PolicyPanel />}

              {/* SUB-TAB 1: DECISIONS & BLOCKED IPS */}
              {csSubTab === 'decisions' && (
                <div className="space-y-4">
                  {/* Filter & Search Bar */}
                  <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 p-3.5 rounded-2xl">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <div className="flex items-center space-x-2 bg-rose-950/40 border border-rose-800/60 px-3 py-1.5 rounded-xl text-xs font-semibold text-rose-300">
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                        <span>Active Local Bans</span>
                        <span className="bg-rose-900/60 text-rose-200 px-1.5 py-0.5 rounded-md font-mono text-[11px]">
                          {csTotalDecisions}
                        </span>
                      </div>
                      {csOverview && csOverview.capiBans > 0 && (
                        <div
                          className="flex items-center space-x-2 bg-slate-800/60 border border-slate-700/60 px-3 py-1.5 rounded-xl text-xs text-slate-300"
                          title="Community blocklist IPs, blocked at the firewall and the edge"
                        >
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                          <span>CAPI Community Intelligence:</span>
                          <span className="text-emerald-400 font-mono font-semibold">
                            {csOverview.capiBans.toLocaleString()}
                          </span>
                          <span className="text-[11px] text-slate-400">Threats Enforced</span>
                        </div>
                      )}
                    </div>

                    <div className="relative flex-1 max-w-md">
                      <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        placeholder="Search local bans, or enter any IP to check status..."
                        value={csSearch}
                        onChange={e => {
                          const val = e.target.value;
                          setCsSearch(val);
                          setCsPage(1);
                          if (csSearchTimeoutRef.current) clearTimeout(csSearchTimeoutRef.current);
                          csSearchTimeoutRef.current = setTimeout(() => {
                            fetchCrowdSecDecisions(csOriginFilter, val, false, 1);
                          }, 350);
                        }}
                        onKeyDown={e => {
                          if (e.key === 'Enter') {
                            if (csSearchTimeoutRef.current) clearTimeout(csSearchTimeoutRef.current);
                            fetchCrowdSecDecisions(csOriginFilter, csSearch, false, 1);
                          }
                        }}
                        className="w-full pl-9 pr-8 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-rose-500 transition-all font-mono"
                      />
                      {csSearch && (
                        <button
                          onClick={() => {
                            setCsSearch('');
                            setCsPage(1);
                            if (csSearchTimeoutRef.current) clearTimeout(csSearchTimeoutRef.current);
                            fetchCrowdSecDecisions(csOriginFilter, '', false, 1);
                          }}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer text-xs"
                          title="Clear search"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Decisions Table */}
                  <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl overflow-hidden shadow-xl">
                    {csLoading && csDecisions.length === 0 ? (
                      <div className="flex items-center justify-center p-12 text-slate-400 space-x-2">
                        <RefreshCw className="w-5 h-5 animate-spin text-rose-400" />
                        <span className="text-xs">Querying decisions & enriching IP geolocation...</span>
                      </div>
                    ) : csDecisions.length === 0 ? (
                      <div className="text-center p-12 text-slate-400 space-x-2">
                        <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                        <p className="text-sm font-medium text-slate-300">No decisions match current criteria</p>
                        <p className="text-xs text-slate-500 mt-1">If filtering by "Local & Custom Bans", no IPs have been banned locally yet.</p>
                      </div>
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                          <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                            <tr>
                              <th className="py-3 px-4">Target IP / Range</th>
                              <th className="py-3 px-4">Location & GeoIP</th>
                              <th className="py-3 px-4">Trigger / Scenario</th>
                              <th className="py-3 px-4">Action</th>
                              <th className="py-3 px-4">Duration</th>
                              <th className="py-3 px-4">Origin</th>
                              <th className="py-3 px-4 text-right">Remediation</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-slate-800/60 text-slate-300">
                            {csDecisions.map((dec) => (
                              <tr key={`${dec.id}-${dec.value}`} className="hover:bg-slate-800/30 transition-colors">
                                <td className="py-3.5 px-4 font-mono font-bold text-white">
                                  <div className="flex items-center space-x-2">
                                    <span>{dec.value}</span>
                                    <button
                                      onClick={() => handleCopyIP(dec.value)}
                                      className="text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
                                      title="Copy IP"
                                    >
                                      {copiedIP === dec.value ? (
                                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                                      ) : (
                                        <Copy className="w-3.5 h-3.5" />
                                      )}
                                    </button>
                                  </div>
                                </td>
                                <td className="py-3.5 px-4">
                                  <CountryFlagBadge geo={dec.geo} />
                                </td>
                                <td className="py-3.5 px-4">
                                  <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-rose-950/40 text-rose-300 border border-rose-800/40 max-w-[220px] truncate" title={dec.scenario}>
                                    {dec.scenario}
                                  </span>
                                </td>
                                <td className="py-3.5 px-4">
                                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                                    dec.type === 'ban'
                                      ? 'bg-rose-950/80 text-rose-300 border border-rose-800/70'
                                      : 'bg-amber-950/80 text-amber-300 border border-amber-800/70'
                                  }`}>
                                    <Ban className="w-2.5 h-2.5" />
                                    <span>{dec.type}</span>
                                  </span>
                                </td>
                                <td className="py-3.5 px-4 font-mono text-slate-400">
                                  <span className="inline-flex items-center gap-1">
                                    <Clock className="w-3 h-3 text-slate-500" />
                                    <span>{dec.duration}</span>
                                  </span>
                                </td>
                                <td className="py-3.5 px-4">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                                    dec.origin === 'cscli'
                                      ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                                      : dec.origin === 'crowdsec'
                                      ? 'bg-blue-950/80 text-blue-300 border border-blue-800/60'
                                      : 'bg-slate-800 text-slate-300 border border-slate-700/60'
                                  }`}>
                                    {dec.origin}
                                  </span>
                                </td>
                                <td className="py-3.5 px-4 text-right">
                                  <button
                                    onClick={() => setUnblockTarget(dec)}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-rose-950/80 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-700 transition-all cursor-pointer text-xs"
                                    title="Unblock this IP"
                                  >
                                    <Unlock className="w-3 h-3" />
                                    <span>Unblock</span>
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {/* Pagination Bar */}
                    {csDecisions.length > 0 && (
                      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 px-4 py-3 bg-slate-950/70 border-t border-slate-800/80 text-xs text-slate-400">
                        <div>
                          Showing <span className="font-semibold text-slate-200">{(csPage - 1) * 50 + 1}</span> to <span className="font-semibold text-slate-200">{Math.min(csPage * 50, csTotalDecisions)}</span> of <span className="font-semibold text-rose-400">{csTotalDecisions.toLocaleString()}</span> active threats
                        </div>
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => {
                              const newPage = Math.max(1, csPage - 1);
                              setCsPage(newPage);
                              fetchCrowdSecDecisions(csOriginFilter, csSearch, false, newPage);
                            }}
                            disabled={csPage <= 1 || csLoading}
                            className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer font-medium"
                          >
                            Previous
                          </button>
                          <span className="font-mono text-xs text-slate-400 px-1">
                            Page <span className="font-semibold text-white">{csPage}</span> of <span className="font-semibold text-white">{Math.max(1, Math.ceil(csTotalDecisions / 50))}</span>
                          </span>
                          <button
                            onClick={() => {
                              const maxPage = Math.max(1, Math.ceil(csTotalDecisions / 50));
                              const newPage = Math.min(maxPage, csPage + 1);
                              setCsPage(newPage);
                              fetchCrowdSecDecisions(csOriginFilter, csSearch, false, newPage);
                            }}
                            disabled={csPage >= Math.ceil(csTotalDecisions / 50) || csLoading}
                            className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 disabled:opacity-40 disabled:cursor-not-allowed transition-all cursor-pointer font-medium"
                          >
                            Next
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* SUB-TAB 2: APPSEC WAF & VIRTUAL PATCHES */}
              {csSubTab === 'appsec' && <MailWafPanel />}

              {csSubTab === 'hub' && (
                <div className="space-y-6">
                  {/* Category Filter Selector - Directly matching CrowdSec Hub */}
                  <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-2xl space-y-3">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                      <div>
                        <div className="flex items-center space-x-2">
                          <Library className="w-4 h-4 text-purple-400" />
                          <h3 className="font-bold text-sm text-white">CrowdSec Hub Extensions Catalog</h3>
                        </div>
                        <p className="text-xs text-slate-400 mt-0.5">
                          Install threat detection collections, scenarios, log parsers, postoverflows, and WAF rules dynamically from the CrowdSec Hub.
                        </p>
                      </div>
                      <div className="flex items-center space-x-2 text-xs">
                        <span className="px-2.5 py-1 bg-purple-950/60 border border-purple-800/60 text-purple-300 rounded-lg font-mono">
                          {hubTotal} items
                        </span>
                        <span className="px-2.5 py-1 bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 rounded-lg font-mono">
                          {hubEnabledCount} in the trough
                        </span>
                      </div>
                    </div>

                    {/* 7 Hub Categories as Pills */}
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      {[
                        { id: 'collections', label: 'Collections', icon: Package, count: hubCounts['collections'] ?? 0, color: 'purple' },
                        { id: 'scenarios', label: 'Attack Scenarios', icon: ShieldAlert, count: hubCounts['scenarios'] ?? 0, color: 'amber' },
                        { id: 'parsers', label: 'Log Parsers', icon: Radio, count: hubCounts['parsers'] ?? 0, color: 'blue' },
                        { id: 'postoverflows', label: 'Postoverflows', icon: Layers, count: hubCounts['postoverflows'] ?? 0, color: 'rose' },
                        { id: 'all', label: 'All relevant', icon: Boxes, count: hubCounts['all'] ?? 0, color: 'slate' },
                      ].map(cat => {
                        const Icon = cat.icon;
                        const isSelected = hubCategory === cat.id;
                        return (
                          <button
                            key={cat.id}
                            onClick={() => {
                              setHubCategory(cat.id as any);
                              fetchCrowdSecHub(cat.id as any, hubSearch, hubStatusFilter);
                            }}
                            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                              isSelected
                                ? 'bg-purple-600 text-white font-semibold shadow-md shadow-purple-600/20'
                                : 'bg-slate-950/60 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-slate-700'
                            }`}
                          >
                            <Icon className="w-3.5 h-3.5" />
                            <span>{cat.label}</span>
                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                              isSelected ? 'bg-purple-800 text-purple-100' : 'bg-slate-800 text-slate-400'
                            }`}>
                              {cat.count}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Filter & Search Bar */}
                  <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3 bg-slate-900/60 border border-slate-800/80 p-3.5 rounded-2xl">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs text-slate-400 font-medium mr-1">Status:</span>
                      {[
                        { id: 'all', label: 'All Items' },
                        { id: 'enabled', label: 'Enabled Only' },
                        { id: 'available', label: 'Available to Install' },
                      ].map(st => (
                        <button
                          key={st.id}
                          onClick={() => {
                            setHubStatusFilter(st.id as any);
                            fetchCrowdSecHub(hubCategory, hubSearch, st.id as any);
                          }}
                          className={`px-3 py-1.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                            hubStatusFilter === st.id
                              ? 'bg-purple-600 text-white font-semibold'
                              : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60'
                          }`}
                        >
                          {st.label}
                        </button>
                      ))}
                    </div>

                    <div className="relative flex-1 max-w-md">
                      <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        placeholder="Search the hub (e.g. postfix, dovecot, nginx, ssh)..."
                        value={hubSearch}
                        onChange={e => {
                          setHubSearch(e.target.value);
                          fetchCrowdSecHub(hubCategory, e.target.value, hubStatusFilter);
                        }}
                        className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-purple-500 transition-all font-mono"
                      />
                    </div>
                  </div>

                  {/* Quick Filter Tag Buttons */}
                  <div className="flex flex-wrap items-center gap-1.5 text-xs">
                    <span className="text-slate-500 text-[11px] font-medium mr-1">Showing what matters on a mail server (installed items always show; WAF rules live in Electric Fence). Quick filters:</span>
                    {['postfix', 'dovecot', 'nginx', 'ssh', 'http', 'cve', 'whitelist', 'linux'].map(tag => (
                      <button
                        key={tag}
                        onClick={() => {
                          setHubSearch(tag);
                          fetchCrowdSecHub(hubCategory, tag, hubStatusFilter);
                        }}
                        className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 hover:border-purple-500/50 text-slate-400 hover:text-purple-300 font-mono text-[11px] cursor-pointer transition-all"
                      >
                        #{tag}
                      </button>
                    ))}
                    {hubSearch && (
                      <button
                        onClick={() => {
                          setHubSearch('');
                          fetchCrowdSecHub(hubCategory, '', hubStatusFilter);
                        }}
                        className="px-2 py-0.5 text-[11px] text-slate-500 hover:text-rose-400 cursor-pointer"
                      >
                        Clear search
                      </button>
                    )}
                  </div>

                  {/* Hub Items Grid */}
                  {hubLoading ? (
                    <div className="flex items-center justify-center p-16 bg-slate-900/40 border border-slate-800 rounded-2xl text-slate-400 space-x-2">
                      <RefreshCw className="w-5 h-5 animate-spin text-purple-400" />
                      <span className="text-xs">Querying CrowdSec Central Hub catalog...</span>
                    </div>
                  ) : hubItems.length === 0 ? (
                    <div className="text-center p-16 bg-slate-900/40 border border-slate-800 rounded-2xl text-slate-400 space-y-2">
                      <Package className="w-8 h-8 text-slate-600 mx-auto" />
                      <p className="text-sm font-medium text-slate-300">No CrowdSec Hub items match your query</p>
                      <p className="text-xs text-slate-500">Try changing your category, search term, or status filter.</p>
                      <button
                        onClick={() => {
                          setHubCategory('collections');
                          setHubStatusFilter('all');
                          setHubSearch('');
                          fetchCrowdSecHub('collections', '', 'all');
                        }}
                        className="mt-3 px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-medium cursor-pointer transition-all"
                      >
                        Reset Hub Filters
                      </button>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {hubItems.map((item: any) => {
                        const isEnabled = item.status && item.status.includes('enabled');
                        const isUpdate = isEnabled && item.status.includes('update-available');
                        const isActionLoading = hubActionLoading === item.name;

                        const author = item.author || 'crowdsecurity';
                        const itemName = item.itemName || item.name.replace(`${author}/`, '');
                        const hubUrl = `https://app.crowdsec.net/hub/author/${author}/collections/${itemName}`;

                        return (
                          <div
                            key={item.name}
                            className={`bg-slate-900/60 border rounded-2xl p-4 flex flex-col justify-between transition-all relative overflow-hidden group shadow-lg ${
                              isEnabled
                                ? 'border-emerald-900/60 hover:border-emerald-700/80 bg-slate-900/80'
                                : 'border-slate-800 hover:border-slate-700'
                            }`}
                          >
                            <div className="space-y-2.5">
                              {/* Card Header: Category & Status */}
                              <div className="flex items-center justify-between gap-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                                  item.type === 'collections' ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60' :
                                  item.type === 'scenarios' ? 'bg-amber-950/80 text-amber-300 border border-amber-800/60' :
                                  item.type === 'parsers' ? 'bg-blue-950/80 text-blue-300 border border-blue-800/60' :
                                  item.type === 'postoverflows' ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60' :
                                  item.type === 'appsec-configs' ? 'bg-indigo-950/80 text-indigo-300 border border-indigo-800/60' :
                                  'bg-sky-950/80 text-sky-300 border border-sky-800/60'
                                }`}>
                                  {item.type || 'collection'}
                                </span>

                                {isEnabled ? (
                                  <span className="flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800/70">
                                    <CheckCircle2 className="w-2.5 h-2.5 text-emerald-400" />
                                    <span>Enabled</span>
                                    {item.local_version && <span className="font-mono text-emerald-400 ml-1">v{item.local_version}</span>}
                                  </span>
                                ) : (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800/70 text-slate-400 border border-slate-700/60">
                                    Available
                                  </span>
                                )}
                              </div>

                              {/* Title & Description */}
                              <div>
                                <h4 className="font-bold text-sm text-white font-mono group-hover:text-purple-300 transition-colors break-all">
                                  {item.name}
                                </h4>
                                <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                                  {item.description || 'Threat protection module provided by the CrowdSec Hub community.'}
                                </p>
                              </div>

                              {/* Path / Version metadata */}
                              {item.local_path && (
                                <div className="text-[10px] font-mono text-slate-500 truncate pt-1 border-t border-slate-800/50">
                                  Path: {item.local_path}
                                </div>
                              )}
                            </div>

                            {/* Card Footer: Action Buttons */}
                            <div className="flex items-center justify-between gap-2 pt-3 mt-3 border-t border-slate-800/80">
                              <a
                                href={hubUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="flex items-center space-x-1 text-[11px] text-slate-400 hover:text-purple-300 transition-colors cursor-pointer"
                                title="Open Hub page"
                              >
                                <ExternalLink className="w-3 h-3" />
                                <span>Hub Info</span>
                              </a>

                              <div className="flex items-center space-x-2">
                                {isUpdate && (
                                  <button
                                    onClick={() => handleUpgradeHubItem(item)}
                                    disabled={isActionLoading}
                                    className="px-2.5 py-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/50 rounded-xl text-xs font-semibold flex items-center space-x-1 transition-all cursor-pointer disabled:opacity-50"
                                  >
                                    <RefreshCw className={`w-3 h-3 ${isActionLoading ? 'animate-spin' : ''}`} />
                                    <span>Update</span>
                                  </button>
                                )}

                                {isEnabled ? (
                                  <button
                                    onClick={() => handleRemoveHubItem(item)}
                                    disabled={isActionLoading}
                                    className="px-2.5 py-1.5 bg-slate-800 hover:bg-rose-950/80 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-700 rounded-xl text-xs font-medium flex items-center space-x-1 transition-all cursor-pointer disabled:opacity-50"
                                    title="Disable and remove plugin"
                                  >
                                    <Trash2 className="w-3 h-3" />
                                    <span>{isActionLoading ? 'Removing...' : 'Remove'}</span>
                                  </button>
                                ) : (
                                  <button
                                    onClick={() => handleInstallHubItem(item)}
                                    disabled={isActionLoading}
                                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-xl text-xs font-semibold shadow-md shadow-purple-600/20 flex items-center space-x-1.5 transition-all cursor-pointer disabled:opacity-50"
                                    title="Install and enable this item"
                                  >
                                    <Download className="w-3 h-3" />
                                    <span>{isActionLoading ? 'Installing...' : 'Install'}</span>
                                  </button>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* SUB-TAB 3: ALERTS STREAM */}
              {csSubTab === 'alerts' && (
                <div className="space-y-4">
                  <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl overflow-hidden shadow-xl">
                    <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Activity className="w-4 h-4 text-amber-400" />
                        <h3 className="font-bold text-sm text-white">Live Threat Alerts</h3>
                      </div>
                      <span className="text-xs text-slate-400 font-mono">Real-time incident log</span>
                    </div>

                    {csAlerts.length === 0 ? (
                      <div className="text-center p-12 text-slate-400 space-x-2">
                        <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                        <p className="text-sm font-medium text-slate-300">Clean security log: no recent alerts</p>
                        <p className="text-xs text-slate-500 mt-1">When bad actors probe endpoints or fail credentials, alerts will stream here.</p>
                      </div>
                    ) : (
                      <div className="divide-y divide-slate-800/60">
                        {csAlerts.map((alert) => (
                          <div key={alert.id} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-slate-800/20 transition-colors">
                            <div className="space-y-1">
                              <div className="flex items-center space-x-2.5">
                                <span className="font-mono font-bold text-sm text-white">{alert.ip}</span>
                                <CountryFlagBadge geo={alert.geo} />
                                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950/80 text-rose-300 border border-rose-800/60 font-semibold">
                                  {alert.scenario}
                                </span>
                              </div>
                              <p className="text-xs text-slate-400">
                                {alert.message || `Security event triggered ${alert.eventsCount} time(s)`}
                              </p>
                            </div>
                            <div className="flex items-center space-x-3 text-xs text-slate-400 font-mono">
                              <span>Alert ID #{alert.id}</span>
                              <span className="text-slate-500">•</span>
                              <span>{new Date(alert.createdAt).toLocaleTimeString()}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* SUB-TAB 4: TOPOLOGY (BOUNCERS & MACHINES) */}
              {csSubTab === 'topology' && (
                <div className="space-y-6">
                  {/* Bouncers Section */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-sm text-white flex items-center space-x-2">
                        <Shield className="w-4 h-4 text-emerald-400" />
                        <span>Registered Remediation Components (Bouncers)</span>
                      </h3>
                      <span className="text-[11px] font-mono text-slate-400">
                        {(csBouncers || []).length} registered bouncer(s)
                      </span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                      {(csBouncers || []).length === 0 ? (
                        <div className="col-span-full bg-slate-900/40 border border-slate-800 rounded-2xl p-6 text-center text-slate-400 text-xs font-mono">
                          No bouncers registered yet or loading...
                        </div>
                      ) : (
                        (csBouncers || []).map((b) => {
                          const isReplica = b.name.includes('@') || b.auto_created;
                          return (
                            <div key={b.name} className="cowsec-card rounded-2xl p-4 space-y-2.5 shadow-md">
                              <div className="flex items-center justify-between gap-2">
                                <h4 className="font-mono font-bold text-sm text-white truncate" title={b.name}>{b.name}</h4>
                                <div className="flex items-center space-x-1.5 shrink-0">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
                                    isReplica
                                      ? 'bg-cyan-950/70 text-cyan-300 border-cyan-700/50'
                                      : 'bg-indigo-950/70 text-indigo-300 border-indigo-700/50 font-semibold'
                                  }`}>
                                    {isReplica ? 'Replica Stream' : 'Primary Key'}
                                  </span>
                                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
                                    Active
                                  </span>
                                </div>
                              </div>
                              <div className="space-y-1 text-xs text-slate-400 font-mono">
                                <p>Type: <strong className="text-slate-200">{b.type || 'bouncer'} {b.version ? `(${b.version})` : ''}</strong></p>
                                <p>Address: <strong className="text-cyan-300">{b.ip_address || 'local'}</strong></p>
                                <p>Enforcement: <strong className="text-emerald-400">{/firewall/i.test(b.type || b.name) ? 'Firewall (iptables/ipset)' : /openresty|nginx|lua/i.test(b.type || b.name) ? 'Web edge + AppSec WAF' : 'Remediation component'}</strong></p>
                                <p>Last Decision Pull: <strong className="text-slate-200">{b.last_pull ? formatRelativeTime(b.last_pull) : 'Streaming live'}</strong></p>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* Registered Machines & Agents */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-bold text-sm text-white flex items-center space-x-2">
                        <Server className="w-4 h-4 text-sky-400" />
                        <span>Registered Machines, AppSec WAF Engines & Log Agents ({(csMachines || []).length})</span>
                      </h3>
                      <div className="flex items-center space-x-2.5">
                        <span className="text-[11px] text-slate-400 hidden sm:inline font-mono">
                          1 LAPI • {(csMachines || []).filter(m => m.machineId.includes('appsec')).length} AppSec WAF • {(csMachines || []).filter(m => m.machineId.includes('agent')).length} Node Log Agents
                        </span>
                        <button
                          onClick={handlePruneMachines}
                          disabled={isPruningMachines}
                          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 transition-all border border-slate-700/80 cursor-pointer disabled:opacity-50"
                          title="Remove machine registrations that stopped reporting (bouncers are never removed)"
                        >
                          <Trash2 className="w-3.5 h-3.5 text-slate-400" />
                          <span>{isPruningMachines ? 'Pruning...' : 'Prune stale machines'}</span>
                        </button>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
                      {(csMachines || []).length === 0 ? (
                        <div className="col-span-full bg-slate-900/40 border border-slate-800 rounded-2xl p-6 text-center text-slate-400 text-xs font-mono">
                          No registered machines found.
                        </div>
                      ) : (
                        (csMachines || []).map((m) => {
                        const isLapi = m.machineId.includes('lapi');
                        const isAppSec = m.machineId.includes('appsec');
                        const heartbeatDiffSec = m.last_heartbeat 
                          ? Math.floor((new Date().getTime() - new Date(m.last_heartbeat).getTime()) / 1000)
                          : null;
                        const isHeartbeatHealthy = heartbeatDiffSec !== null && heartbeatDiffSec < 180;

                        return (
                          <div key={m.machineId} className="cowsec-card rounded-2xl p-4 space-y-3 shadow-md">
                            <div className="flex items-center justify-between gap-2">
                              <h4 className="font-mono font-bold text-xs text-white truncate" title={m.machineId}>
                                {m.machineId}
                              </h4>
                              <div className="flex items-center space-x-1.5 shrink-0">
                                {isLapi ? (
                                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-700/60 font-semibold">
                                    LAPI Server
                                  </span>
                                ) : isAppSec ? (
                                  <>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-700/60 font-semibold">
                                      AppSec WAF
                                    </span>
                                    <button
                                      onClick={() => handleDeleteMachine(m.machineId)}
                                      disabled={deletingMachine === m.machineId}
                                      className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 transition-colors disabled:opacity-50 cursor-pointer"
                                      title={`Delete machine registration for ${m.machineId}`}
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                  </>
                                ) : (
                                  <>
                                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-950 text-sky-300 border border-sky-800 font-semibold">
                                      Log Agent
                                    </span>
                                    <button
                                      onClick={() => handleDeleteMachine(m.machineId)}
                                      disabled={deletingMachine === m.machineId}
                                      className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-rose-950/40 transition-colors disabled:opacity-50 cursor-pointer"
                                      title={`Delete machine registration for ${m.machineId}`}
                                    >
                                      <Trash2 className="w-3 h-3" />
                                    </button>
                                  </>
                                )}
                              </div>
                            </div>
                            <div className="space-y-1 text-xs text-slate-400 font-mono">
                              <p>
                                Role:{' '}
                                <strong className={isLapi ? 'text-indigo-300' : isAppSec ? 'text-purple-300' : 'text-sky-300'}>
                                  {isLapi ? 'Local API decision server' : isAppSec ? 'AppSec WAF & virtual patching' : 'Log processor (agent)'}
                                </strong>
                              </p>
                              <p>
                                Address:{' '}
                                <strong className="text-slate-200">{m.ipAddress || 'local'}</strong>
                              </p>
                              <p>Version: <strong className="text-slate-300">{m.version || 'unknown'}</strong></p>

                              {isLapi ? (
                                <div className="pt-2 border-t border-slate-800/80 space-y-0.5">
                                  <div className="text-[11px] text-indigo-300 flex items-center gap-1.5 font-medium">
                                    <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
                                    <span>Server Daemon Active</span>
                                  </div>
                                  <p className="text-[11px] text-slate-400">
                                    Last Activity: <strong className="text-slate-200">{formatRelativeTime(m.updated_at || m.last_heartbeat || m.created_at)}</strong>
                                  </p>
                                  <p className="text-[10px] text-slate-500 italic">
                                    Central API receiver & CAPI blocklist synchronizer
                                  </p>
                                </div>
                              ) : m.last_heartbeat ? (
                                <div className="pt-2 border-t border-slate-800/80 space-y-0.5">
                                  {isHeartbeatHealthy ? (
                                    <div className="text-[11px] text-emerald-400 flex items-center gap-1.5 font-medium">
                                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                                      <span>Heartbeat Active</span>
                                      <span className="text-slate-400 text-[10px]">({formatRelativeTime(m.last_heartbeat)})</span>
                                    </div>
                                  ) : (
                                    <div className="text-[11px] text-amber-400 flex items-center gap-1.5 font-medium">
                                      <span className="w-2 h-2 rounded-full bg-amber-400"></span>
                                      <span>Heartbeat Stale</span>
                                      <span className="text-slate-400 text-[10px]">({formatRelativeTime(m.last_heartbeat)})</span>
                                    </div>
                                  )}
                                  <p className="text-[10px] text-slate-500">
                                    {isAppSec
                                      ? 'Inspecting HTTP requests on 127.0.0.1:7422'
                                      : 'Reading mailcow, web and system logs'}
                                  </p>
                                </div>
                              ) : (
                                <div className="pt-2 border-t border-slate-800/80">
                                  <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
                                    <span className="w-2 h-2 rounded-full bg-slate-600"></span>
                                    <span>No heartbeat recorded</span>
                                  </span>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      }))}
                    </div>
                  </div>
                </div>
              )}

              {/* SUB-TAB 5: WHITELISTS & LAN SAFETY */}
              {csSubTab === 'whitelists' && <WhitelistsPanel />}
            </div>
      {/* MANUAL BLOCK MODAL */}
      {isManualBlockModalOpen && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-md w-full space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Ban className="w-5 h-5 text-rose-500" />
                <h3 className="font-bold text-base text-white">Manual Security Ban</h3>
              </div>
              <button
                onClick={() => setIsManualBlockModalOpen(false)}
                className="text-slate-500 hover:text-slate-300 cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleManualBlock} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Target IP Address or CIDR Range</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 198.51.100.42 or 203.0.113.0/24"
                  value={manualBlockForm.ip}
                  onChange={e => setManualBlockForm(prev => ({ ...prev, ip: e.target.value }))}
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-sm font-mono text-white placeholder-slate-500 focus:outline-hidden focus:border-rose-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Decision Duration</label>
                <div className="grid grid-cols-5 gap-1.5">
                  {['1h', '4h', '24h', '7d', '30d'].map(d => (
                    <button
                      type="button"
                      key={d}
                      onClick={() => setManualBlockForm(prev => ({ ...prev, duration: d }))}
                      className={`py-1.5 rounded-lg text-xs font-mono font-medium border transition-all cursor-pointer ${
                        manualBlockForm.duration === d
                          ? 'bg-rose-600 border-rose-500 text-white font-bold shadow-xs'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                      }`}
                    >
                      {d}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Reason / Threat Description</label>
                <input
                  type="text"
                  placeholder="e.g. manual-admin-ban: suspicious vulnerability probe"
                  value={manualBlockForm.reason}
                  onChange={e => setManualBlockForm(prev => ({ ...prev, reason: e.target.value }))}
                  className="w-full px-3.5 py-2.5 bg-slate-950 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-rose-500 font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-medium text-slate-300">Remediation Action</label>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { type: 'ban', label: 'Drop / Ban (403 Forbidden)', desc: 'Blocks all HTTP/S packets' },
                    { type: 'captcha', label: 'Captcha Challenge', desc: 'Forces browser validation' }
                  ].map(act => (
                    <button
                      type="button"
                      key={act.type}
                      onClick={() => setManualBlockForm(prev => ({ ...prev, type: act.type }))}
                      className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                        manualBlockForm.type === act.type
                          ? 'bg-rose-950/60 border-rose-500 text-white shadow-xs'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="font-semibold text-xs text-slate-200">{act.label}</div>
                      <div className="text-[10px] text-slate-500">{act.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsManualBlockModalOpen(false)}
                  className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={csLoading}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-rose-600/20 transition-all cursor-pointer flex items-center space-x-1.5 disabled:opacity-50"
                >
                  <Ban className="w-3.5 h-3.5" />
                  <span>{csLoading ? 'Enforcing...' : 'Enforce Ban'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* CONFIRM UNBLOCK MODAL */}
      {unblockTarget && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 max-w-sm w-full space-y-4 shadow-2xl">
            <div className="flex items-center space-x-3 text-amber-400">
              <div className="p-2.5 rounded-xl bg-amber-950/60 border border-amber-800/60">
                <Unlock className="w-5 h-5 text-amber-400" />
              </div>
              <div>
                <h3 className="font-bold text-sm text-white">Unblock IP Decision</h3>
                <p className="text-xs text-slate-400">Remove security remediation</p>
              </div>
            </div>

            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1 text-xs">
              <div className="text-slate-400">Target IP / CIDR:</div>
              <div className="font-mono font-bold text-white text-sm">{unblockTarget.value}</div>
              <div className="text-[11px] text-slate-500">Scenario: {unblockTarget.scenario}</div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to lift this ban? The IP can reach the server again straight away.
            </p>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-800">
              <button
                type="button"
                onClick={() => setUnblockTarget(null)}
                className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={csLoading}
                onClick={() => handleUnblock(unblockTarget)}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-semibold shadow-lg shadow-emerald-600/20 transition-all cursor-pointer flex items-center space-x-1.5 disabled:opacity-50"
              >
                <Unlock className="w-3.5 h-3.5" />
                <span>{csLoading ? 'Unblocking...' : 'Confirm Unblock'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
