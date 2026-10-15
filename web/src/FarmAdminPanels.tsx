// The Farm, part two: domain administrators and their permissions, rate limits, TLS
// policy maps, relay hosts and transports, and mailcow's own ban engine (netfilter) with
// its coordination with CrowdSec. Same validated /api/mailcow endpoints and audit log.
import Select from './Select';
import { useEffect, useState } from 'react';
import {
  ArrowRight, Dog, Gauge, Lock, Pause, Play, Plus, RefreshCw, Route, Save, ShieldCheck, Trash2, Users, Workflow,
} from 'lucide-react';
import { Card, Tile } from './HostPanel';
import {
  btn, Confirm, Field, Header, input, Loading, NotConfigured, on, Pill, Problem, send, useApi, useToast,
} from './MailcowPanels';

const list = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

function Switch({ value, onChange, label }: { value: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer select-none">
      <button type="button" role="switch" aria-checked={value} onClick={() => onChange(!value)}
        className={`w-9 h-5 rounded-full relative transition-colors ${value ? 'bg-emerald-500' : 'bg-slate-700'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${value ? 'left-4.5' : 'left-0.5'}`} />
      </button>
      {label}
    </label>
  );
}

// ---------------------------------------------------------------- domain administrators

interface DomainAdmin { username: string; active: number | string; tfa_active?: number | string; selected_domains: string[]; unselected_domains: string[]; created?: string }
interface AdminsResponse { admins: DomainAdmin[] | Record<string, never>; acl: { keys: string[]; acls: Record<string, Record<string, boolean>>; error?: string } }

const ACL_LABELS: Record<string, string> = {
  syncjobs: 'Sync jobs', quarantine: 'Quarantine actions', login_as: 'Log in as a mailbox user', sogo_access: 'Manage SOGo access',
  app_passwds: 'App passwords', bcc_maps: 'BCC maps', pushover: 'Pushover notifications', filters: 'Sieve filters', ratelimit: 'Rate limits',
  spam_policy: 'Spam allow/block lists', extend_sender_acl: 'Send as external addresses', unlimited_quota: 'Unlimited mailbox quota',
  protocol_access: 'Protocol access (IMAP/POP/SMTP)', smtp_ip_access: 'SMTP IP restrictions', alias_domains: 'Alias domains',
  mailbox_relayhost: 'Mailbox relay host', domain_relayhost: 'Domain relay host', domain_desc: 'Domain description',
  alias_external_goto: 'Aliases to external addresses', quarantine_attachments: 'Quarantine attachments',
  quarantine_notification: 'Quarantine notifications', quarantine_category: 'Quarantine categories', tls_policy: 'TLS policy',
};
const aclLabel = (k: string) => ACL_LABELS[k] || k.replace(/_/g, ' ');

function AclEditor({ user, keys, current, onSaved, run }: { user: string; keys: string[]; current: Record<string, boolean>; onSaved: () => void; run: ReturnType<typeof useToast>['run'] }) {
  const [allow, setAllow] = useState<Record<string, boolean>>(current);
  useEffect(() => setAllow(current), [current]);
  return (
    <div className="mt-2 bg-slate-950/50 border border-slate-800 rounded-xl p-3 space-y-3 cs-page">
      <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {keys.map((k) => <Switch key={k} value={!!allow[k]} onChange={(v) => setAllow({ ...allow, [k]: v })} label={aclLabel(k)} />)}
      </div>
      <button onClick={() => run(() => send('PUT', `/api/mailcow/domain-admins/${encodeURIComponent(user)}/acl`, { allow: keys.filter((k) => allow[k]) }), onSaved)}
        className={`${btn} bg-indigo-600 hover:bg-indigo-500 text-white`}><Save className="w-3.5 h-3.5" /> Save permissions</button>
    </div>
  );
}

export function FarmhandsPanel() {
  const { data, error, notConfigured, reload } = useApi<AdminsResponse>('/api/mailcow/domain-admins');
  const domainsApi = useApi<{ domain_name: string }[]>('/api/mailcow/domains');
  const { toast, run } = useToast();
  const [adding, setAdding] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [f, setF] = useState({ username: '', password: '', domains: [] as string[] });
  if (notConfigured) return <NotConfigured />;
  const admins = list<DomainAdmin>(data?.admins);
  const allDomains = list<{ domain_name: string }>(domainsApi.data).map((d) => d.domain_name);
  const toggleDomain = (d: string) => setF({ ...f, domains: f.domains.includes(d) ? f.domains.filter((x) => x !== d) : [...f.domains, d] });
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Farmhands (Domain admins)" sub="People who manage some domains in mailcow, and exactly what they may change"
        action={<button onClick={() => setAdding(!adding)} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add farmhand</button>} />
      {adding && (
        <Card title="New farmhand" icon={<Plus className="w-4 h-4 text-emerald-400" />}>
          <div className="grid sm:grid-cols-2 gap-3 text-xs">
            <Field label="Username"><input className={input} value={f.username} onChange={(e) => setF({ ...f, username: e.target.value.trim() })} placeholder="jane" autoComplete="off" /></Field>
            <Field label="Password (8+ characters)"><input className={input} type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" /></Field>
          </div>
          <Field label="Domains they manage">
            <div className="flex flex-wrap gap-1.5">
              {allDomains.map((d) => (
                <button key={d} onClick={() => toggleDomain(d)} className={`text-xs font-mono px-2 py-1 rounded-lg border cursor-pointer ${f.domains.includes(d) ? 'border-indigo-400 bg-indigo-500/15 text-white' : 'border-slate-700 text-slate-400 hover:text-white'}`}>{d}</button>
              ))}
              {!allDomains.length && <span className="text-xs text-slate-500">Add a domain first.</span>}
            </div>
          </Field>
          <div className="flex gap-2">
            <button disabled={!f.username || f.password.length < 8 || !f.domains.length} onClick={() => run(() => send('POST', '/api/mailcow/domain-admins', { ...f, active: true }), () => { setAdding(false); setF({ username: '', password: '', domains: [] }); reload(); })}
              className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}>Create</button>
            <button onClick={() => setAdding(false)} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
          </div>
          <p className="text-[11px] text-slate-500">They sign in at mailcow's /domainadmin page. With "admin pages on the local network only", that page only answers from your LAN.</p>
        </Card>
      )}
      {error && <Problem text={error} />}
      {data?.acl.error && <Problem text="Couldn't read permissions from mailcow's database; editing still works." />}
      {!data ? <Loading text="Rounding up the farmhands…" /> : (
        <Card title={`${admins.length} farmhand${admins.length === 1 ? '' : 's'}`} icon={<Users className="w-4 h-4 text-indigo-300" />}>
          {!admins.length && <p className="text-sm text-slate-500">No domain administrators yet. Only the mailcow admin can manage domains.</p>}
          <div className="space-y-2 cs-stagger">
            {admins.map((a) => {
              const acl = data.acl.acls[a.username] || {};
              const granted = data.acl.keys.filter((k) => acl[k]).length;
              return (
                <div key={a.username} className="border border-slate-800 rounded-xl p-3">
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-white">{a.username} {on(a.tfa_active) && <span className="text-[10px] text-emerald-300 ml-1">2FA</span>}</p>
                      <p className="text-xs text-slate-500 font-mono truncate">{(a.selected_domains || []).join(', ') || 'no domains'}</p>
                    </div>
                    <span className="text-xs text-slate-400">{granted}/{data.acl.keys.length} permissions</span>
                    <Pill ok={on(a.active)} />
                    <button onClick={() => setOpen(open === a.username ? null : a.username)} className={`${btn} text-slate-300 hover:bg-slate-800`}><ShieldCheck className="w-3.5 h-3.5" /> Permissions</button>
                    <button onClick={() => run(() => send('PATCH', `/api/mailcow/domain-admins/${encodeURIComponent(a.username)}`, { active: !on(a.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>
                      {on(a.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    </button>
                    <Confirm label="Delete farmhand" onConfirm={() => run(() => send('DELETE', `/api/mailcow/domain-admins/${encodeURIComponent(a.username)}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
                  </div>
                  {open === a.username && <AclEditor user={a.username} keys={data.acl.keys} current={acl} onSaved={reload} run={run} />}
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- rate limits

interface RL { domain?: string; mailbox?: string; value?: string; frame?: string }
const FRAMES: [string, string][] = [['s', 'second'], ['m', 'minute'], ['h', 'hour'], ['d', 'day']];

function LimitRow({ kind, name, rl, run, reload }: { kind: 'domain' | 'mailbox'; name: string; rl?: RL; run: ReturnType<typeof useToast>['run']; reload: () => void }) {
  const [value, setValue] = useState(Number(rl?.value || 0));
  const [frame, setFrame] = useState(rl?.frame || 'h');
  useEffect(() => { setValue(Number(rl?.value || 0)); setFrame(rl?.frame || 'h'); }, [rl?.value, rl?.frame]);
  return (
    <tr className="border-t border-slate-800/70">
      <td className="py-2 font-mono text-xs text-slate-200">{name}</td>
      <td>{rl?.value ? <span className="text-xs font-mono text-amber-200">{rl.value} / {FRAMES.find(([f]) => f === rl.frame)?.[1] || rl.frame}</span> : <span className="text-xs text-slate-500">no limit</span>}</td>
      <td className="whitespace-nowrap">
        <input type="number" min={0} className={`${input} w-24`} value={value} onChange={(e) => setValue(Math.max(0, +e.target.value))} />
        <span className="text-xs text-slate-500 mx-1.5">per</span>
        <Select compact className="inline-block w-28 align-middle" value={frame} onChange={setFrame} options={FRAMES.map(([f, l]) => ({ value: f, label: l }))} ariaLabel="Per" />
      </td>
      <td className="text-right">
        <button onClick={() => run(() => send('PUT', `/api/mailcow/ratelimits/${kind}/${encodeURIComponent(name)}`, { value, frame }), reload)} className={`${btn} text-slate-300 hover:bg-slate-800`}><Save className="w-3.5 h-3.5" /> {value ? 'Set' : 'Remove'}</button>
      </td>
    </tr>
  );
}

export function GrazingLimitsPanel() {
  const { data, error, notConfigured, reload } = useApi<{ domains: RL[] | Record<string, never>; mailboxes: RL[] | Record<string, never> }>('/api/mailcow/ratelimits');
  const doms = useApi<{ domain_name: string }[]>('/api/mailcow/domains');
  const boxes = useApi<{ username: string }[]>('/api/mailcow/mailboxes');
  const { toast, run } = useToast();
  const [q, setQ] = useState('');
  if (notConfigured) return <NotConfigured />;
  const dl = new Map(list<RL>(data?.domains).map((x) => [x.domain || '', x]));
  const ml = new Map(list<RL>(data?.mailboxes).map((x) => [x.mailbox || '', x]));
  const mailboxes = list<{ username: string }>(boxes.data).map((m) => m.username).filter((m) => m.includes(q.toLowerCase()));
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Grazing Limits (Rate limits)" sub="How many messages a domain or mailbox may send. A hijacked account can't spray spam from your IP." />
      <div className="text-xs text-slate-400 bg-slate-900/50 border border-slate-800 rounded-xl p-3">
        Limits are enforced by rspamd on outgoing mail. The smaller of the domain and mailbox limit applies; set 0 to remove one.
      </div>
      {error && <Problem text={error} />}
      {!data ? <Loading text="Measuring the grass…" /> : (
        <>
          <Card title="Domains" icon={<Gauge className="w-4 h-4 text-amber-300" />}>
            <table className="w-full text-sm"><tbody>
              {list<{ domain_name: string }>(doms.data).map((d) => <LimitRow key={d.domain_name} kind="domain" name={d.domain_name} rl={dl.get(d.domain_name)} run={run} reload={reload} />)}
            </tbody></table>
          </Card>
          <Card title="Mailboxes" icon={<Gauge className="w-4 h-4 text-sky-300" />}>
            <input className={`${input} w-full mb-2`} placeholder="Filter mailboxes…" value={q} onChange={(e) => setQ(e.target.value)} />
            <table className="w-full text-sm"><tbody>
              {mailboxes.slice(0, 200).map((m) => <LimitRow key={m} kind="mailbox" name={m} rl={ml.get(m)} run={run} reload={reload} />)}
            </tbody></table>
          </Card>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- TLS policy maps

interface TlsPolicy { id: number; dest: string; policy: string; parameters: string; active: number | string }
const POLICIES: [string, string][] = [
  ['none', 'No TLS'], ['may', 'Opportunistic (default)'], ['encrypt', 'Require TLS, no certificate check'], ['dane', 'DANE if published, else opportunistic'],
  ['dane-only', 'Require DANE'], ['verify', 'Require a valid certificate (MX name)'], ['secure', 'Require a valid certificate (domain name)'], ['fingerprint', 'Pin a certificate fingerprint'],
];

export function LockedLanesPanel() {
  const { data, error, notConfigured, reload } = useApi<TlsPolicy[] | Record<string, never>>('/api/mailcow/tls-policies');
  const { toast, run } = useToast();
  const [f, setF] = useState({ dest: '', policy: 'secure', parameters: '' });
  if (notConfigured) return <NotConfigured />;
  const rows = list<TlsPolicy>(data);
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Locked Lanes (TLS policy)" sub="Demand encryption, or a verified certificate, when sending to particular domains" />
      <Card title="New lane" icon={<Plus className="w-4 h-4 text-emerald-400" />}>
        <div className="grid sm:grid-cols-3 gap-3 text-xs">
          <Field label="Destination"><input className={input} value={f.dest} onChange={(e) => setF({ ...f, dest: e.target.value.trim().toLowerCase() })} placeholder="bank.example" /></Field>
          <Field label="Policy"><Select value={f.policy} onChange={(v) => setF({ ...f, policy: v })} options={POLICIES.map(([p, l]) => ({ value: p, label: p, hint: l }))} /></Field>
          <Field label="Parameters (optional)"><input className={input} value={f.parameters} onChange={(e) => setF({ ...f, parameters: e.target.value })} placeholder="e.g. protocols=>=TLSv1.2" /></Field>
        </div>
        <button disabled={!f.dest} onClick={() => run(() => send('POST', '/api/mailcow/tls-policies', { ...f, active: true }), () => { setF({ ...f, dest: '', parameters: '' }); reload(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}>Add</button>
        <p className="text-[11px] text-slate-500">If the other side can't meet the policy, mail waits in the queue instead of going out unprotected.</p>
      </Card>
      {error && <Problem text={error} />}
      {!data ? <Loading text="Checking the locks…" /> : (
        <Card title={`${rows.length} lane${rows.length === 1 ? '' : 's'}`} icon={<Lock className="w-4 h-4 text-emerald-300" />}>
          {!rows.length && <p className="text-sm text-slate-500">No policies: mail uses opportunistic TLS everywhere (encrypted when the other side offers it).</p>}
          <table className="w-full text-sm"><tbody>
            {rows.map((t) => (
              <tr key={t.id} className="border-t border-slate-800/70">
                <td className="py-2 font-mono text-xs text-white">{t.dest}</td>
                <td>
                  <Select compact className="w-36" value={t.policy} onChange={(v) => run(() => send('PATCH', `/api/mailcow/tls-policies/${t.id}`, { policy: v }), reload)} options={POLICIES.map(([p, l]) => ({ value: p, label: p, hint: l }))} />
                </td>
                <td className="text-xs font-mono text-slate-400">{t.parameters}</td>
                <td><Pill ok={on(t.active)} /></td>
                <td className="text-right whitespace-nowrap">
                  <button onClick={() => run(() => send('PATCH', `/api/mailcow/tls-policies/${t.id}`, { active: !on(t.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{on(t.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}</button>
                  <Confirm label="Delete policy" onConfirm={() => run(() => send('DELETE', `/api/mailcow/tls-policies/${t.id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
                </td>
              </tr>
            ))}
          </tbody></table>
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- relay hosts and transports

interface Relayhost { id: number; hostname: string; username: string; active: number | string; used_by_domains?: string; used_by_mailboxes?: string }
interface Transport { id: number; destination: string; nexthop: string; username: string; active: number | string; is_mx_based?: number | string }

export function CattleRoutesPanel() {
  const relays = useApi<Relayhost[] | Record<string, never>>('/api/mailcow/relayhosts');
  const transports = useApi<Transport[] | Record<string, never>>('/api/mailcow/transports');
  const doms = useApi<{ domain_name: string; relayhost?: string | number }[]>('/api/mailcow/domains');
  const { toast, run } = useToast();
  const [r, setR] = useState({ hostname: '', username: '', password: '' });
  const [t, setT] = useState({ destination: '', nexthop: '', username: '', password: '', mxBased: false });
  if (relays.notConfigured) return <NotConfigured />;
  const rl = list<Relayhost>(relays.data);
  const tl = list<Transport>(transports.data);
  const reload = () => { relays.reload(); transports.reload(); doms.reload(); };
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Cattle Routes (Relay hosts & transports)" sub="Send some or all mail through another server, e.g. a smarthost when your provider blocks port 25" />
      <div className="flex items-center justify-center gap-3 text-xs text-slate-400 py-1">
        <span className="px-2.5 py-1 rounded-lg border border-slate-700">your mailcow</span>
        <ArrowRight className="w-4 h-4 text-sky-400 cs-flow" />
        <span className="px-2.5 py-1 rounded-lg border border-sky-700 text-sky-200">relay host / next hop</span>
        <ArrowRight className="w-4 h-4 text-sky-400 cs-flow" />
        <span className="px-2.5 py-1 rounded-lg border border-slate-700">the internet</span>
      </div>
      <div className="grid lg:grid-cols-2 gap-6">
        <Card title="Relay hosts (by sender domain)" icon={<Route className="w-4 h-4 text-sky-300" />}>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <input className={input} value={r.hostname} onChange={(e) => setR({ ...r, hostname: e.target.value.trim() })} placeholder="[smtp.relay.example]:587" />
            <input className={input} value={r.username} onChange={(e) => setR({ ...r, username: e.target.value })} placeholder="username" autoComplete="off" />
            <input className={input} type="password" value={r.password} onChange={(e) => setR({ ...r, password: e.target.value })} placeholder="password" autoComplete="new-password" />
          </div>
          <button disabled={!r.hostname} onClick={() => run(() => send('POST', '/api/mailcow/relayhosts', r), () => { setR({ hostname: '', username: '', password: '' }); reload(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add relay host</button>
          {rl.map((h) => (
            <div key={h.id} className="flex items-center gap-2 border-t border-slate-800/70 pt-2 text-sm">
              <div className="flex-1 min-w-0">
                <p className="font-mono text-xs text-white">#{h.id} {h.hostname}</p>
                <p className="text-[11px] text-slate-500">{h.username || 'no login'} · used by {h.used_by_domains || 'no domains'}</p>
              </div>
              <Pill ok={on(h.active)} />
              <button onClick={() => run(() => send('PATCH', `/api/mailcow/relayhosts/${h.id}`, { active: !on(h.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{on(h.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}</button>
              <Confirm label="Delete relay host" onConfirm={() => run(() => send('DELETE', `/api/mailcow/relayhosts/${h.id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
            </div>
          ))}
          {!!rl.length && (
            <div className="border-t border-slate-800/70 pt-2 space-y-1.5">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Which domains use them</p>
              {list<{ domain_name: string; relayhost?: string | number }>(doms.data).map((d) => (
                <div key={d.domain_name} className="flex items-center justify-between text-xs">
                  <span className="font-mono text-slate-300">{d.domain_name}</span>
                  <Select compact className="w-56" value={String(d.relayhost || '0')} onChange={(v) => run(() => send('PUT', `/api/mailcow/domains/${d.domain_name}/relayhost`, { id: +v }), reload)}
                    options={[{ value: '0', label: 'send directly' }, ...rl.map((h) => ({ value: String(h.id), label: `via #${h.id} ${h.hostname}` }))]} />
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card title="Transports (by destination)" icon={<Workflow className="w-4 h-4 text-violet-300" />}>
          <div className="grid grid-cols-2 gap-2 text-xs">
            <input className={input} value={t.destination} onChange={(e) => setT({ ...t, destination: e.target.value.trim() })} placeholder="example.org, .example.org or *" />
            <input className={input} value={t.nexthop} onChange={(e) => setT({ ...t, nexthop: e.target.value.trim() })} placeholder="[mx.partner.example]:25" />
            <input className={input} value={t.username} onChange={(e) => setT({ ...t, username: e.target.value })} placeholder="username (optional)" autoComplete="off" />
            <input className={input} type="password" value={t.password} onChange={(e) => setT({ ...t, password: e.target.value })} placeholder="password (optional)" autoComplete="new-password" />
          </div>
          <Switch value={t.mxBased} onChange={(v) => setT({ ...t, mxBased: v })} label="Match by the destination's MX (e.g. everything hosted at one provider)" />
          <button disabled={!t.destination || !t.nexthop} onClick={() => run(() => send('POST', '/api/mailcow/transports', { ...t, active: true }), () => { setT({ destination: '', nexthop: '', username: '', password: '', mxBased: false }); reload(); })} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white`}><Plus className="w-3.5 h-3.5" /> Add transport</button>
          {tl.map((x) => (
            <div key={x.id} className="flex items-center gap-2 border-t border-slate-800/70 pt-2 text-sm">
              <div className="flex-1 min-w-0">
                <p className="font-mono text-xs text-white">{x.destination} <ArrowRight className="inline w-3 h-3 text-slate-500" /> {x.nexthop}</p>
                <p className="text-[11px] text-slate-500">{x.username || 'no login'}{on(x.is_mx_based) ? ' · MX-based' : ''}</p>
              </div>
              <Pill ok={on(x.active)} />
              <button onClick={() => run(() => send('PATCH', `/api/mailcow/transports/${x.id}`, { active: !on(x.active) }), reload)} className={`${btn} text-slate-400 hover:text-white hover:bg-slate-800`}>{on(x.active) ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}</button>
              <Confirm label="Delete transport" onConfirm={() => run(() => send('DELETE', `/api/mailcow/transports/${x.id}`), reload)}><Trash2 className="w-3.5 h-3.5" /></Confirm>
            </div>
          ))}
        </Card>
      </div>
      {(relays.error || transports.error) && <Problem text={relays.error || transports.error} />}
    </div>
  );
}

// ---------------------------------------------------------------- netfilter (mailcow's own ban engine)

interface F2B {
  ban_time: number; max_ban_time: number; ban_time_increment: boolean | number; max_attempts: number; retry_window: number;
  netban_ipv4: number; netban_ipv6: number; whitelist: string; blacklist: string; manage_external: number;
  active_bans?: { network: string; banned_until: string; queued_for_unban: number }[] | string; perm_bans?: { network: string }[] | string;
}
interface Coord { mode: 'side-by-side' | 'crowdsec'; syncTrusted: boolean; lastSync?: string; imported?: number; lastError?: string | null }

export function GuardDogPanel() {
  const { data, error, notConfigured, loading, reload } = useApi<{ settings: F2B; coordination: Coord }>('/api/mailcow/netfilter');
  const { toast, run } = useToast();
  const [s, setS] = useState<F2B | null>(null);
  const [mode, setMode] = useState<Coord['mode']>('side-by-side');
  const [sync, setSync] = useState(true);
  const [net, setNet] = useState('');
  useEffect(() => {
    if (!data) return;
    setS(data.settings);
    setMode(data.coordination.mode);
    setSync(data.coordination.syncTrusted);
  }, [data]);
  if (notConfigured) return <NotConfigured />;
  if (error) return <Problem text={`Couldn't reach mailcow: ${error}`} />;
  if (!data || !s) return <Loading text="Whistling for the guard dog…" />;
  const active = list<{ network: string; banned_until: string; queued_for_unban: number }>(data.settings.active_bans);
  // with "manage externally" on, netfilter stops filling perm_bans; the blacklist is the source
  const perm = [...new Set([...list<{ network: string }>(data.settings.perm_bans).map((x) => x.network),
    ...(data.settings.blacklist || '').split(/[\s,;]+/).filter(Boolean)])].map((network) => ({ network }));
  const c = data.coordination;
  const changed = mode !== c.mode || sync !== c.syncTrusted;
  const num = (k: keyof F2B, label: string, unit: string) => (
    <Field label={`${label} (${unit})`}><input type="number" className={input} value={Number(s[k])} onChange={(e) => setS({ ...s, [k]: +e.target.value })} /></Field>
  );
  return (
    <div className="space-y-6">
      {toast}
      <Header title="Guard Dog (mailcow netfilter)" sub="mailcow's own ban engine, and how it works together with CrowdSec"
        action={<button onClick={() => run(async () => { await send('POST', '/api/mailcow/netfilter-sync'); return 'Synced with netfilter'; }, reload)} className={`${btn} border border-slate-700 text-slate-300 hover:bg-slate-800`}><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Sync now</button>} />
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tile label="Active bans" value={String(active.length)} sub="netfilter, right now" tone={active.length ? 'rose' : 'emerald'} icon={<Dog className="w-4 h-4" />} />
        <Tile label="Permanent" value={String(perm.length)} sub="from the blacklist" tone="amber" icon={<Lock className="w-4 h-4" />} />
        <Tile label="Who enforces" value={c.mode === 'crowdsec' ? 'CrowdSec' : 'Both'} sub={c.mode === 'crowdsec' ? `${c.imported || 0} bans imported` : 'side by side'} tone="indigo" icon={<ShieldCheck className="w-4 h-4" />} />
        <Tile label="Last sync" value={c.lastSync ? new Date(c.lastSync).toLocaleTimeString() : '—'} sub={c.lastError ? 'last run failed' : c.syncTrusted ? 'trusted lists in step' : 'trusted sync off'} tone={c.lastError ? 'rose' : 'sky'} icon={<RefreshCw className="w-4 h-4" />} />
      </div>
      {c.lastError && <Problem text={c.lastError} />}

      <Card title="Working together" icon={<Workflow className="w-4 h-4 text-indigo-300" />}>
        <div className="grid sm:grid-cols-2 gap-3">
          {([['side-by-side', 'Side by side', 'netfilter bans brute-forcers in its own firewall chain; CrowdSec bans in DOCKER-USER. Two independent guards.'],
            ['crowdsec', 'CrowdSec enforces', "netfilter keeps detecting, but hands its bans to CrowdSec (mailcow's \"manage externally\"). Every ban appears in Banned from the Herd, follows your ban ladder and your allowlist."]] as const).map(([id, title, text]) => (
            <button key={id} onClick={() => setMode(id)} className={`text-left rounded-xl border p-3 cursor-pointer transition-colors ${mode === id ? 'border-indigo-400 bg-indigo-500/10' : 'border-slate-800 hover:border-slate-600'}`}>
              <p className="text-sm font-semibold text-white">{title}</p>
              <p className="text-xs text-slate-400 mt-1">{text}</p>
            </button>
          ))}
        </div>
        <Switch value={sync} onChange={setSync} label="Keep netfilter's whitelist in step with Trusted Herd and your local network" />
        <div className="flex items-center gap-3">
          <button disabled={!changed} onClick={() => run(async () => { await send('PUT', '/api/mailcow/netfilter/coordination', { mode, syncTrusted: sync }); return mode === 'crowdsec' ? 'CrowdSec now enforces netfilter bans' : 'Both guards ban side by side'; }, reload)}
            className={`${btn} bg-indigo-600 hover:bg-indigo-500 text-white`}><Save className="w-3.5 h-3.5" /> Apply</button>
          <p className="text-[11px] text-slate-500">Lifting a ban in Banned from the Herd also lifts it here. Changes sync every minute.</p>
        </div>
      </Card>

      <Card title={`Banned by netfilter (${active.length + perm.length})`} icon={<Dog className="w-4 h-4 text-rose-300" />}>
        <div className="flex gap-2">
          <input className={`${input} flex-1`} value={net} onChange={(e) => setNet(e.target.value.trim())} placeholder="IP or network, e.g. 203.0.113.7 or 203.0.113.0/24" />
          {(['unban', 'whitelist', 'blacklist'] as const).map((a) => (
            <button key={a} disabled={!net} onClick={() => run(() => send('POST', `/api/mailcow/netfilter/${a}`, { network: net }), () => { setNet(''); reload(); })}
              className={`${btn} ${a === 'blacklist' ? 'bg-rose-700 hover:bg-rose-600' : a === 'whitelist' ? 'bg-emerald-700 hover:bg-emerald-600' : 'bg-slate-700 hover:bg-slate-600'} text-white capitalize`}>{a}</button>
          ))}
        </div>
        <table className="w-full text-sm"><tbody>
          {active.map((b) => (
            <tr key={b.network} className="border-t border-slate-800/70">
              <td className="py-2 font-mono text-xs text-white">{b.network}</td>
              <td className="text-xs text-slate-400">{b.queued_for_unban ? 'being lifted…' : `${b.banned_until} left`}</td>
              <td className="text-right">
                <button onClick={() => run(() => send('POST', '/api/mailcow/netfilter/unban', { network: b.network }), reload)} className={`${btn} text-slate-300 hover:bg-slate-800`}>Unban</button>
                <Confirm label="Always trust this network" danger={false} onConfirm={() => run(() => send('POST', '/api/mailcow/netfilter/whitelist', { network: b.network }), reload)}><ShieldCheck className="w-3.5 h-3.5" /></Confirm>
              </td>
            </tr>
          ))}
          {perm.map((b) => (
            <tr key={'p' + b.network} className="border-t border-slate-800/70">
              <td className="py-2 font-mono text-xs text-white">{b.network}</td>
              <td className="text-xs text-rose-300">permanent</td>
              <td />
            </tr>
          ))}
          {!active.length && !perm.length && <tr><td className="text-sm text-slate-500 py-2">Nobody in the doghouse.</td></tr>}
        </tbody></table>
      </Card>

      <NetfilterLog />

      <Card title="Ban settings" icon={<Gauge className="w-4 h-4 text-amber-300" />}>
        <div className="grid sm:grid-cols-3 lg:grid-cols-4 gap-3 text-xs">
          {num('max_attempts', 'Failures before a ban', 'count')}
          {num('retry_window', 'Within', 'seconds')}
          {num('ban_time', 'Ban for', 'seconds')}
          {num('max_ban_time', 'Longest ban', 'seconds')}
          {num('netban_ipv4', 'Ban IPv4 as', 'prefix /8–/32')}
          {num('netban_ipv6', 'Ban IPv6 as', 'prefix /8–/128')}
        </div>
        <Switch value={on(s.ban_time_increment)} onChange={(v) => setS({ ...s, ban_time_increment: v })} label="Double the ban each time an address comes back" />
        <div className="grid sm:grid-cols-2 gap-3 text-xs">
          <Field label="Whitelist (one per line)"><textarea className={`${input} h-24 font-mono`} value={s.whitelist || ''} onChange={(e) => setS({ ...s, whitelist: e.target.value })} /></Field>
          <Field label="Blacklist (permanent bans)"><textarea className={`${input} h-24 font-mono`} value={s.blacklist || ''} onChange={(e) => setS({ ...s, blacklist: e.target.value })} /></Field>
        </div>
        <button onClick={() => run(() => send('PUT', '/api/mailcow/netfilter/settings', { ban_time: Number(s.ban_time), max_ban_time: Number(s.max_ban_time), ban_time_increment: on(s.ban_time_increment), max_attempts: Number(s.max_attempts), retry_window: Number(s.retry_window), netban_ipv4: Number(s.netban_ipv4), netban_ipv6: Number(s.netban_ipv6), whitelist: s.whitelist || '', blacklist: s.blacklist || '' }), reload)} className={`${btn} bg-indigo-600 hover:bg-indigo-500 text-white`}><Save className="w-3.5 h-3.5" /> Save settings</button>
      </Card>
    </div>
  );
}

function NetfilterLog() {
  const { data } = useApi<{ time: number | string; priority: string; message: string }[] | Record<string, never>>('/api/mailcow/logs/netfilter?count=40');
  const rows = list<{ time: number | string; priority: string; message: string }>(data);
  return (
    <Card title="Recent netfilter activity" icon={<Dog className="w-4 h-4 text-orange-300" />}>
      {!rows.length ? <p className="text-sm text-slate-500">No recent entries.</p> : (
        <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-[11px]">
          {rows.map((r, i) => (
            <div key={i} className="flex gap-3">
              <span className="text-slate-500 shrink-0">{new Date(Number(r.time) * 1000).toLocaleString()}</span>
              <span className={/crit|warn/i.test(r.priority) ? 'text-amber-300' : 'text-slate-300'}>{r.message}</span>
            </div>
          ))}
        </div>
      )}
      <p className="text-[11px] text-slate-500">netfilter never bans private (LAN) addresses, and CrowdSec often bans an attacker first, so an empty ban list on a quiet day is normal.</p>
    </Card>
  );
}
