// Modals for The Farm: add/edit mailboxes, domains and aliases with mailcow's full set of
// options, and a DNS checklist per domain (what mailcow needs vs. what DNS answers).
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import {
  AlertTriangle, AtSign, Ban, CheckCircle2, CircleDashed, Copy, Download, Eye, EyeOff, FileSignature, Gauge, Globe, KeyRound, Lock, Mail, RefreshCw, Server, Settings2, Shield, Signature, Sparkles, Ticket, X, XCircle,
} from 'lucide-react';
import { AliasDomainsTab, AppPasswordsTab, DisposableTab, DkimCard, FooterTab, SenderListsTab, SpamScoreTab, Tabs } from './MailcowExtras';
import { SecurityTab } from './MailcowSecurity';
import { MtaStsTab } from './MailcowDeliver';
import Select from './Select';
import { btn, input, send, useApi } from './MailcowPanels';

type Run = (fn: () => Promise<string>, after?: () => void) => Promise<void>;

// ---------------------------------------------------------------- building blocks

export function Modal({ title, sub, icon, onClose, children, footer, wide }: { title: string; sub?: string; icon?: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', esc);
    return () => window.removeEventListener('keydown', esc);
  }, [onClose]);
  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-start sm:items-center justify-center p-4 bg-slate-950/70 backdrop-blur-sm cs-page" onMouseDown={onClose}>
      <div onMouseDown={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label={title}
        className={`w-full ${wide ? 'max-w-5xl' : 'max-w-3xl'} max-h-[90vh] flex flex-col rounded-3xl border border-slate-700/80 bg-slate-900 shadow-2xl shadow-black/50 cs-pop`}>
        <div className="flex items-start gap-3 px-6 py-4 border-b border-slate-800">
          {icon && <span className="w-9 h-9 rounded-xl flex items-center justify-center bg-sky-500/15 text-sky-300 shrink-0">{icon}</span>}
          <div className="flex-1 min-w-0">
            <h3 className="text-lg font-bold text-white truncate">{title}</h3>
            {sub && <p className="text-xs text-slate-400">{sub}</p>}
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer" aria-label="Close"><X className="w-5 h-5" /></button>
        </div>
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">{children}</div>
        {footer && <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-slate-800">{footer}</div>}
      </div>
    </div>,
    document.body,
  );
}

export function Section({ title, icon, children }: { title: string; icon: ReactNode; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <h4 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400">{icon}{title}</h4>
      {children}
    </section>
  );
}

export function Labelled({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1 min-w-0">
      <span className="text-xs font-semibold text-slate-300">{label}</span>
      {children}
      {hint && <span className="text-[11px] text-slate-500">{hint}</span>}
    </label>
  );
}

export function Segmented<T extends string>({ value, onChange, options }: { value: T; onChange: (v: T) => void; options: [T, string][] }) {
  return (
    <div className="inline-flex flex-wrap self-start w-fit rounded-xl border border-slate-700 bg-slate-950/60 p-0.5">
      {options.map(([v, l]) => (
        <button key={v} type="button" onClick={() => onChange(v)}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer transition-colors ${value === v ? 'bg-sky-600 text-white shadow' : 'text-slate-400 hover:text-white'}`}>{l}</button>
      ))}
    </div>
  );
}

export function SwitchRow({ value, onChange, label, hint }: { value: boolean; onChange: (v: boolean) => void; label: string; hint?: string }) {
  return (
    <button type="button" onClick={() => onChange(!value)} className="w-full flex items-start gap-3 text-left cursor-pointer group">
      <span className={`mt-0.5 w-9 h-5 rounded-full relative shrink-0 transition-colors ${value ? 'bg-emerald-500' : 'bg-slate-700'}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${value ? 'left-4.5' : 'left-0.5'}`} />
      </span>
      <span>
        <span className="block text-sm text-slate-200 group-hover:text-white">{label}</span>
        {hint && <span className="block text-[11px] text-slate-500">{hint}</span>}
      </span>
    </button>
  );
}

export function Chips<T extends string>({ value, onChange, options }: { value: T[]; onChange: (v: T[]) => void; options: [T, string][] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {options.map(([v, l]) => {
        const on = value.includes(v);
        return (
          <button key={v} type="button" onClick={() => onChange(on ? value.filter((x) => x !== v) : [...value, v])}
            className={`px-2.5 py-1 rounded-lg text-xs font-semibold border cursor-pointer transition-colors ${on ? 'border-emerald-500/50 bg-emerald-500/15 text-emerald-200' : 'border-slate-700 text-slate-500 hover:text-slate-300'}`}>{l}</button>
        );
      })}
    </div>
  );
}

export function TagInput({ value, onChange, placeholder = 'Add a tag and press Enter' }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [draft, setDraft] = useState('');
  const add = () => {
    const t = draft.trim();
    if (t && !value.includes(t)) onChange([...value, t]);
    setDraft('');
  };
  return (
    <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950/60 px-2 py-1.5 min-h-[38px]">
      {value.map((t) => (
        <span key={t} className="inline-flex items-center gap-1 rounded-md bg-sky-500/15 text-sky-200 text-xs px-2 py-0.5">
          {t}<button type="button" onClick={() => onChange(value.filter((x) => x !== t))} className="cursor-pointer opacity-70 hover:opacity-100"><X className="w-3 h-3" /></button>
        </span>
      ))}
      <input value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); } }} onBlur={add}
        placeholder={value.length ? '' : placeholder} className="flex-1 min-w-[120px] bg-transparent text-sm text-white focus:outline-none" />
    </div>
  );
}

const genPw = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b % 56]).join('');
const yes = (v: unknown) => v === 1 || v === '1' || v === true;

function PasswordField({ value, onChange, optional }: { value: string; onChange: (v: string) => void; optional?: boolean }) {
  const [show, setShow] = useState(!optional);
  return (
    <div className="flex gap-1.5">
      <input className={`${input} flex-1 font-mono`} type={show ? 'text' : 'password'} value={value} onChange={(e) => onChange(e.target.value)} placeholder={optional ? 'Leave empty to keep the current password' : ''} autoComplete="new-password" />
      <button type="button" onClick={() => setShow(!show)} className={`${btn} border border-slate-700 text-slate-300`} title={show ? 'Hide' : 'Show'}>{show ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}</button>
      <button type="button" onClick={() => { onChange(genPw()); setShow(true); }} className={`${btn} border border-slate-700 text-slate-300`} title="Generate"><Sparkles className="w-3.5 h-3.5" /></button>
      <button type="button" onClick={() => navigator.clipboard?.writeText(value)} className={`${btn} border border-slate-700 text-slate-300`} title="Copy"><Copy className="w-3.5 h-3.5" /></button>
    </div>
  );
}

// ---------------------------------------------------------------- mailbox

export interface DomainLite { domain_name: string; max_quota_for_mbox?: number | string; def_new_mailbox_quota?: number | string }
interface MailboxDetail { username: string; name: string; quota: number | string; active: number | string; attributes?: Record<string, string>; tags?: string[]; sender_acl?: string[] }

const PROTOCOLS: ['imap' | 'pop3' | 'smtp' | 'sieve' | 'eas' | 'dav', string][] = [['imap', 'IMAP'], ['pop3', 'POP3'], ['smtp', 'SMTP'], ['sieve', 'Sieve'], ['eas', 'ActiveSync'], ['dav', 'CalDAV / CardDAV']];

export function MailboxModal({ domains, username, onClose, onSaved, run }: { domains: DomainLite[]; username?: string; onClose: () => void; onSaved: () => void; run: Run }) {
  const editing = !!username;
  const existing = useApi<MailboxDetail>(editing ? `/api/mailcow/mailboxes/${encodeURIComponent(username!)}` : null);
  const relays = useApi<{ id: number; hostname: string }[] | Record<string, never>>('/api/mailcow/relayhosts');
  const [f, setF] = useState({
    local_part: '', domain: domains[0]?.domain_name || '', name: '', password: editing ? '' : genPw(), quota: Number(domains[0]?.def_new_mailbox_quota || 3221225472) / 1048576,
    active: true, force_pw_update: false, force_tfa: false, tls_enforce_in: false, tls_enforce_out: false, sogo_access: true,
    send_mode: 'own' as 'own' | 'some' | 'any', sender_acl: [] as string[],
    protocols: ['imap', 'pop3', 'smtp', 'sieve', 'eas', 'dav'] as string[], tags: [] as string[], tagged_mail_handler: 'none',
    quarantine_notification: 'hourly', quarantine_category: 'reject', relayhost: '0',
  });
  const [dirty, setDirty] = useState<Record<string, boolean>>({});
  const set = (patch: Partial<typeof f>) => {
    setF({ ...f, ...patch });
    setDirty({ ...dirty, ...Object.fromEntries(Object.keys(patch).map((k) => [k, true])) });
  };
  useEffect(() => {
    const m = existing.data;
    if (!m) return;
    const a = m.attributes || {};
    setF((p) => ({
      ...p, name: m.name || '', quota: Number(m.quota || 0) / 1048576, active: yes(m.active), force_pw_update: yes(a.force_pw_update), force_tfa: yes(a.force_tfa),
      send_mode: (m.sender_acl || []).includes('*') ? 'any' : (m.sender_acl || []).length ? 'some' : 'own', sender_acl: (m.sender_acl || []).filter((x) => x !== '*'),
      tls_enforce_in: yes(a.tls_enforce_in), tls_enforce_out: yes(a.tls_enforce_out), sogo_access: yes(a.sogo_access),
      protocols: PROTOCOLS.map(([k]) => k).filter((k) => yes(a[`${k}_access`])), tags: m.tags || [],
      quarantine_notification: a.quarantine_notification || 'hourly', quarantine_category: a.quarantine_category || 'reject', relayhost: String(a.relayhost || '0'),
    }));
  }, [existing.data]);
  const dom = domains.find((d) => d.domain_name === f.domain);
  const maxQ = dom?.max_quota_for_mbox ? Number(dom.max_quota_for_mbox) / 1048576 : 0;
  const save = () => {
    const all: Record<string, unknown> = {
      name: f.name, quota: Math.round(f.quota), active: f.active, force_pw_update: f.force_pw_update, force_tfa: f.force_tfa, tls_enforce_in: f.tls_enforce_in, tls_enforce_out: f.tls_enforce_out,
      sender_acl: f.send_mode === 'any' ? ['*'] : f.send_mode === 'some' ? f.sender_acl : [],
      sogo_access: f.sogo_access, protocols: f.protocols, tags: f.tags, tagged_mail_handler: f.tagged_mail_handler,
      quarantine_notification: f.quarantine_notification, quarantine_category: f.quarantine_category, relayhost: Number(f.relayhost),
    };
    if (f.password) all.password = f.password;
    if (editing) {
      const body = Object.fromEntries(Object.entries(all).filter(([k]) => dirty[k] || (k === 'sender_acl' && dirty.send_mode)));
      return run(() => send('PATCH', `/api/mailcow/mailboxes/${encodeURIComponent(username!)}`, body), () => { onSaved(); onClose(); });
    }
    return run(() => send('POST', '/api/mailcow/mailboxes', { ...all, local_part: f.local_part, domain: f.domain }), () => { onSaved(); onClose(); });
  };
  const relayList = Array.isArray(relays.data) ? relays.data : [];
  const [tab, setTab] = useState<'settings' | 'security' | 'spam' | 'apps' | 'disposable' | 'senders'>('settings');
  const valid = editing ? (!f.password || f.password.length >= 10) : !!f.local_part && !!f.domain && f.password.length >= 10;
  return (
    <Modal wide={editing} title={editing ? `Edit ${username}` : 'New stall (mailbox)'} sub={editing ? 'Settings, security, spam filter, app passwords and disposable addresses' : 'Every option mailcow offers when you add a mailbox'} icon={<Mail className="w-5 h-5" />} onClose={onClose}
      footer={tab === 'settings' ? <><button onClick={onClose} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
        <button disabled={!valid} onClick={save} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>{editing ? 'Save changes' : 'Create mailbox'}</button></> : undefined}>
      {editing && <Tabs value={tab} onChange={setTab} tabs={[['settings', 'Settings', <Settings2 key="s" className="w-3.5 h-3.5" />], ['security', 'Security', <Shield key="sec" className="w-3.5 h-3.5" />], ['spam', 'Spam filter', <Gauge key="g" className="w-3.5 h-3.5" />],
        ['apps', 'App passwords', <KeyRound key="k" className="w-3.5 h-3.5" />], ['disposable', 'Disposable addresses', <Ticket key="t" className="w-3.5 h-3.5" />], ['senders', 'Allow / block senders', <Ban key="b" className="w-3.5 h-3.5" />]]} />}
      {editing && tab === 'security' && <SecurityTab user={username!} run={run} />}
      {editing && tab === 'spam' && <SpamScoreTab user={username!} run={run} />}
      {editing && tab === 'apps' && <AppPasswordsTab user={username!} run={run} />}
      {editing && tab === 'disposable' && <DisposableTab user={username!} domains={domains.map((d) => d.domain_name)} run={run} />}
      {editing && tab === 'senders' && <SenderListsTab scope="mailbox" target={username!} run={run} />}
      {tab !== 'settings' ? null : editing && !existing.data ? <p className="text-sm text-slate-400">Loading…</p> : (
        <>
          <Section title="Account" icon={<Mail className="w-3.5 h-3.5" />}>
            {!editing && (
              <Labelled label="Address" hint="The part before the @, and the domain it belongs to.">
                <div className="flex items-center gap-2">
                  <input className={`${input} flex-1`} value={f.local_part} onChange={(e) => set({ local_part: e.target.value.trim().toLowerCase() })} placeholder="alice" />
                  <span className="text-slate-500">@</span>
                  <Select className="flex-1" value={f.domain} onChange={(v) => set({ domain: v })} searchable={domains.length > 8}
                    options={domains.map((d) => ({ value: d.domain_name, label: d.domain_name }))} ariaLabel="Domain" />
                </div>
              </Labelled>
            )}
            <div className="grid sm:grid-cols-2 gap-3">
              <Labelled label="Full name"><input className={input} value={f.name} onChange={(e) => set({ name: e.target.value })} placeholder="Alice Example" /></Labelled>
              <Labelled label={editing ? 'New password' : 'Password'} hint="10 characters or more.">
                <PasswordField value={f.password} onChange={(v) => set({ password: v })} optional={editing} />
              </Labelled>
            </div>
            <SwitchRow value={f.force_pw_update} onChange={(v) => set({ force_pw_update: v })} label="Ask them to change the password at next sign-in" />
            <SwitchRow value={f.force_tfa} onChange={(v) => set({ force_tfa: v })} label="Require two-factor sign-in" hint="They must set up an authenticator or security key before they can use webmail or settings. Mail apps keep working with app passwords." />
            <SwitchRow value={f.active} onChange={(v) => set({ active: v })} label="Active" hint="Inactive mailboxes keep their mail but can't sign in or receive." />
          </Section>
          <Section title="Storage and tags" icon={<Server className="w-3.5 h-3.5" />}>
            <div className="grid sm:grid-cols-2 gap-3">
              <Labelled label="Quota (MiB)" hint={maxQ ? `Up to ${maxQ.toLocaleString()} MiB in this domain · 0 = unlimited` : '0 = unlimited'}>
                <input type="number" min={0} className={input} value={f.quota} onChange={(e) => set({ quota: Math.max(0, +e.target.value) })} />
              </Labelled>
              <Labelled label="Tags" hint="Your own labels, for searching."><TagInput value={f.tags} onChange={(v) => set({ tags: v })} /></Labelled>
            </div>
          </Section>
          <Section title="Delivery" icon={<Sparkles className="w-3.5 h-3.5" />}>
            <Labelled label="Tagged mail (me+news@example.org)" hint="Where mail sent to a +tag address goes.">
              <Segmented value={f.tagged_mail_handler} onChange={(v) => set({ tagged_mail_handler: v })} options={[['subfolder', 'Into a subfolder'], ['subject', 'Tag in the subject'], ['none', 'Do nothing']]} />
            </Labelled>
            {relayList.length > 0 && (
              <Labelled label="Send through a relay host">
                <Select value={f.relayhost} onChange={(v) => set({ relayhost: v })} options={[{ value: '0', label: 'Use the domain setting' }, ...relayList.map((r) => ({ value: String(r.id), label: `#${r.id} ${r.hostname}` }))]} />
              </Labelled>
            )}
          </Section>
          <Section title="Sending as" icon={<AtSign className="w-3.5 h-3.5" />}>
            <Labelled label="Which From addresses it may use" hint="Its own address and the aliases that deliver to it are always allowed.">
              <Segmented value={f.send_mode} onChange={(v) => set({ send_mode: v })} options={[['own', 'Only its own'], ['some', 'Also these…'], ['any', 'Any address']]} />
            </Labelled>
            {f.send_mode === 'some' && (
              <Labelled label="Also allowed to send as" hint="Addresses (sales@example.org) or whole domains (@example.org).">
                <TagInput value={f.sender_acl} onChange={(v) => set({ sender_acl: v, send_mode: 'some' })} placeholder="sales@example.org or @example.org, then Enter" />
              </Labelled>
            )}
            {f.send_mode === 'any' && <p className="text-[11px] text-amber-300/90 flex items-center gap-1.5"><AlertTriangle className="w-3.5 h-3.5" /> It can send as anyone, on any domain. Only for a trusted system mailbox such as a ticketing system.</p>}
          </Section>
          <Section title="Quarantine notifications" icon={<AlertTriangle className="w-3.5 h-3.5" />}>
            <div className="grid sm:grid-cols-2 gap-3">
              <Labelled label="How often"><Segmented value={f.quarantine_notification} onChange={(v) => set({ quarantine_notification: v })} options={[['never', 'Never'], ['hourly', 'Hourly'], ['daily', 'Daily'], ['weekly', 'Weekly']]} /></Labelled>
              <Labelled label="About"><Segmented value={f.quarantine_category} onChange={(v) => set({ quarantine_category: v })} options={[['reject', 'Rejected'], ['add_header', 'Junk folder'], ['all', 'Everything']]} /></Labelled>
            </div>
          </Section>
          <Section title="Security and access" icon={<Shield className="w-3.5 h-3.5" />}>
            <div className="grid sm:grid-cols-2 gap-2">
              <SwitchRow value={f.tls_enforce_in} onChange={(v) => set({ tls_enforce_in: v })} label="Require TLS for incoming mail" />
              <SwitchRow value={f.tls_enforce_out} onChange={(v) => set({ tls_enforce_out: v })} label="Require TLS for outgoing mail" />
            </div>
            <Labelled label="Allowed protocols" hint="App passwords are not affected."><Chips value={f.protocols} onChange={(v) => set({ protocols: v })} options={PROTOCOLS} /></Labelled>
            <SwitchRow value={f.sogo_access} onChange={(v) => set({ sogo_access: v })} label="Webmail (SOGo)" />
          </Section>
        </>
      )}
    </Modal>
  );
}

// ---------------------------------------------------------------- domain

interface DomainDetail {
  domain_name: string; description?: string; active?: unknown; max_num_mboxes_for_domain?: number; max_num_aliases_for_domain?: number;
  def_new_mailbox_quota?: number | string; max_quota_for_mbox?: number | string; max_quota_for_domain?: number | string; backupmx?: unknown;
  relay_all_recipients?: unknown; relay_unknown_only?: unknown; gal?: unknown; tags?: string[];
}

export function DomainModal({ domain, onClose, onSaved, run }: { domain?: DomainDetail; onClose: () => void; onSaved: () => void; run: Run }) {
  const editing = !!domain;
  const mib = (v: unknown, d: number) => (v == null ? d : Math.round(Number(v) / 1048576));
  const [f, setF] = useState({
    domain: domain?.domain_name || '', description: domain?.description || '', active: domain ? yes(domain.active) : true,
    mailboxes: domain?.max_num_mboxes_for_domain ?? 10, aliases: domain?.max_num_aliases_for_domain ?? 400,
    defquota: mib(domain?.def_new_mailbox_quota, 3072), maxquota: mib(domain?.max_quota_for_mbox, 10240), quota: mib(domain?.max_quota_for_domain, 10240),
    backupmx: yes(domain?.backupmx), relay_all_recipients: yes(domain?.relay_all_recipients), relay_unknown_only: yes(domain?.relay_unknown_only),
    gal: domain ? yes(domain.gal) : true, tags: domain?.tags || [], rl_value: 0, rl_frame: 'h',
  });
  const [tab, setTab] = useState<'settings' | 'footer' | 'aliases' | 'senders' | 'mtasts'>('settings');
  const set = (p: Partial<typeof f>) => setF({ ...f, ...p });
  const body = { description: f.description, active: f.active, mailboxes: f.mailboxes, aliases: f.aliases, defquota: f.defquota, maxquota: f.maxquota, quota: f.quota,
    backupmx: f.backupmx, relay_all_recipients: f.relay_all_recipients, relay_unknown_only: f.relay_unknown_only, gal: f.gal, tags: f.tags };
  const save = () => (editing
    ? run(() => send('PATCH', `/api/mailcow/domains/${f.domain}`, body), () => { onSaved(); onClose(); })
    : run(() => send('POST', '/api/mailcow/domains', { ...body, domain: f.domain, ...(f.rl_value > 0 ? { rl_value: f.rl_value, rl_frame: f.rl_frame } : {}) }), () => { onSaved(); onClose(); }));
  const n = (k: 'mailboxes' | 'aliases' | 'defquota' | 'maxquota' | 'quota', label: string, hint?: string) => (
    <Labelled label={label} hint={hint}><input type="number" min={0} className={input} value={f[k]} onChange={(e) => set({ [k]: Math.max(0, +e.target.value) } as Partial<typeof f>)} /></Labelled>
  );
  return (
    <Modal title={editing ? `Edit ${f.domain}` : 'New paddock (domain)'} sub={editing ? 'Limits, footer, alias domains, sender lists and MTA-STS' : 'Limits, quotas and relay options'} icon={<Globe className="w-5 h-5" />} onClose={onClose}
      footer={tab === 'settings' ? <><button onClick={onClose} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
        <button disabled={!f.domain} onClick={save} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>{editing ? 'Save changes' : 'Create domain'}</button></> : undefined}>
      {editing && <Tabs value={tab} onChange={setTab} tabs={[['settings', 'Settings', <Settings2 key="s" className="w-3.5 h-3.5" />], ['footer', 'Footer', <FileSignature key="f" className="w-3.5 h-3.5" />],
        ['aliases', 'Alias domains', <AtSign key="a" className="w-3.5 h-3.5" />], ['senders', 'Allow / block senders', <Ban key="b" className="w-3.5 h-3.5" />], ['mtasts', 'MTA-STS', <Lock key="m" className="w-3.5 h-3.5" />]]} />}
      {editing && tab === 'mtasts' && <MtaStsTab domain={f.domain} run={run} />}
      {editing && tab === 'footer' && <FooterTab domain={f.domain} run={run} />}
      {editing && tab === 'aliases' && <AliasDomainsTab domain={f.domain} run={run} />}
      {editing && tab === 'senders' && <SenderListsTab scope="domain" target={f.domain} run={run} />}
      {tab === 'settings' && <>
      <Section title="Domain" icon={<Globe className="w-3.5 h-3.5" />}>
        <div className="grid sm:grid-cols-2 gap-3">
          {!editing && <Labelled label="Domain name"><input className={input} value={f.domain} onChange={(e) => set({ domain: e.target.value.trim().toLowerCase() })} placeholder="example.org" /></Labelled>}
          <Labelled label="Description"><input className={input} value={f.description} onChange={(e) => set({ description: e.target.value })} /></Labelled>
          <Labelled label="Tags"><TagInput value={f.tags} onChange={(v) => set({ tags: v })} /></Labelled>
        </div>
        <SwitchRow value={f.active} onChange={(v) => set({ active: v })} label="Active" />
      </Section>
      <Section title="Limits and quotas" icon={<Server className="w-3.5 h-3.5" />}>
        <div className="grid sm:grid-cols-3 gap-3">
          {n('mailboxes', 'Max mailboxes')}
          {n('aliases', 'Max aliases')}
          {n('quota', 'Domain quota (MiB)', 'Total for all mailboxes')}
          {n('defquota', 'New mailbox quota (MiB)', 'The default when adding one')}
          {n('maxquota', 'Max per mailbox (MiB)')}
          {!editing && (
            <Labelled label="Sending limit" hint="Messages for the whole domain · 0 = no limit">
              <div className="flex gap-1.5">
                <input type="number" min={0} className={`${input} w-24`} value={f.rl_value} onChange={(e) => set({ rl_value: Math.max(0, +e.target.value) })} />
                <Segmented value={f.rl_frame} onChange={(v) => set({ rl_frame: v })} options={[['m', '/min'], ['h', '/hour'], ['d', '/day']]} />
              </div>
            </Labelled>
          )}
        </div>
      </Section>
      <Section title="Relay and directory" icon={<Shield className="w-3.5 h-3.5" />}>
        <SwitchRow value={f.gal} onChange={(v) => set({ gal: v })} label="Global address list" hint="Users of this domain see each other in webmail and ActiveSync." />
        <SwitchRow value={f.backupmx} onChange={(v) => set({ backupmx: v })} label="Relay this domain (backup MX)" hint="Accept mail for it and pass it on to its real server." />
        {f.backupmx && (
          <div className="pl-12 space-y-2 cs-page">
            <SwitchRow value={f.relay_all_recipients} onChange={(v) => set({ relay_all_recipients: v })} label="Relay all recipients" hint="Accept any address at this domain, not just known ones." />
            <SwitchRow value={f.relay_unknown_only} onChange={(v) => set({ relay_unknown_only: v })} label="Relay only addresses with no mailbox here" />
          </div>
        )}
      </Section>
      </>}
    </Modal>
  );
}

// ---------------------------------------------------------------- alias

interface AliasDetail { id: number; address: string; goto: string; active: unknown; sogo_visible?: unknown; internal?: unknown; private_comment?: string; public_comment?: string }

export function AliasModal({ alias, onClose, onSaved, run }: { alias?: AliasDetail; onClose: () => void; onSaved: () => void; run: Run }) {
  const editing = !!alias;
  const mode0 = alias?.goto === 'null@localhost' ? 'discard' : alias?.goto === 'spam@localhost' ? 'spam' : alias?.goto === 'ham@localhost' ? 'ham' : 'addresses';
  const [f, setF] = useState({
    address: alias?.address || '', goto: mode0 === 'addresses' ? (alias?.goto || '').split(',').join(', ') : '', goto_mode: mode0 as 'addresses' | 'discard' | 'spam' | 'ham',
    active: alias ? yes(alias.active) : true, sogo_visible: alias ? yes(alias.sogo_visible) : true, internal: yes(alias?.internal),
    private_comment: alias?.private_comment || '', public_comment: alias?.public_comment || '',
  });
  const set = (p: Partial<typeof f>) => setF({ ...f, ...p });
  const body = { goto: f.goto, goto_mode: f.goto_mode, active: f.active, sogo_visible: f.sogo_visible, internal: f.internal, private_comment: f.private_comment, public_comment: f.public_comment };
  const save = () => (editing
    ? run(() => send('PATCH', `/api/mailcow/aliases/${alias!.id}`, body), () => { onSaved(); onClose(); })
    : run(() => send('POST', '/api/mailcow/aliases', { ...body, address: f.address }), () => { onSaved(); onClose(); }));
  return (
    <Modal title={editing ? `Edit ${f.address}` : 'New ear tag (alias)'} sub="Forward an address, or catch everything at a domain with @example.org" icon={<Mail className="w-5 h-5" />} onClose={onClose}
      footer={<><button onClick={onClose} className={`${btn} text-slate-400 hover:text-white`}>Cancel</button>
        <button disabled={!f.address || (f.goto_mode === 'addresses' && !f.goto)} onClick={save} className={`${btn} bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2`}>{editing ? 'Save changes' : 'Create alias'}</button></>}>
      <Section title="Address" icon={<Mail className="w-3.5 h-3.5" />}>
        {!editing && <Labelled label="Alias address" hint="Or @example.org for a catch-all."><input className={input} value={f.address} onChange={(e) => set({ address: e.target.value.trim().toLowerCase() })} placeholder="sales@example.org" /></Labelled>}
        <Labelled label="Mail to this address">
          <Segmented value={f.goto_mode} onChange={(v) => set({ goto_mode: v })} options={[['addresses', 'Deliver to addresses'], ['discard', 'Silently discard'], ['spam', 'Learn as spam'], ['ham', 'Learn as not spam']]} />
        </Labelled>
        {f.goto_mode === 'addresses' && (
          <Labelled label="Deliver to" hint="One or more addresses, separated by commas.">
            <textarea className={`${input} h-20`} value={f.goto} onChange={(e) => set({ goto: e.target.value })} placeholder="alice@example.org, bob@example.org" />
          </Labelled>
        )}
      </Section>
      <Section title="Options" icon={<Shield className="w-3.5 h-3.5" />}>
        <SwitchRow value={f.active} onChange={(v) => set({ active: v })} label="Active" />
        <SwitchRow value={f.sogo_visible} onChange={(v) => set({ sogo_visible: v })} label="Show in webmail as a sender address" hint="Users it delivers to can send as this alias in SOGo." />
        <SwitchRow value={f.internal} onChange={(v) => set({ internal: v })} label="Internal only" hint="Only accept mail from this server's own users." />
        <div className="grid sm:grid-cols-2 gap-3">
          <Labelled label="Private note" hint="Only admins see it."><input className={input} value={f.private_comment} onChange={(e) => set({ private_comment: e.target.value })} /></Labelled>
          <Labelled label="Public note" hint="Users see it in their settings."><input className={input} value={f.public_comment} onChange={(e) => set({ public_comment: e.target.value })} /></Labelled>
        </div>
      </Section>
    </Modal>
  );
}

// ---------------------------------------------------------------- DNS records

interface Rec { group: string; name: string; type: string; expected: string; current: string[] | null; state: 'ok' | 'mismatch' | 'missing' | 'info'; optional: boolean; help: string }

const GROUPS: Record<string, [string, ReactNode]> = {
  server: ['Your mail server', <Server key="i" className="w-3.5 h-3.5" />], mail: ['Mail delivery', <Mail key="i" className="w-3.5 h-3.5" />],
  policy: ['Sender policy', <Shield key="i" className="w-3.5 h-3.5" />], signing: ['Signing (DKIM)', <Signature key="i" className="w-3.5 h-3.5" />],
  autoconfig: ['Client setup (optional)', <Sparkles key="i" className="w-3.5 h-3.5" />],
};

function StateIcon({ r }: { r: Rec }) {
  if (r.state === 'ok') return <CheckCircle2 className="w-4 h-4 text-emerald-400 cs-pop" />;
  if (r.state === 'info') return <CircleDashed className="w-4 h-4 text-slate-500" />;
  if (r.optional && r.state === 'missing') return <CircleDashed className="w-4 h-4 text-slate-500" />;
  if (r.state === 'mismatch') return <AlertTriangle className="w-4 h-4 text-amber-400" />;
  return <XCircle className="w-4 h-4 text-rose-400" />;
}

function CopyText({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" onClick={() => navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }).catch(() => {})}
      className="p-1 rounded-md text-slate-500 hover:text-white hover:bg-slate-800 cursor-pointer shrink-0" title="Copy">
      {done ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  );
}

export function DnsModal({ domain, domains = [], onClose, run }: { domain: string; domains?: string[]; onClose: () => void; run: Run }) {
  const { data, loading, error, reload } = useApi<{ hostname: string; records: Rec[] }>(`/api/mailcow/dns/${domain}`);
  const recs = data?.records || [];
  const needed = recs.filter((r) => !r.optional && r.state !== 'info');
  const good = needed.filter((r) => r.state === 'ok').length;
  const groups = useMemo(() => [...new Set(recs.map((r) => r.group))], [recs]);
  const zone = recs.filter((r) => r.expected && !r.type.startsWith('A') && r.type !== 'PTR')
    .map((r) => `${r.name}.\t3600\tIN\t${r.type.split(' ')[0]}\t${r.type.startsWith('TXT') ? `"${r.expected}"` : r.expected}${r.type === 'MX' || r.type === 'CNAME' || r.type === 'SRV' ? '.' : ''}`).join('\n');
  const download = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([`; DNS records for ${domain} (CowSec)\n` + zone + '\n'], { type: 'text/plain' }));
    a.download = `${domain}.zone.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };
  const pct = needed.length ? Math.round((good / needed.length) * 100) : 0;
  return (
    <Modal wide title={`DNS records · ${domain}`} sub={`What mailcow needs, checked live against DNS · mail server ${data?.hostname || ''}`} icon={<Globe className="w-5 h-5" />} onClose={onClose}
      footer={<>
        <span className="mr-auto text-[11px] text-slate-500">Changes can take up to a day to show here, depending on each record's TTL.</span>
        <button onClick={reload} className={`${btn} border border-slate-700 text-slate-300`}><RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Check again</button>
        <button onClick={download} disabled={!zone} className={`${btn} bg-sky-600 hover:bg-sky-500 text-white`}><Download className="w-3.5 h-3.5" /> Download as zone file</button>
      </>}>
      {error && <p className="text-sm text-rose-300">{error}</p>}
      {!data ? <p className="flex items-center gap-2 text-sm text-slate-400"><RefreshCw className="w-4 h-4 animate-spin" /> Asking DNS…</p> : (
        <>
          <div className="flex items-center gap-4 rounded-2xl border border-slate-800 bg-slate-950/50 p-4">
            <div className="relative w-14 h-14 shrink-0">
              <svg viewBox="0 0 36 36" className="w-14 h-14 -rotate-90"><circle cx="18" cy="18" r="15.5" fill="none" strokeWidth="3.5" className="stroke-slate-800" />
                <circle cx="18" cy="18" r="15.5" fill="none" strokeWidth="3.5" strokeLinecap="round" stroke={pct === 100 ? '#34d399' : pct > 60 ? '#fbbf24' : '#fb7185'}
                  strokeDasharray={`${(pct / 100) * 97.4} 97.4`} style={{ transition: 'stroke-dasharray .8s ease' }} /></svg>
              <span className="absolute inset-0 flex items-center justify-center text-xs font-bold text-white">{good}/{needed.length}</span>
            </div>
            <div className="text-sm">
              <p className="font-semibold text-white">{good === needed.length ? 'Everything required is in place.' : `${needed.length - good} required record${needed.length - good === 1 ? '' : 's'} need attention.`}</p>
              <p className="text-xs text-slate-400">Records marked optional help mail clients and DANE, but mail works without them.</p>
            </div>
          </div>
          {groups.map((g) => (
            <section key={g} className="space-y-2">
              <h4 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-widest text-slate-400">{GROUPS[g]?.[1]}{GROUPS[g]?.[0] || g}</h4>
              {g === 'signing' && <DkimCard domain={domain} domains={domains} run={run} onChanged={reload} />}
              <div className="rounded-2xl border border-slate-800 divide-y divide-slate-800/80 overflow-hidden cs-stagger">
                {recs.filter((r) => r.group === g).map((r) => (
                  <div key={r.name + r.type} className="grid md:grid-cols-[minmax(0,1.1fr)_80px_minmax(0,1.6fr)_minmax(0,1.3fr)_24px] gap-x-3 gap-y-1 px-4 py-3 text-xs items-start">
                    <div className="flex items-center gap-1 min-w-0"><span className="font-mono text-slate-200 break-all">{r.name}</span><CopyText text={r.name} /></div>
                    <span className="font-mono text-sky-300">{r.type}{r.optional && <span className="block text-[10px] text-slate-500 font-sans">optional</span>}</span>
                    <div className="min-w-0">
                      {r.expected ? (
                        <div className="flex items-start gap-1"><span className="font-mono text-slate-300 break-all leading-relaxed">{r.expected}</span><CopyText text={r.expected} /></div>
                      ) : r.type.startsWith('TXT (DKIM)') ? (
                        <span className="text-slate-500">Create a key above first.</span>
                      ) : <span className="text-slate-500">—</span>}
                      <p className="text-[11px] text-slate-500 mt-1">{r.help}</p>
                    </div>
                    <div className="font-mono text-slate-400 break-all space-y-0.5">{(r.current || []).length ? (r.current || []).map((c) => <div key={c}>{c}</div>) : <span className="text-slate-600">not found</span>}</div>
                    <StateIcon r={r} />
                  </div>
                ))}
              </div>
            </section>
          ))}
        </>
      )}
    </Modal>
  );
}
