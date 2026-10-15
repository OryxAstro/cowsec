import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Globe, Loader2, Mail, Plus, Repeat, Save, ShieldCheck, TrendingUp, X } from 'lucide-react';
import { Card, Tile } from './HostPanel';

interface Policy {
  homeCountries: string[];
  abroad: { enabled: boolean; smtp: boolean; imap: boolean; failures: number; windowHours: number };
  escalation: { enabled: boolean; includeHome?: boolean; baseHours: number; mode: 'linear' | 'double'; maxHours: number; lookbackDays: number };
}
interface PolicyState {
  policy: Policy;
  saved: boolean;
  managed: boolean;
  abroadScenarioInstalled: boolean;
  historyDays: number;
  notifications: string[];
  repeatOffenders: { days: number; ips?: number; histogram?: Record<string, number>; top?: { ip: string; bans: number; last: string }[]; error?: string };
}
interface CountryFailures { code: string; name: string; ips: number; attempts: number; smtpIps: number; imapIps: number; perIp: number[] }
interface Failures { hours: number; countries: CountryFailures[]; ips: number; geo: boolean }

const fmt = (n: number | undefined | null) => (n ?? 0).toLocaleString();
const hours = (h: number) => (h % 24 === 0 && h >= 48 ? `${h / 24}d` : `${h}h`);

// Ban duration for 0, 1, 2... previous bans; same maths as cowsec-hostctl.
function ladder(e: Policy['escalation']): number[] {
  const out: number[] = [];
  for (let k = 0; k < 12; k++) {
    const h = e.mode === 'linear' ? e.baseHours * (k + 1) : e.baseHours * 2 ** k;
    out.push(Math.min(h, e.maxHours));
    if (h >= e.maxHours) break;
  }
  return out;
}

const ordinal = (n: number) => `${n}${n % 10 === 1 && n % 100 !== 11 ? 'st' : n % 10 === 2 && n % 100 !== 12 ? 'nd' : n % 10 === 3 && n % 100 !== 13 ? 'rd' : 'th'}`;

function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      onClick={() => onChange(!on)}
      className={`relative w-11 h-6 rounded-full transition-colors cursor-pointer ${on ? 'bg-emerald-500' : 'bg-slate-700'}`}
    >
      <span className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform ${on ? 'translate-x-5' : ''}`} />
    </button>
  );
}

function NumberField({ label, value, onChange, min, max, suffix, disabled }: { label: string; value: number; onChange: (v: number) => void; min: number; max: number; suffix?: string; disabled?: boolean }) {
  return (
    <label className={`block space-y-1 ${disabled ? 'opacity-50' : ''}`}>
      <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</span>
      <div className="flex items-center space-x-2">
        <input
          type="number"
          min={min}
          max={max}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(Math.round(Number(e.target.value)))}
          className="w-24 bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white font-mono focus:outline-none focus:border-sky-500"
        />
        {suffix && <span className="text-xs text-slate-400">{suffix}</span>}
      </div>
    </label>
  );
}

export default function PolicyPanel() {
  const [state, setState] = useState<PolicyState | null>(null);
  const [draft, setDraft] = useState<Policy | null>(null);
  const [failures, setFailures] = useState<Failures | null>(null);
  const [error, setError] = useState('');
  const [newCountry, setNewCountry] = useState('');
  const [saving, setSaving] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  const load = async () => {
    try {
      const res = await fetch('/api/crowdsec/host/policy', { cache: 'no-store' });
      if (!res.ok) throw new Error(await res.text());
      const st: PolicyState = await res.json();
      setState(st);
      setDraft(st.policy);
      setError('');
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };

  useEffect(() => {
    load();
    fetch('/api/crowdsec/host/auth-failures', { cache: 'no-store' })
      .then((r) => (r.ok ? r.json() : null))
      .then((f) => f && setFailures(f))
      .catch(() => {});
  }, []);

  const dirty = useMemo(() => !!state && !!draft && JSON.stringify(state.policy) !== JSON.stringify(draft), [state, draft]);
  const names = useMemo(() => Object.fromEntries((failures?.countries ?? []).map((c) => [c.code, c.name])), [failures]);

  // IPs from outside the home countries that reached the threshold in the last 24h.
  const caught = (c: CountryFailures, p: Policy) => c.perIp.slice(Math.min(p.abroad.failures, 10) - 1).reduce((a, b) => a + b, 0);
  const abroadRows = (failures?.countries ?? []).filter((c) => draft && c.code !== 'LAN' && c.code !== '??' && !draft.homeCountries.includes(c.code));
  const wouldCatch = draft ? abroadRows.reduce((a, c) => a + caught(c, draft), 0) : 0;
  const abroadIps = abroadRows.reduce((a, c) => a + c.ips, 0);

  if (error && !state) {
    return (
      <div className="flex items-center space-x-2 text-rose-300 bg-rose-950/40 border border-rose-900 rounded-xl p-4 text-sm">
        <AlertTriangle className="w-4 h-4" />
        <span>Couldn't read the herd rules: {error}</span>
      </div>
    );
  }
  if (!state || !draft) {
    return (
      <div className="flex items-center space-x-2 text-slate-400 text-sm p-6">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span>Reading the herd rules…</span>
      </div>
    );
  }

  const set = (fn: (p: Policy) => void) => {
    const next: Policy = JSON.parse(JSON.stringify(draft));
    fn(next);
    setDraft(next);
    setResult(null);
  };
  const addCountry = (code: string) => {
    const c = code.trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(c) || draft.homeCountries.includes(c)) return;
    set((p) => {
      p.homeCountries = [...p.homeCountries, c].sort();
    });
    setNewCountry('');
  };

  const save = async () => {
    setSaving(true);
    setResult(null);
    try {
      const res = await fetch('/api/crowdsec/host/policy', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(draft),
      });
      if (!res.ok) throw new Error(await res.text());
      const r = await res.json();
      setResult({ ok: true, text: `Applied. CrowdSec reloaded${r.ladderHours ? ` · ban ladder ${r.ladderHours.map(hours).join(' → ')}` : ''}.` });
      await load();
    } catch (e) {
      setResult({ ok: false, text: String(e instanceof Error ? e.message : e) });
    } finally {
      setSaving(false);
    }
  };

  const steps = ladder(draft.escalation);
  const ro = state.repeatOffenders;
  const repeatIps = ro.histogram ? (ro.histogram['2'] ?? 0) + (ro.histogram['3-5'] ?? 0) + (ro.histogram['6+'] ?? 0) : 0;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Tile
          label="Failed mail logins"
          value={fmt(failures?.ips)}
          sub={`IPs in the last 24h · ${fmt(failures?.countries.reduce((a, c) => a + c.attempts, 0))} attempts`}
          tone="sky"
          icon={<Mail className="w-4 h-4" />}
        />
        <Tile label="From outside the pasture" value={fmt(abroadIps)} sub={`IPs from outside ${draft.homeCountries.join(', ')}`} tone="amber" icon={<Globe className="w-4 h-4" />} />
        <Tile
          label="Abroad rule would catch"
          value={fmt(wouldCatch)}
          sub={`IPs with ${draft.abroad.failures}+ failures (last 24h)`}
          tone={draft.abroad.enabled ? 'emerald' : 'indigo'}
          icon={<ShieldCheck className="w-4 h-4" />}
        />
        <Tile label="Repeat offenders" value={fmt(repeatIps)} sub={`IPs banned 2+ times in ${ro.days} days`} tone="rose" icon={<Repeat className="w-4 h-4" />} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <Card title="Home pasture (home countries)" icon={<Globe className="w-4 h-4 text-sky-400" />}>
          <p className="text-xs text-slate-400">
            Failed logins from these countries follow CrowdSec's normal rules, so a mistyped password on your phone won't lock you out. Everywhere else gets the stricter rule below.
          </p>
          <div className="flex flex-wrap gap-2">
            {draft.homeCountries.map((c) => (
              <span key={c} className="inline-flex items-center space-x-1.5 bg-sky-950/50 border border-sky-800 text-sky-200 rounded-lg pl-2.5 pr-1 py-1 text-xs font-semibold">
                <span className="font-mono">{c}</span>
                {names[c] && <span className="text-sky-400/80 font-normal">{names[c]}</span>}
                <button
                  onClick={() => set((p) => void (p.homeCountries = p.homeCountries.filter((x) => x !== c)))}
                  disabled={draft.homeCountries.length === 1}
                  className="p-0.5 rounded hover:bg-sky-900 disabled:opacity-30 cursor-pointer"
                  aria-label={`Remove ${c}`}
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}
          </div>
          <form
            className="flex items-center space-x-2"
            onSubmit={(e) => {
              e.preventDefault();
              addCountry(newCountry);
            }}
          >
            <input
              value={newCountry}
              onChange={(e) => setNewCountry(e.target.value.toUpperCase().slice(0, 2))}
              placeholder="e.g. IE"
              className="w-24 bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white font-mono uppercase focus:outline-none focus:border-sky-500"
            />
            <button type="submit" className="inline-flex items-center space-x-1 text-xs font-semibold text-sky-300 border border-sky-800 rounded-lg px-2.5 py-1.5 hover:bg-sky-950 cursor-pointer">
              <Plus className="w-3.5 h-3.5" />
              <span>Add country</span>
            </button>
            <span className="text-[11px] text-slate-500">Two-letter ISO code</span>
          </form>
        </Card>

        <Card
          title="Strict rule for logins from abroad"
          icon={<Mail className="w-4 h-4 text-amber-400" />}
          right={<Toggle on={draft.abroad.enabled} onChange={(v) => set((p) => void (p.abroad.enabled = v))} label="Abroad rule" />}
        >
          <p className="text-xs text-slate-400">
            Password-spraying bots try one or two passwords per IP, too slowly for CrowdSec's stock postfix rule. This bans an IP from outside the home countries after a few failed logins. Only failed <em>logins</em> count: other mail servers delivering to you never log in, so incoming mail and your sender reputation are not affected. LAN addresses are never banned.
          </p>
          <div className={`flex flex-wrap items-end gap-5 ${draft.abroad.enabled ? '' : 'opacity-50'}`}>
            <NumberField label="Ban after" value={draft.abroad.failures} min={1} max={20} suffix="failed logins" onChange={(v) => set((p) => void (p.abroad.failures = v))} />
            <NumberField label="Within about" value={draft.abroad.windowHours} min={1} max={168} suffix="hours" onChange={(v) => set((p) => void (p.abroad.windowHours = v))} />
            <div className="space-y-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Watch</span>
              <div className="flex items-center space-x-4 text-sm text-slate-300">
                <label className="flex items-center space-x-1.5 cursor-pointer">
                  <input type="checkbox" checked={draft.abroad.smtp} onChange={(e) => set((p) => void (p.abroad.smtp = e.target.checked))} />
                  <span>SMTP AUTH</span>
                </label>
                <label className="flex items-center space-x-1.5 cursor-pointer">
                  <input type="checkbox" checked={draft.abroad.imap} onChange={(e) => set((p) => void (p.abroad.imap = e.target.checked))} />
                  <span>IMAP / POP</span>
                </label>
              </div>
            </div>
          </div>
          {draft.abroad.failures === 1 && (
            <p className="text-[11px] text-amber-300 flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>One strike: a single typo while travelling bans that IP. Two or more is kinder.</span>
            </p>
          )}
        </Card>

        <Card
          title="Escalating bans for repeat offenders"
          icon={<TrendingUp className="w-4 h-4 text-rose-400" />}
          right={<Toggle on={draft.escalation.enabled} onChange={(v) => set((p) => void (p.escalation.enabled = v))} label="Escalating bans" />}
        >
          <p className="text-xs text-slate-400">
            Each new ban looks back at how often CrowdSec already banned that IP and gets longer every time. This applies to every scenario (mail, web, WAF, SSH). Being on a community blocklist counts as one earlier ban.
          </p>
          <label className={`flex items-start space-x-2 text-xs text-slate-300 cursor-pointer ${draft.escalation.enabled ? '' : 'opacity-50'}`}>
            <input
              type="checkbox"
              className="mt-0.5"
              checked={!!draft.escalation.includeHome}
              disabled={!draft.escalation.enabled}
              onChange={(e) => set((p) => void (p.escalation.includeHome = e.target.checked))}
            />
            <span>
              Escalate for home-country IPs too. Off by default: a phone or laptop with an old saved password at a customer's house keeps getting short {hours(draft.escalation.baseHours)} bans instead of week-long ones.
            </span>
          </label>
          <div className="flex flex-wrap items-end gap-5">
            <NumberField label={draft.escalation.enabled ? 'First ban' : 'Ban length'} value={draft.escalation.baseHours} min={1} max={168} suffix="hours" onChange={(v) => set((p) => void (p.escalation.baseHours = v))} />
            <label className={`block space-y-1 ${draft.escalation.enabled ? '' : 'opacity-50'}`}>
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">Each repeat</span>
              <select
                value={draft.escalation.mode}
                disabled={!draft.escalation.enabled}
                onChange={(e) => set((p) => void (p.escalation.mode = e.target.value as 'linear' | 'double'))}
                className="block bg-slate-950/60 border border-slate-700 rounded-lg px-2.5 py-1.5 text-sm text-white focus:outline-none focus:border-sky-500"
              >
                <option value="double">doubles the ban</option>
                <option value="linear">adds another first ban</option>
              </select>
            </label>
            <NumberField label="Longest ban" value={draft.escalation.maxHours} min={1} max={720} suffix="hours" disabled={!draft.escalation.enabled} onChange={(v) => set((p) => void (p.escalation.maxHours = v))} />
            <NumberField
              label="Remember bans for"
              value={draft.escalation.lookbackDays}
              min={1}
              max={state.historyDays}
              suffix={`days (max ${state.historyDays})`}
              disabled={!draft.escalation.enabled}
              onChange={(v) => set((p) => void (p.escalation.lookbackDays = v))}
            />
          </div>
          {draft.escalation.enabled && (
            <div className="flex flex-wrap items-center gap-1.5 text-xs">
              {steps.map((h, i) => (
                <span key={i} className="inline-flex items-center space-x-1.5">
                  <span className="bg-rose-950/40 border border-rose-900/70 text-rose-200 rounded-md px-2 py-0.5 font-mono">
                    {ordinal(i + 1)}
                    {i === steps.length - 1 ? '+' : ''}: {hours(h)}
                  </span>
                  {i < steps.length - 1 && <span className="text-slate-600">→</span>}
                </span>
              ))}
            </div>
          )}
        </Card>

        <Card title={`Repeat offenders (last ${ro.days} days)`} icon={<Repeat className="w-4 h-4 text-rose-400" />}>
          {ro.error ? (
            <p className="text-xs text-rose-300">{ro.error}</p>
          ) : (
            <>
              <div className="grid grid-cols-4 gap-2 text-center">
                {Object.entries(ro.histogram ?? {}).map(([k, v]) => (
                  <div key={k} className="bg-slate-950/50 border border-slate-800 rounded-lg py-2">
                    <p className="text-lg font-bold text-white font-mono">{fmt(v)}</p>
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">{k} ban{k === '1' ? '' : 's'}</p>
                  </div>
                ))}
              </div>
              <div className="max-h-56 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="text-slate-500 text-left">
                    <tr>
                      <th className="py-1 font-semibold">IP</th>
                      <th className="py-1 font-semibold text-right">Bans</th>
                      <th className="py-1 font-semibold text-right">Last ban (UTC)</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono text-slate-300">
                    {(ro.top ?? []).map((r) => (
                      <tr key={r.ip} className="border-t border-slate-800/60">
                        <td className="py-1">{r.ip}</td>
                        <td className="py-1 text-right text-rose-300">{r.bans}</td>
                        <td className="py-1 text-right text-slate-400">{r.last}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </Card>
      </div>

      <Card title={`Failed mail logins by country (last ${failures?.hours ?? 24}h)`} icon={<Globe className="w-4 h-4 text-amber-400" />}>
        {!failures ? (
          <div className="flex items-center space-x-2 text-slate-400 text-xs">
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
            <span>Reading postfix and dovecot logs…</span>
          </div>
        ) : (
          <div className="max-h-80 overflow-auto">
            <table className="w-full text-xs">
              <thead className="text-slate-500 text-left sticky top-0 bg-slate-900">
                <tr>
                  <th className="py-1.5 font-semibold">Country</th>
                  <th className="py-1.5 font-semibold text-right">IPs</th>
                  <th className="py-1.5 font-semibold text-right">Attempts</th>
                  <th className="py-1.5 font-semibold text-right">SMTP / IMAP IPs</th>
                  <th className="py-1.5 font-semibold text-right">Rule</th>
                </tr>
              </thead>
              <tbody className="text-slate-300">
                {failures.countries.map((c) => {
                  const home = draft.homeCountries.includes(c.code);
                  const exempt = home || c.code === 'LAN' || c.code === '??';
                  return (
                    <tr key={c.code} className="border-t border-slate-800/60">
                      <td className="py-1.5">
                        <span className="font-mono text-slate-400 mr-2">{c.code}</span>
                        {c.name}
                      </td>
                      <td className="py-1.5 text-right font-mono">{fmt(c.ips)}</td>
                      <td className="py-1.5 text-right font-mono">{fmt(c.attempts)}</td>
                      <td className="py-1.5 text-right font-mono text-slate-400">
                        {c.smtpIps} / {c.imapIps}
                      </td>
                      <td className="py-1.5 text-right">
                        {exempt ? (
                          <span className="text-sky-300">{home ? 'home · normal rules' : 'never banned'}</span>
                        ) : (
                          <span className="text-amber-300">strict · {fmt(caught(c, draft))} would be caught</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="sticky bottom-4 flex flex-wrap items-center justify-between gap-3 bg-slate-900/90 backdrop-blur border border-slate-700 rounded-2xl px-5 py-3">
        <div className="text-xs text-slate-400 space-y-0.5">
          <p>
            {state.managed ? 'CrowdSec is using these rules.' : 'CrowdSec is still on its stock ban profile.'}
            {state.notifications.length > 0 && ` Notifications kept: ${state.notifications.join(', ')}.`}
          </p>
          {result && (
            <p className={`flex items-center space-x-1.5 ${result.ok ? 'text-emerald-300' : 'text-rose-300'}`}>
              {result.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
              <span>{result.text}</span>
            </p>
          )}
        </div>
        <div className="flex items-center space-x-2">
          {dirty && (
            <button onClick={() => { setDraft(state.policy); setResult(null); }} className="text-xs font-semibold text-slate-400 hover:text-white px-3 py-2 cursor-pointer">
              Discard
            </button>
          )}
          <button
            onClick={save}
            disabled={saving || (!dirty && state.managed)}
            className="inline-flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:text-slate-400 text-white text-sm font-semibold rounded-xl px-4 py-2 cursor-pointer disabled:cursor-default"
          >
            {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            <span>{saving ? 'Testing & reloading…' : 'Apply to CrowdSec'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
