// The Farmer's Almanac (help: manual, knowledge base, troubleshooting) and About.
// Everything here ships with the console and works offline; nothing is fetched from outside.
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  BookOpen, Box, ChevronRight, Cloud, Coffee, Copy, Cpu, ExternalLink, Flame, Globe, KeyRound, Library, LifeBuoy, Lock, Mail, Search,
  Server, Shield, ShieldCheck, Sparkles, Terminal, Wheat, Wrench,
} from 'lucide-react';
import CowSecLogo, { BESSIE, currentLook, LOOKS } from './CowSecLogo';
import architecture from '../../docs/assets/architecture.svg';
import banLadder from '../../docs/assets/ban-ladder.svg';
import accessModes from '../../docs/assets/access-modes.svg';
import certFlow from '../../docs/assets/cert-flow.svg';
import securityLayers from '../../docs/assets/security-layers.svg';
import upgradeFlow from '../../docs/assets/upgrade-flow.svg';
import mailcowFlow from '../../docs/assets/mailcow-flow.svg';

type Block = string | { code: string } | { list: string[] } | { img: string; alt: string } | { tip: string };
interface Article { id: string; title: string; summary: string; body: Block[]; group?: string }
type Section = 'manual' | 'kb' | 'trouble';

// ---------------------------------------------------------------- content

const MANUAL: Article[] = [
  { id: 'barn-status', group: 'The Barn', title: 'Barn Status', summary: 'Health of the server and every protection, at a glance.',
    body: ['Shows CrowdSec, the firewall bouncer, the web edge (OpenResty, or nginx on Debian 13) and their timers, how many addresses the firewall is blocking, WAF traffic and its top rules, which logs CrowdSec reads, certificate expiry, the clock, and mailcow\'s containers.',
      { list: ['Use the service buttons to restart or reload a component safely.', 'A red tile means a protection is down: start there.', 'Certificate expiry turns amber at 14 days and red at 7.'] }] },
  { id: 'fresh-hay', group: 'The Barn', title: 'Fresh Hay (Updates)', summary: 'Update mailcow, CrowdSec, its bouncers and the hub.',
    body: ['mailcow updates run mailcow\'s own update.sh as a staged job: an optional backup, then a download of the new images before any downtime, then the update, then health checks of every container and of CowSec\'s protections.',
      { img: upgradeFlow, alt: 'Safe upgrade steps' },
      { list: ['Pick the backup folder with the folder button. The default, /var/backups/cowsec/mailcow, sits inside a root-only folder.', 'Branch switches (stable to nightly) stay manual: mailcow refuses them unattended.', 'Nightly hub updates are CrowdSec\'s own timer; the switch turns it on or off.'] }] },
  { id: 'banned', group: 'Fence & Gate', title: 'Banned from the Herd', summary: 'Every active ban, with country, network and reason.',
    body: ['Search by IP, country or scenario. Ban an address or range by hand, or lift a ban. Lifting a ban here also lifts it in mailcow\'s netfilter.',
      { tip: 'Locked yourself out? Lift the ban here, then add your address to Trusted Herd so it never happens again.' }] },
  { id: 'herd-rules', group: 'Fence & Gate', title: 'Herd Rules (Ban policy)', summary: 'Home countries, the abroad rule and escalating bans.',
    body: ['Failed logins from your home countries follow CrowdSec\'s normal rules. From anywhere else, a stricter rule catches slow password sprays. Repeat offenders get longer bans each time.', { img: banLadder, alt: 'Escalating ban ladder' }] },
  { id: 'electric-fence', group: 'Fence & Gate', title: 'Electric Fence (WAF)', summary: 'AppSec rules and CVE virtual patches in front of mailcow\'s web UI.',
    body: ['The mail WAF gives every AppSec rule a mode. Block: checked before the request reaches mailcow (rules for the mail stack, webmail, nginx, and probes like .env or .git). Watch: checked after the reply, so it never slows or blocks a real request, and anything that trips it is banned as a scanner (rules for software you don\'t run). Off: not installed.',
      { list: ['New rules from hub updates start in Watch; new patches for mail products block automatically.', 'Change any rule\'s mode on the page; your choice is kept across hub updates.', 'The diagram at the top shows how many rules sit in the request path and how many watch.'] }] },
  { id: 'trusted-herd', group: 'Fence & Gate', title: 'Trusted Herd (Allowlists)', summary: 'Addresses CrowdSec must never ban.',
    body: ['Entries apply instantly through CrowdSec\'s API and also filter the community blocklist. Your LAN ranges are always trusted. With netfilter sync on, these entries are copied to mailcow\'s netfilter whitelist too.'] },
  { id: 'guard-dog', group: 'Fence & Gate', title: 'Guard Dog (netfilter)', summary: 'mailcow\'s own ban engine, and how it works with CrowdSec.',
    body: ['See and edit netfilter\'s thresholds, its active and permanent bans, and unban, whitelist or blacklist a network.', { list: ['Side by side: both guards ban independently.', 'CrowdSec enforces: netfilter only detects; CowSec turns its bans into CrowdSec decisions every minute, so every ban is in one list and follows your ban ladder.'] },
      { tip: 'netfilter never bans private (LAN) addresses. That is mailcow\'s design.' }] },
  { id: 'farm', group: 'The Farm', title: 'Farmhouse, Paddocks, Stalls, Ear Tags', summary: 'Overview, domains, mailboxes and aliases.',
    body: ['Everything runs through mailcow\'s API with a key that only works from this server. Every change is written to CowSec\'s audit log.', { img: mailcowFlow, alt: 'How CowSec manages mailcow' },
      { list: ['Paddocks: add, pause or delete domains and set their limits and sending limit. Editing a domain adds a footer or disclaimer (with a live preview), alias domains, and senders the whole domain always allows or blocks.',
        'Stalls: every mailbox option mailcow has, plus required two-factor sign-in and which From addresses it may use. Editing a mailbox adds tabs for its security, spam filter thresholds, app passwords (generated and shown once), disposable addresses and allow/block lists.',
        'Ear Tags: aliases and catch-alls (@example.org).'] }] },
  { id: 'brand-irons', group: 'The Farm', title: 'DNS records, Quarantine, Milk Queue, Farm Log', summary: 'DNS checklist, DKIM, held mail, the outgoing queue and mailcow\'s logs.',
    body: [{ list: ['Paddocks → DNS: every record mailcow needs (MX, SPF, DMARC, DKIM, PTR, TLSA, autodiscover), checked live, with copy buttons and a zone-file download.',
      'DKIM: create a key with your choice of selector and size, copy it to other domains, or rotate it. Rotation makes the new key first, waits until DNS shows its record, and only then switches, so no message goes out unsigned.',
      'Quarantine Pen: open a held message to see it as plain text (nothing loads), the rules that held it, links whose text hides a different address, and risky attachments. Release it, release it and teach the filter, delete it, or always allow or block the sender.',
      'Milk Queue: see stuck outgoing mail with the reason; retry, hold or delete it, or empty the whole queue.',
      'Farm Log: postfix, dovecot, rspamd, SOGo, netfilter, ACME and more.'] }] },
  { id: 'mail-security', group: 'The Farm', title: 'Mailbox security and Lookout', summary: 'Sign-ins, failed attempts, the lock-down playbook, and keeping watch.',
    body: ['The shield button on a mailbox shows its sign-ins from the last 30 days with country flags, highlights countries it rarely uses, and lists failed sign-ins from mailcow\'s logs grouped by IP, with each IP\'s CrowdSec ban status.',
      { list: ['Lock down this mailbox: disable sign-in (mail still arrives), require a new password, pause app passwords, sign out phones and tablets, throttle sending to one an hour, and ban the suspicious IPs. Each step is optional.',
        'CowSec records what it changed, so Undo puts sign-in, app passwords and the old sending limit back, and can lift the bans.',
        'Lookout (The Farm → Lookout): outbound mail per sender with unusual senders flagged, the queue by sender, rate-limit hits, locked-down mailboxes, admins without 2FA, the password policy and forwarding hosts.'] },
      'A sudden jump in one account\'s outgoing mail, or one account sending from many addresses, is the usual sign of a stolen password. Lock it down first, then investigate.'] },
  { id: 'herd-health', group: 'The Farm', title: 'Herd Health (Dashboard)', summary: 'Mail flow, spam, refusals, bounces and failed sign-ins over time.',
    body: ['mailcow only keeps the last few thousand log lines, so CowSec reads its Postfix, Dovecot and rspamd logs every minute and keeps its own history: hourly counts for 31 days. Pick 24 hours, 7 days or 30 days; each tile compares with the period before.',
      { list: ['Received: messages from outside that reached a mailbox. Sent: messages your signed-in users sent.', 'Spam caught: refused by rspamd, or delivered to Junk. Turned away: refused at the gate (unknown recipient, sender on a blocklist, a domain that doesn\'t accept mail, greylisting).', 'Bounced: recipients that never got a message. Delayed mail is shown with bounces in the flow chart, because it is still being retried.', 'Failed sign-ins: one per wrong password, whether over SMTP, IMAP or POP3. A climb against one mailbox is worth opening in the Lookout.', 'Mailboxes: who sent and received most, with their bounces and failed sign-ins. The footprints button opens that mailbox\'s mail in the trail.'] },
      { tip: 'Counting starts when CowSec is installed (or upgraded to 0.4), with whatever is still in mailcow\'s log. If mail arrives faster than CowSec reads it, the page says when counts may be low.' }] },
  { id: 'mail-trail', group: 'The Farm', title: 'Hoofprints (Mail trail)', summary: 'Follow one message from the gate to the mailbox.',
    body: ['Search by sender, recipient, subject, queue ID, Message-ID or IP address, and filter by what happened (delivered, delayed, bounced, refused, spam) and direction. Open a message to see each step with its time and reason:',
      { list: ['Arrived: from which server, or sent by which signed-in user.', 'rspamd: its verdict, the spam score against the refusal threshold, and the rules that scored. The subject comes from here.', 'Queued, then for each recipient: delivered to a mailbox, handed to the recipient\'s server, delayed (with how many tries), or bounced with the server\'s reason.', 'Mail turned away at the gate has no subject: the sender was refused before it sent the message.'] },
      { tip: 'The trail keeps 7 days (up to 20,000 messages) in CowSec\'s state folder, readable only by root. rspamd skips its history for a few things, such as the GTUBE test message, so those show no score.' }] },
  { id: 'ribbons', group: 'The Farm', title: 'Show Ribbons (Deliverability)', summary: 'A grade for every domain, and how to raise it.',
    body: ['Each domain gets a rosette from A to F: MX, SPF, DKIM, DMARC, MTA-STS, TLS reporting, plus the server\'s reverse DNS and seven blocklists. Every failing check says how to fix it.',
      { list: ['MTA-STS: edit a domain → MTA-STS to tell other servers to always use encrypted, verified connections. Start in testing, then enforce.', 'Add domain opens a wizard: domain, DKIM key, DNS records ticked off live as they appear, then the postmaster mailbox.', 'A "?" next to a blocklist means this server\'s DNS resolver can\'t query it, not that you\'re listed.'] }] },
  { id: 'farmhands', group: 'Farm Office', title: 'Farmhands, Grazing Limits, Locked Lanes, Cattle Routes', summary: 'Domain admins, rate limits, TLS policy, relays.',
    body: [{ list: ['Farmhands: domain administrators, their domains and each permission. Open as signs you into mailcow as that admin with a single-use link.', 'Grazing Limits: messages per second, minute, hour or day for a domain or mailbox, so a hijacked account can\'t spray spam.', 'Locked Lanes: require TLS, a verified certificate or DANE for particular destinations.', 'Cattle Routes: send mail through a smarthost per domain, or route destinations to a specific next hop.'] }] },
  { id: 'herd-watch', group: 'Herd Watch', title: 'Moo Alerts, Feed Store, Bouncers & Herd Dogs', summary: 'Detections, the hub and registered components.',
    body: [{ list: ['Moo Alerts: what CrowdSec detected, newest first.', 'Feed Store: install, upgrade or remove collections, parsers, scenarios and WAF rules.', 'Bouncers & Herd Dogs: the bouncers and machines registered with CrowdSec\'s local API.'] }] },
  { id: 'bessie', group: 'Your account', title: 'Bessie the Bouncer (the mascot)', summary: 'Her seasonal wardrobe, and how to pick a look.',
    body: ['Bessie guards the console. Through the year she swaps her hat and collar charm: a security cap every day, a party hat at New Year, a love lock for Valentine\'s, bunny ears at Easter, sunglasses in summer, a witch\'s hat for Halloween and a Santa hat in December.',
      { list: ['Settings → Mascot: follow the calendar, or pin any look.', 'The choice is per browser.', 'Every look stays inside the shield, so she reads at any size.'] }] },
  { id: 'settings', group: 'Your account', title: 'Settings and sign-in', summary: 'Your account, 2FA and the sign-in log.',
    body: ['Sign-in always needs a password and a second factor (an authenticator app, or Duo for directory accounts). Settings shows recent sign-ins and lets you reset your authenticator.',
      { code: 'sudo cowsec auth local-admin set <name>   # add or reset a local account\nsudo cowsec auth totp reset <name>        # re-enrol an authenticator' }] },
];

const KB: Article[] = [
  { id: 'how-it-fits', title: 'How CowSec fits around mailcow', summary: 'The pieces, and where traffic goes.',
    body: ['CrowdSec reads mailcow\'s logs and decides who to ban. The firewall bouncer enforces bans for every port; the web edge (OpenResty, or Debian\'s nginx on Debian 13) checks each web request with the CrowdSec bouncer and the AppSec WAF before it reaches mailcow, which listens only on localhost.', { img: architecture, alt: 'CowSec architecture' }] },
  { id: 'docker-ports', title: 'Why the firewall bouncer needs DOCKER-USER', summary: 'mailcow\'s mail ports are Docker-published.',
    body: ['Docker forwards SMTP and IMAP to mailcow\'s containers before the host\'s INPUT chain ever sees them. A bouncer on INPUT alone would never block mail. CowSec adds the DOCKER-USER chain for the iptables bouncer, or the forward hook for the nftables bouncer.'] },
  { id: 'ban-ladder', title: 'Home countries and escalating bans', summary: 'Stop sprays without locking out your own users.',
    body: ['Logins from home countries follow CrowdSec\'s standard scenarios. Failed logins from abroad use a stricter rule. Each repeat ban for the same address doubles, from 4 hours up to 7 days. Country lookups use the local GeoLite2 database, so no address leaves the server.', { img: banLadder, alt: 'Ban ladder' }] },
  { id: 'certificates', title: 'Certificates: DNS-01, mailcow\'s own, or yours', summary: 'Which one to choose.',
    body: [{ list: ['DNS-01 (lego): no port 80, wildcards, one certificate per domain. Works with 190+ DNS providers.', 'mailcow\'s Let\'s Encrypt: what mailcow does by default. Port 80 must stay open.', 'Keep my current certificates: for servers that already renew with certbot; the edge reloads after each renewal.'] }, { img: certFlow, alt: 'Certificate flow' }] },
  { id: 'access-modes', title: 'Reaching the console', summary: 'LAN, Cloudflare Tunnel, internet or SSH.',
    body: ['The console always listens on 127.0.0.1:8090. The access mode decides how it is published.', { img: accessModes, alt: 'Access modes' },
      { code: 'sudo cowsec-setup access lan --hostname cowsec.example.com\nsudo cowsec-setup access tunnel --tunnel-token <token>\nsudo cowsec-setup access local' }] },
  { id: 'netfilter', title: 'mailcow netfilter and CrowdSec', summary: 'Two guards, one fence.',
    body: ['mailcow ships its own ban engine. Side by side, both ban independently. With "CrowdSec enforces", netfilter switches to mailcow\'s "manage externally" mode and CowSec imports its active bans and blacklist into CrowdSec every minute. Switching back hands enforcement back and removes the imported bans.'] },
  { id: 'what-changes', title: 'What CowSec changes on the server', summary: 'Only mailcow\'s supported settings, with a way back.',
    body: ['In mailcow it only uses mailcow.conf, data/conf/postfix/extra.cf and data/assets/ssl, so ./update.sh keeps working. Every file it changes is backed up first as <file>.cowsec-bak-<time>.',
      { list: ['Before changing anything on a server that already runs mailcow, it saves mailcow\'s settings and certificates, CrowdSec\'s configuration and the firewall rules to /var/backups/cowsec/pre-install-<time>.tar.gz.',
        'sudo cowsec-setup restore-mailcow puts mailcow back exactly as it was from that snapshot: the edge stops, mailcow\'s nginx takes 80/443 again, and mailcow restarts. CrowdSec keeps protecting you.',
        'Takes over hand-built setups with backups in /root/cowsec-adopted-<time>.', 'Keeps an apt-installed CrowdSec and an existing iptables or nftables bouncer.', 'Refuses a second CrowdSec engine in a container.'] }] },
  { id: 'live-server', title: 'Installing on a server that already handles mail', summary: 'What to do first, what to expect, and how to undo it.',
    body: [{ list: ['Back up first: a VM or cloud snapshot, your usual backup, or mailcow\'s own helper-scripts/backup_and_restore.sh, which works on any server. CowSec\'s own snapshot covers its changes, not your mail.', 'Run sudo cowsec-setup check: it changes nothing and shows what it found.',
      'Pick a quiet time. Mail keeps flowing, but mailcow\'s web interface is unavailable for a minute while the edge takes over ports 80 and 443.',
      'The review step lists every choice before anything happens, and asks you to confirm you have a backup.',
      'If the edge can\'t start, mailcow\'s web settings are put back automatically. Afterwards, sudo cowsec-setup revert-edge or restore-mailcow undo it by hand.', 'To remove CowSec, sudo apt remove cowsec is enough: it first hands mailcow back to its own settings (ports, its own Let\'s Encrypt, ban enforcement, API key), puts back any hand-built setup it took over, and stops if mailcow doesn\'t come back. CrowdSec keeps running.'] }] },
  { id: 'privacy', title: 'Security and privacy', summary: 'Privileges, sign-in and what leaves the server.',
    body: [{ img: securityLayers, alt: 'Security layers' },
      { list: ['Privileged actions go through cowsec-hostctl, which only accepts a fixed list of commands.', 'Sign-in: bcrypt or LDAP, plus TOTP or Duo, rate-limited and logged.', 'GeoIP lookups and fonts are local; CowSec doesn\'t enrol the CrowdSec Console.', 'Secrets live in root-only files and are redacted from job logs.'] }] },
  { id: 'cli', title: 'Command line reference', summary: 'Everything the console does, from the shell.',
    body: [{ code: 'sudo cowsec-setup                 # wizard address and token, or status\nsudo cowsec-setup check           # pre-flight checks\nsudo cowsec-setup install --config FILE\nsudo cowsec-setup access lan|tunnel|wan|local ...\nsudo cowsec-setup mailcow-api     # connect the console to mailcow\'s API\nsudo cowsec-setup reset-wizard    # reopen the browser wizard\nsudo cowsec-setup revert-edge     # give 80/443 back to mailcow\nsudo cowsec-setup restore-mailcow # mailcow\'s settings back as before CowSec\nsudo cowsec-setup appsec-curate   # rebuild the mail WAF\nsudo cowsec-setup fix-mailcow-port  # move mailcow\'s web port off 8081 (runs on upgrade)\nsudo cowsec-setup uninstall         # hand mailcow back and remove CowSec\'s pieces (apt remove runs it)\nsudo cowsec auth status' }] },
];

const TROUBLE: Article[] = [
  { id: 'where-to-look', title: 'Where to look first', summary: 'Logs and status commands.',
    body: [{ code: 'systemctl status cowsec;  journalctl -u cowsec -n 100\nsudo cowsec-setup check\nls /var/lib/cowsec/jobs/            # setup and update job logs\njournalctl -t cowsec-hostctl        # every privileged action\nsudo cscli metrics' }] },
  { id: 'locked-out', title: 'I locked myself out of mail or the console', summary: 'Lift the ban, then trust the address.',
    body: ['In Banned from the Herd, search for the address and click Unblock. Or on the server:', { code: 'sudo cscli decisions delete --ip <your-ip>\nsudo cscli allowlists add cowsec <your-ip> -d "my office"' }, 'Your LAN ranges are always trusted.'] },
  { id: 'totp', title: '"TOTP code invalid" at sign-in', summary: 'Almost always the server clock.',
    body: ['Check that timedatectl shows "System clock synchronized: yes". To re-enrol someone:', { code: 'sudo cowsec auth totp reset <user>' }] },
  { id: 'bans-mail', title: 'Bans don\'t stop mail traffic', summary: 'The bouncer must hook Docker\'s forwarded traffic.',
    body: [{ code: 'sudo iptables -S DOCKER-USER | grep -i crowdsec          # iptables bouncer\nsudo nft list table ip crowdsec | grep "hook forward"     # nftables bouncer\nsudo systemctl restart crowdsec-firewall-bouncer' }] },
  { id: 'edge', title: 'Setup stopped at "Web edge"', summary: 'Something else holds 80/443.',
    body: ['CowSec puts mailcow\'s web settings back automatically. Find what holds the ports, fix it, then run Install again. The edge is OpenResty, or nginx on Debian 13:', { code: "ss -ltnp | grep -E ':80 |:443 '\njournalctl -u openresty -n 50   # Debian 13: journalctl -u nginx -n 50" }] },
  { id: 'certs', title: 'DNS-01 certificates failed', summary: 'Credentials, DNS host or CAA.',
    body: [{ list: ['The credentials need DNS edit rights for that zone.', 'The domain\'s DNS must be hosted at that provider.', 'A CAA record may forbid Let\'s Encrypt.'] }, 'Use Test run (staging) while you fix it.'] },
  { id: 'double', title: 'Events are counted twice', summary: 'Two acquisitions read the same logs.',
    body: ['Another file in /etc/crowdsec/acquis.yaml or acquis.d/ also reads mailcow\'s containers. The setup wizard comments these out when it takes over a server; remove any you added later.'] },
  { id: 'apt-busy', title: '"Waiting for another apt/dpkg run"', summary: 'First-boot updates on new servers.',
    body: ['New cloud servers run unattended upgrades just after boot. CowSec waits up to 20 minutes.', { code: "ps aux | grep -E 'apt|dpkg'" }] },
  { id: 'capi', title: '"CrowdSec did not restart … api.crowdsec.net"', summary: 'CrowdSec can\'t reach its central API.',
    body: ['CrowdSec stops at startup if it can\'t sign in to its central API. Check DNS, outbound firewalls and /etc/hosts. On a deliberately offline server, comment out credentials_path under online_client in /etc/crowdsec/config.yaml.'] },
  { id: 'resty', title: 'Edge: module \'resty.http\' not found', summary: 'A missing Lua library.',
    body: ['OpenResty:', { code: 'sudo opm get ledgetech/lua-resty-http=0.17.1 && sudo systemctl restart openresty' },
      'Debian 13 (nginx edge):', { code: 'sudo luarocks install lua-resty-http 0.17.1-0 && sudo systemctl restart nginx' }] },
  { id: 'debian13', title: 'Debian 13: the edge runs on Debian\'s nginx', summary: 'OpenResty\'s signing key still uses SHA-1.',
    body: ['Debian 13\'s apt rejects keys bound with SHA-1 since 1 February 2026, and OpenResty\'s repository key still is (openresty/openresty#1072). CowSec won\'t weaken apt\'s checks for every repository to get around it, so on Debian 13 the edge is built from Debian\'s own packages instead.',
      { list: ['nginx with Debian\'s Lua module, and CrowdSec\'s nginx bouncer: the same bouncer library and AppSec WAF as the OpenResty edge, so bans, the mail WAF, DNS-01 certificates and LAN or internet access to the console all work.', 'Every package is signed by Debian or CrowdSec, and updates arrive through apt as usual.', 'Its config lives in /etc/nginx, its logs in /var/log/nginx, and the service is nginx (journalctl -u nginx).'] }] },
  { id: 'docker-io', title: 'Installing mailcow: docker.io is installed', summary: 'mailcow needs Docker CE 24+.',
    body: [{ code: 'sudo apt remove docker.io' }, 'Then run the install again; CowSec installs Docker CE from Docker\'s repository.'] },
];

const SECTIONS: [Section, string, ReactNode, Article[]][] = [
  ['manual', 'User manual', <BookOpen key="i" className="w-4 h-4" />, MANUAL],
  ['kb', 'Knowledge base', <Library key="i" className="w-4 h-4" />, KB],
  ['trouble', 'Troubleshooting', <LifeBuoy key="i" className="w-4 h-4" />, TROUBLE],
];

const text = (a: Article) => [a.title, a.summary, ...a.body.map((b) => (typeof b === 'string' ? b : 'code' in b ? b.code : 'list' in b ? b.list.join(' ') : 'tip' in b ? b.tip : b.alt))].join(' ').toLowerCase();

// ---------------------------------------------------------------- rendering

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="relative group">
      <pre className="text-xs font-mono text-emerald-200 bg-slate-950/80 border border-slate-800 rounded-xl p-3 pr-10 overflow-x-auto whitespace-pre">{code}</pre>
      <button
        onClick={() => navigator.clipboard?.writeText(code).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500); }).catch(() => {})}
        className="absolute top-2 right-2 p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 cursor-pointer" title="Copy">
        {copied ? <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
}

function Body({ blocks }: { blocks: Block[] }) {
  return (
    <div className="space-y-3 text-sm text-slate-300 leading-relaxed">
      {blocks.map((b, i) =>
        typeof b === 'string' ? <p key={i}>{b}</p>
          : 'code' in b ? <CodeBlock key={i} code={b.code} />
          : 'list' in b ? <ul key={i} className="space-y-1.5">{b.list.map((x) => <li key={x} className="flex gap-2"><ChevronRight className="w-3.5 h-3.5 mt-1 shrink-0 text-sky-400" />{x}</li>)}</ul>
          : 'tip' in b ? <p key={i} className="rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-100 px-3 py-2">{b.tip}</p>
          : <img key={i} src={b.img} alt={b.alt} className="w-full rounded-xl border border-slate-800 bg-slate-950/40" loading="lazy" />,
      )}
    </div>
  );
}

export function HelpCenter() {
  const [section, setSection] = useState<Section>('manual');
  const [q, setQ] = useState('');
  const [open, setOpen] = useState<string | null>(null);
  const query = q.trim().toLowerCase();
  const results = useMemo(
    () => (query ? SECTIONS.flatMap(([id, , , list]) => list.filter((a) => text(a).includes(query)).map((a) => ({ ...a, sec: id }))) : []),
    [query],
  );
  const list = SECTIONS.find(([id]) => id === section)![3];
  const groups = [...new Set(list.map((a) => a.group || ''))];
  const card = (a: Article) => (
    <div key={a.id} className={`rounded-2xl border transition-colors ${open === a.id ? 'border-sky-500/40 bg-slate-900/70' : 'border-slate-800 bg-slate-900/40 hover:border-slate-700'}`}>
      <button onClick={() => setOpen(open === a.id ? null : a.id)} className="w-full text-left px-4 py-3 flex items-start gap-3 cursor-pointer">
        <ChevronRight className={`w-4 h-4 mt-0.5 shrink-0 text-slate-500 transition-transform duration-300 ${open === a.id ? 'rotate-90 text-sky-400' : ''}`} />
        <span className="flex-1 min-w-0">
          <span className="block font-semibold text-white">{a.title}</span>
          <span className="block text-xs text-slate-400">{a.summary}</span>
        </span>
      </button>
      {open === a.id && <div className="px-4 pb-4 pl-11 cs-page"><Body blocks={a.body} /></div>}
    </div>
  );
  return (
    <div className="space-y-6">
      <div className="relative overflow-hidden rounded-3xl border border-slate-800 bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/60 p-6">
        <div className="absolute -right-10 -top-10 w-56 h-56 rounded-full bg-sky-500/10 blur-3xl cs-breathe" />
        <div className="relative flex flex-wrap items-center gap-5">
          <CowSecLogo className="w-16 h-16 cs-float drop-shadow-[0_8px_24px_rgba(56,189,248,0.35)]" />
          <div className="flex-1 min-w-[220px]">
            <h2 className="text-2xl font-bold text-white">Farmer's Almanac</h2>
            <p className="text-sm text-slate-400">How CowSec works, how to use every page, and how to fix things when they go wrong.</p>
          </div>
          <div className="relative w-full sm:w-80">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search the almanac…" aria-label="Search help"
              className="w-full bg-slate-950/70 border border-slate-700 rounded-xl pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-sky-500" />
          </div>
        </div>
      </div>

      {query ? (
        <div className="space-y-2 cs-stagger">
          <p className="text-xs text-slate-500">{results.length} result{results.length === 1 ? '' : 's'} for "{q}"</p>
          {results.map((a) => card(a))}
          {!results.length && <p className="text-sm text-slate-500">Nothing found. Try a page name, a command or an error message.</p>}
        </div>
      ) : (
        <>
          <div className="flex flex-wrap gap-2">
            {SECTIONS.map(([id, label, icon, l]) => (
              <button key={id} onClick={() => { setSection(id); setOpen(null); }}
                className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-xl text-sm font-semibold border cursor-pointer transition-colors ${section === id ? 'bg-sky-500/15 border-sky-500/40 text-white' : 'border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'}`}>
                {icon}{label}<span className="text-[10px] font-mono text-slate-500">{l.length}</span>
              </button>
            ))}
          </div>
          <div key={section} className="space-y-5 cs-page">
            {groups.map((g) => (
              <div key={g} className="space-y-2">
                {g && <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">{g}</p>}
                <div className="space-y-2 cs-stagger">{list.filter((a) => (a.group || '') === g).map(card)}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- about

interface Pkg { name: string; installed: string | null }
interface StackItem { name: string; role: string; pkg?: string; icon: ReactNode; tone: string; href: string }

const STACK: [string, StackItem[]][] = [
  ['Protection', [
    { name: 'CrowdSec', role: 'Detection engine', pkg: 'crowdsec', icon: <Shield className="w-3.5 h-3.5" />, tone: 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10', href: 'https://www.crowdsec.net' },
    { name: 'Firewall bouncer', role: 'iptables or nftables', pkg: 'crowdsec-firewall-bouncer-iptables|crowdsec-firewall-bouncer-nftables', icon: <Flame className="w-3.5 h-3.5" />, tone: 'text-rose-300 border-rose-500/30 bg-rose-500/10', href: 'https://github.com/crowdsecurity/cs-firewall-bouncer' },
    { name: 'OpenResty', role: 'Edge proxy', pkg: 'openresty', icon: <Globe className="w-3.5 h-3.5" />, tone: 'text-sky-300 border-sky-500/30 bg-sky-500/10', href: 'https://openresty.org' },
    { name: 'AppSec WAF', role: 'Lua bouncer + virtual patching', pkg: 'crowdsec-openresty-bouncer', icon: <ShieldCheck className="w-3.5 h-3.5" />, tone: 'text-indigo-300 border-indigo-500/30 bg-indigo-500/10', href: 'https://docs.crowdsec.net/docs/appsec/intro' },
  ]],
  ['Mail', [
    { name: 'mailcow-dockerized', role: 'Mail server suite', pkg: 'mailcow', icon: <Mail className="w-3.5 h-3.5" />, tone: 'text-amber-200 border-amber-500/30 bg-amber-500/10', href: 'https://mailcow.email' },
    { name: 'Docker', role: 'Containers', icon: <Box className="w-3.5 h-3.5" />, tone: 'text-sky-300 border-sky-500/30 bg-sky-500/10', href: 'https://www.docker.com' },
    { name: 'Postfix · Dovecot · rspamd', role: 'Inside mailcow', icon: <Mail className="w-3.5 h-3.5" />, tone: 'text-violet-300 border-violet-500/30 bg-violet-500/10', href: 'https://docs.mailcow.email' },
  ]],
  ['Certificates & access', [
    { name: 'lego', role: 'ACME DNS-01 client', icon: <KeyRound className="w-3.5 h-3.5" />, tone: 'text-teal-300 border-teal-500/30 bg-teal-500/10', href: 'https://go-acme.github.io/lego/' },
    { name: "Let's Encrypt", role: 'Certificate authority', icon: <Lock className="w-3.5 h-3.5" />, tone: 'text-amber-300 border-amber-500/30 bg-amber-500/10', href: 'https://letsencrypt.org' },
    { name: 'cloudflared', role: 'Optional tunnel', pkg: 'cloudflared', icon: <Cloud className="w-3.5 h-3.5" />, tone: 'text-orange-300 border-orange-500/30 bg-orange-500/10', href: 'https://github.com/cloudflare/cloudflared' },
    { name: 'chrony', role: 'Accurate clock', icon: <Server className="w-3.5 h-3.5" />, tone: 'text-slate-200 border-slate-500/30 bg-slate-500/10', href: 'https://chrony-project.org' },
  ]],
  ['Built with', [
    { name: 'Go', role: 'Console server', icon: <Cpu className="w-3.5 h-3.5" />, tone: 'text-cyan-300 border-cyan-500/30 bg-cyan-500/10', href: 'https://go.dev' },
    { name: 'Python', role: 'Installer and host helper', icon: <Terminal className="w-3.5 h-3.5" />, tone: 'text-yellow-200 border-yellow-500/30 bg-yellow-500/10', href: 'https://www.python.org' },
    { name: 'React · Vite', role: 'Interface', icon: <Sparkles className="w-3.5 h-3.5" />, tone: 'text-sky-300 border-sky-500/30 bg-sky-500/10', href: 'https://react.dev' },
    { name: 'Tailwind CSS', role: 'Styling', icon: <Sparkles className="w-3.5 h-3.5" />, tone: 'text-teal-300 border-teal-500/30 bg-teal-500/10', href: 'https://tailwindcss.com' },
    { name: 'Lucide', role: 'Icons', icon: <Sparkles className="w-3.5 h-3.5" />, tone: 'text-pink-300 border-pink-500/30 bg-pink-500/10', href: 'https://lucide.dev' },
  ]],
];

export function AboutPanel() {
  const look = currentLook();
  const [version, setVersion] = useState<string | null>(null);
  const [pkgs, setPkgs] = useState<Record<string, string>>({});
  useEffect(() => {
    fetch('/api/about', { cache: 'no-store' }).then((r) => r.json()).then((d) => setVersion(d.version)).catch(() => {});
    fetch('/api/crowdsec/host/updates', { cache: 'no-store' }).then((r) => r.json()).then((d) => {
      const m: Record<string, string> = {};
      for (const p of (d?.packages || []) as Pkg[]) if (p.installed) m[p.name] = p.installed.replace(/^\d+:/, '').replace(/[-+~].*$/, '');
      if (d?.mailcow?.version?.tag) m.mailcow = d.mailcow.version.tag;
      setPkgs(m);
    }).catch(() => {});
  }, []);
  const verOf = (s: StackItem) => s.pkg?.split('|').map((p) => pkgs[p]).find(Boolean);
  return (
    <div className="space-y-6">
      <div className="relative overflow-hidden rounded-3xl border border-slate-800 bg-slate-950/60 p-8 text-center">
        <div className="absolute inset-0 bg-[radial-gradient(60%_80%_at_50%_0%,rgba(56,189,248,0.16),transparent_70%)]" />
        <div className="relative flex flex-col items-center gap-4">
          <div className="relative">
            <div className="absolute -inset-4 rounded-[2rem] bg-gradient-to-br from-emerald-400/30 via-sky-400/20 to-indigo-500/30 blur-xl cs-breathe" />
            <img src={BESSIE[look]} alt={`Bessie the Bouncer, ${LOOKS.find((l) => l.id === look)?.name}`} className="relative w-40 h-40 object-contain cs-float drop-shadow-[0_12px_32px_rgba(56,189,248,0.4)]" />
          </div>
          <div>
            <h2 className="text-3xl font-bold text-white tracking-tight">CowSec</h2>
            <p className="text-sm text-slate-400">The browser installer and security console for CrowdSec on mailcow</p>
            <p className="text-xs text-slate-500 mt-1">Guarded by <b className="text-slate-300">Bessie the Bouncer</b>, head of security. She dresses for the season; pick her look in Settings → Mascot.</p>
          </div>
          <div className="flex flex-wrap justify-center gap-2 text-xs font-mono">
            <span className="px-2.5 py-1 rounded-lg border border-sky-500/30 bg-sky-500/10 text-sky-200">version {version || '…'}</span>
            <span className="px-2.5 py-1 rounded-lg border border-slate-700 text-slate-300">© {new Date().getFullYear()} OryxAstro</span>
            <span className="px-2.5 py-1 rounded-lg border border-slate-700 text-slate-300">AGPL-3.0</span>
            <a href="https://github.com/OryxAstro/cowsec" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg border border-slate-700 text-slate-300 hover:text-white">github.com/OryxAstro/cowsec <ExternalLink className="w-3 h-3" /></a>
          </div>
          <div className="flex flex-wrap justify-center gap-2 pt-1">
            <a href="https://buymeacoffee.com/OryxAstro" target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-bold bg-[#ffdd00] text-[#1f1300] border border-black/10 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-[#ffdd00]/40 transition-all">
              <Coffee className="w-4 h-4" /> Buy Bessie a latte
            </a>
            <a href="https://ko-fi.com/OryxAstro" target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-xl px-3.5 py-2 text-xs font-bold bg-[#ff5e5b] text-[#ffffff] border border-black/10 hover:-translate-y-0.5 hover:shadow-lg hover:shadow-[#ff5e5b]/40 transition-all">
              <Wheat className="w-4 h-4" /> Buy Bessie some hay
            </a>
          </div>
          <p className="text-[11px] text-slate-500 -mt-1">Free forever. Bessie runs on hay and coffee, and moos at every donation.</p>
          <p className="text-xs text-slate-500 max-w-xl">Country flags: Twemoji, © Twitter and contributors, CC-BY 4.0. An independent community project. Not affiliated with or endorsed by mailcow or CrowdSec. All product names belong to their owners.</p>
        </div>
      </div>

      <div className="space-y-5">
        <h3 className="text-sm font-semibold uppercase tracking-widest text-slate-400 flex items-center gap-2"><Wrench className="w-4 h-4" /> The herd it's built on</h3>
        {STACK.map(([group, items]) => (
          <div key={group} className="space-y-2">
            <p className="text-[11px] font-semibold uppercase tracking-widest text-slate-500">{group}</p>
            <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-2.5 cs-stagger">
              {items.map((s) => (
                <a key={s.name} href={s.href} target="_blank" rel="noreferrer"
                  className={`group flex items-center gap-3 rounded-2xl border px-3.5 py-3 transition-transform hover:-translate-y-0.5 ${s.tone}`}>
                  <span className="w-8 h-8 rounded-xl flex items-center justify-center bg-slate-950/50 border border-white/5">{s.icon}</span>
                  <span className="flex-1 min-w-0">
                    <span className="block text-sm font-semibold text-white truncate">{s.name}</span>
                    <span className="block text-[11px] text-slate-400 truncate">{s.role}</span>
                  </span>
                  {verOf(s) && <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-slate-950/60 text-slate-200">{verOf(s)}</span>}
                </a>
              ))}
            </div>
          </div>
        ))}
        <p className="text-[11px] text-slate-500">Country lookups use the GeoLite2 data created by MaxMind, available from maxmind.com, and maintained locally by CrowdSec.</p>
      </div>
    </div>
  );
}
