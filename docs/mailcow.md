<p align="center"><img src="assets/header-mailcow.svg" alt="" width="100%"></p>

# Managing mailcow from CowSec

<p align="center"><a href="assets/full/mailcow-flow.webp" title="Open full size"><img src="assets/mailcow-flow.svg" alt="How CowSec manages mailcow through its API" width="100%"></a></p>

CowSec can run the day-to-day mailcow administration itself, so you rarely need mailcow's admin UI. With that UI limited to your LAN, or closed altogether, admin access goes through CowSec's 2FA sign-in, audit log and WAF.

The pages live under **The Farm · Mail** in the sidebar.

| Page | What you can do |
|---|---|
| **Farmhouse** | Container health, mailcow version, storage, queue and quarantine at a glance |
| **Paddocks (Domains)** | Add, edit, enable/disable and delete domains; limits, quotas, relaying; a live **DNS records** checklist with DKIM |
| **Stalls (Mailboxes)** | Add mailboxes with a generated password, reset passwords, enable/disable, delete; quotas and last logins |
| **Ear Tags (Aliases)** | Forwarding addresses and catch-alls (`@example.org`) |
| **Quarantine Pen** | Release or delete messages rspamd held back |
| **Milk Queue (Mail queue)** | See stuck outgoing mail with the reason, retry, hold or delete |
| **Farm Log (Logs)** | postfix, dovecot, rspamd, SOGo, netfilter, ACME and more, with a filter |
| **Farmhands (Domain admins)** | Domain administrators, their domains and exactly which permissions they have |
| **Grazing Limits (Rate limits)** | Messages per second/minute/hour/day for each domain and mailbox |
| **Locked Lanes (TLS policy)** | Require TLS, a verified certificate or DANE for particular destinations |
| **Cattle Routes (Relays)** | Relay hosts (smarthosts) per domain, and transport maps per destination |
| **Guard Dog (netfilter)**, under Fence & Gate | mailcow's own ban engine, and how it works with CrowdSec |

## Turning it on

New installs: leave **Manage mailcow from CowSec** switched on in the setup wizard's *Protection* step.

Existing installs:

```bash
sudo cowsec-setup mailcow-api
```

This step does four things:
- **Reuses your key:** if mailcow already has an `API_KEY` in `mailcow.conf`, CowSec uses it, so your other tools keep working. Otherwise it generates one.
- **Allows local callers only:** `API_ALLOW_FROM` gains just `127.0.0.1`, `::1` and mailcow's Docker gateway (usually `172.22.1.1`). Calls from anywhere else are refused.
- **Stores the key root-only:** the key goes in `/etc/cowsec/mailcow.env` (mode 0600). It is never sent to the browser.
- **Applies the change:** if `mailcow.conf` changed, mailcow is restarted with `docker compose up -d`.

> [!IMPORTANT]
> mailcow's read-write API key is full administrative access to all mail on the server. CowSec only exposes a fixed set of validated operations. It never passes raw API calls through from the browser, and every change is recorded in CowSec's audit log (**Settings → Activity**).

## A tour

### Farmhouse

<p align="center"><img src="img/mail/farm.webp" alt="Farmhouse: mailcow at a glance" width="900"></p>

### Paddocks (Domains)

Add or edit a domain with its limits, quotas, tags, the global address list and backup-MX relaying. mailcow creates a DKIM key for new domains automatically.

<p align="center"><img src="img/mail/domains.webp" alt="Domain list with usage" width="900"></p>

#### DNS records

The **DNS** button on each domain opens its checklist. It lists every record mailcow needs, with what DNS answers right now:
- the server's address and reverse DNS (PTR);
- TLSA for DANE (optional);
- MX, SPF and DMARC;
- the DKIM key;
- autodiscover/autoconfig and SRV records for mail clients (optional).

Each value has a copy button. If a domain has no DKIM key yet, you can generate one there. The whole set downloads as a zone file. The expected TLSA value is calculated from the certificate Postfix actually presents.

<p align="center"><img src="img/mail/dns-records.webp" alt="DNS records for a domain, checked live" width="900"></p>

### Stalls (Mailboxes)

The mailbox form has every option mailcow offers:
- the full name, a generated password, and a forced password change at next sign-in;
- quota and tags;
- tagged-mail handling (`me+news@`);
- quarantine notifications and their category;
- required TLS, incoming and outgoing;
- which protocols may sign in: IMAP, POP3, SMTP, Sieve, ActiveSync and DAV;
- webmail access and a relay host.

**Edit** opens the same form, pre-filled. The key button sets a new password at any time.

<p align="center"><img src="img/mail/mailbox-new.webp" alt="Adding a mailbox" width="900"></p>
<p align="center"><img src="img/mail/mailboxes.webp" alt="Mailbox list with quotas and last logins" width="900"></p>

### Ear Tags (Aliases)

An alias can deliver to a list of addresses, silently discard mail, or act as a spam or not-spam training address. You can also choose:
- whether the people it delivers to can send as it in webmail;
- whether it only accepts mail from this server's own users;
- private and public notes.

<p align="center"><img src="img/mail/alias-new.webp" alt="Adding an alias" width="900"></p>
<p align="center"><img src="img/mail/aliases.webp" alt="Aliases" width="900"></p>

### Milk Queue and Quarantine Pen

The queue shows why a message is waiting, for example a remote server refusing it or DNS problems. You can retry everything at once.

<p align="center"><img src="img/mail/queue.webp" alt="The mail queue" width="900"></p>
<p align="center"><img src="img/mail/quarantine.webp" alt="The quarantine" width="900"></p>

### Farm Log

<p align="center"><img src="img/mail/logs.webp" alt="mailcow logs" width="900"></p>

### Farmhands (Domain admins)

Create domain administrators, choose their domains, and switch each permission on or off: sync jobs, quarantine, log in as a user, spam lists, protocol access, relay hosts and so on. mailcow's API doesn't report permissions, so CowSec reads them from mailcow's database (read-only) and saves them through the API.

<p align="center"><img src="img/mail/farmhands.webp" alt="Farmhands: domain admins and permissions" width="900"></p>

### Grazing Limits (Rate limits)

Set how many messages each domain or mailbox may send per second, minute, hour or day. A hijacked account then can't send thousands of spam messages from your IP before you notice. rspamd enforces the limits; 0 removes one.

<p align="center"><img src="img/mail/ratelimits.webp" alt="Grazing Limits: rate limits" width="900"></p>

### Locked Lanes (TLS policy)

Require encryption, a verified certificate or DANE when sending to particular domains or addresses, for example your bank or a partner. If the other side can't meet the policy, mail waits in the queue instead of going out unprotected.

<p align="center"><img src="img/mail/tls-policy.webp" alt="Locked Lanes: TLS policy maps" width="900"></p>

### Cattle Routes (Relay hosts & transports)

- **Relay hosts** send mail through a smarthost. This is handy when your provider blocks outbound port 25. You can choose per domain which relay to use, or send directly.
- **Transports** route mail for particular destinations, or for everything hosted at one provider, to a specific next hop.

<p align="center"><img src="img/mail/routes.webp" alt="Cattle Routes: relay hosts and transports" width="900"></p>

### Guard Dog (mailcow netfilter)

mailcow has its own ban engine, *netfilter*. It is a separate guard from CrowdSec, so CowSec shows it under **Fence & Gate**. From this page you can:
- see netfilter's active and permanent bans;
- unban, whitelist or blacklist a network;
- edit its thresholds.

Choose how the two guards work together:

| Mode | What happens |
|---|---|
| **Side by side** (default) | netfilter bans in its own firewall chain and CrowdSec bans in `DOCKER-USER`. |
| **CrowdSec enforces** | netfilter keeps detecting but switches to mailcow's *manage externally* mode. Every minute CowSec turns its active bans and blacklist into CrowdSec decisions (reason `mailcow netfilter`). Every ban then shows in **Banned from the Herd**, under one firewall. Switching back hands enforcement back to netfilter and removes the imported decisions. |

In both modes:
- **Keep trusted lists in step** adds your **Trusted Herd** allowlist and local network to netfilter's whitelist, so neither guard bans them.
- Lifting a ban in **Banned from the Herd** lifts it in netfilter too.

<p align="center"><img src="img/console/netfilter.webp" alt="Guard Dog: mailcow netfilter and CrowdSec" width="900"></p>

## Limits

These are deliberately out of scope for now:
- **Mailbox users' own settings** (spam filters, app passwords, sieve) stay in SOGo and mailcow's user pages.
- **Domain admins** are a planned phase.
- **Rate limits, TLS policy maps, transports and relay hosts** are a planned phase.
- **mailcow's netfilter** coordination is a planned phase.
