<p align="center">
  <img src="docs/assets/banner.svg" alt="CowSec: the browser installer and security console for CrowdSec on mailcow" width="100%">
</p>

<p align="center">
  <a href="https://buymeacoffee.com/OryxAstro"><img src="docs/assets/buttons/buymeacoffee.svg" alt="Buy Bessie a latte on Buy Me a Coffee" height="56"></a>
  <a href="https://ko-fi.com/OryxAstro"><img src="docs/assets/buttons/kofi.svg" alt="Buy Bessie some hay on Ko-fi" height="56"></a>
  <a href="https://github.com/OryxAstro/cowsec/stargazers"><img src="docs/assets/buttons/star.svg" alt="Star the repo" height="56"></a>
  <!-- once GitHub Sponsors is approved: <a href="https://github.com/sponsors/OryxAstro"><img src="docs/assets/buttons/sponsor.svg" alt="Sponsor the herd on GitHub Sponsors" height="56"></a> -->
</p>
<p align="center"><a href="https://github.com/OryxAstro"><img alt="Follow the herd" src="https://img.shields.io/github/followers/OryxAstro?label=Follow%20the%20herd&style=social"></a></p>
<p align="center"><sub>🐄 Bessie guards your mail around the clock and has never once asked for a pay rise. She runs on hay and coffee.</sub></p>

<p align="center">
  <img alt="Debian and Ubuntu" src="https://img.shields.io/badge/Debian%2012%2F13%20·%20Ubuntu%2022.04%2F24.04-0b1530?style=for-the-badge&logo=debian&logoColor=a5b4fc&labelColor=050a18">
  <img alt="mailcow-dockerized" src="https://img.shields.io/badge/mailcow--dockerized-0b1530?style=for-the-badge&logo=docker&logoColor=7dd3fc&labelColor=050a18">
  <img alt="CrowdSec 1.7+" src="https://img.shields.io/badge/CrowdSec-1.7%2B-0b1530?style=for-the-badge&logoColor=6ee7b7&labelColor=050a18">
  <img alt="amd64" src="https://img.shields.io/badge/arch-amd64-0b1530?style=for-the-badge&labelColor=050a18">
</p>

<p align="center">
  <b>Turn a stock mailcow server into a well-defended one in minutes (or start from a bare server), then run it from a friendly console.</b><br>
  <sub>Firewall + Docker-aware bans · OpenResty edge with AppSec WAF · DNS-01 certificates for 190+ providers · smart ban policy · 2FA console</sub>
</p>

<p align="center">
  <a href="docs/guide.md"><b>Installation walkthrough</b></a> ·
  <a href="docs/install.md">Requirements</a> ·
  <a href="docs/access.md">Access modes</a> ·
  <a href="docs/security.md">Security model</a> ·
  <a href="docs/troubleshooting.md">Troubleshooting</a>
</p>

---

<p align="center">
  <img src="docs/img/console/host.webp" alt="CowSec console: Barn Status" width="100%">
</p>

## Why CowSec

mailcow is a superb mail server, but defending it properly with CrowdSec takes a lot of fiddly work:
- a bouncer that covers Docker-published ports;
- a reverse proxy for the WAF;
- certificates without port 80;
- ban rules that stop slow password-spraying without locking out your own users.

CowSec does all of that for you from a browser wizard, then keeps it running with a console that explains what it's doing.

**Safe to add to a server people rely on.** Mail keeps flowing during setup. Before its first change, CowSec saves mailcow's settings, certificates, CrowdSec's configuration and the firewall rules, and `sudo cowsec-setup restore-mailcow` puts mailcow back exactly as it was. Removing the package (`apt remove cowsec`) hands mailcow back to its own settings first, so nothing is left half-working. Tested with full installs on Debian 12 and 13 and Ubuntu 22.04 and 24.04.

> CowSec is an independent community project. It is not affiliated with mailcow or CrowdSec.

## Features

<table>
<tr>
<td width="50%" valign="top">

**🧱 Fence & Gate: protection**
- Firewall bouncer on **`INPUT` and `DOCKER-USER`**. mailcow's mail ports are Docker-published, so a bouncer on `INPUT` alone never blocks SMTP or IMAP.
- **OpenResty edge** with the CrowdSec Lua bouncer and a **mail WAF**: CrowdSec's AppSec rules for the mail stack block in the request path, and every other virtual patch watches after the reply and bans the scanners that trip it.
- mailcow **admin pages LAN-only**; webmail and ActiveSync untouched.
- Your own **allowlist**, applied instantly and filtering community blocklists too.

</td>
<td width="50%" valign="top">

**🐄 Herd Rules: ban policy**
- **Home countries**: a typo on your phone never locks you out.
- **Abroad rule**: catches slow password sprays that stock scenarios miss.
- **Escalating bans**: 4h → 8h → 16h … up to 7 days for repeat offenders.
- Failed logins **by country** and **repeat offenders**, from local data only.

</td>
</tr>
<tr>
<td valign="top">

**🔐 Certificates**
- **DNS-01** via [lego](https://go-acme.github.io/lego/): Cloudflare, Route 53, Hetzner, OVH, DigitalOcean, Gandi and 180+ more.
- **One certificate per domain** for privacy, with wildcards.
- Deployed to web, IMAP and SMTP (with SNI), renewed daily, new mailcow domains picked up automatically.

</td>
<td valign="top">

**🖥️ Console & setup**
- **Browser setup wizard** with pre-flight checks, live progress, backups and automatic rollback.
- **Protect your existing mailcow, or install one**: asks the same questions as mailcow's own installer. It also takes over hand-built setups (certbot, OpenResty, CrowdSec) cleanly.
- Console for bans, alerts, the WAF, the hub, bouncers and policy.
- **One-click updates** for mailcow (with backup), CrowdSec and the hub, shown as an animated pipeline with health checks.
- **2FA sign-in** (TOTP or Duo), local accounts or LDAP, audit log.
- Reach it on your **LAN**, through a **Cloudflare Tunnel**, the internet, or SSH only.

</td>
</tr>
<tr>
<td colspan="2" valign="top">

**🏡 The Farm: mailcow management**
Run mailcow's day-to-day admin from CowSec, behind its 2FA sign-in and audit log:
- domains and mailboxes, including quotas, password resets, required 2FA, send-as rights, spam thresholds, app passwords and disposable addresses;
- aliases, catch-alls, alias domains and per-domain footers with a live preview;
- a live DNS checklist per domain (MX, SPF, DMARC, DKIM, PTR, TLSA, autodiscover) with copy buttons, a zone-file download, and DKIM key rotation with no gap in signing;
- a safe quarantine preview (plain text only, with the rules that held each message, disguised links and risky attachments), the mail queue and mailcow's logs;
- **mailbox security:** sign-ins with country flags and failed attempts with their CrowdSec ban status, plus a one-click **lock-down** you can undo;
- the **Lookout** page: outbound volume per sender, admins without 2FA, password policy and forwarding hosts;
- **Herd Health:** a mail dashboard for 24 hours, 7 days or 30 days (mail in and out, spam caught, refusals and why, bounces, failed sign-ins, the busiest mailboxes), from a history CowSec keeps itself;
- **Hoofprints**, the mail trail: search any message by sender, recipient, subject or IP and follow its journey step by step, with rspamd's score and the reason at every stop;
- **Show Ribbons:** a deliverability grade for every domain (DNS, DKIM, SPF, DMARC, MTA-STS, reverse DNS, blocklists), MTA-STS per domain, a new-domain wizard that watches DNS turn green, and one-click sign-in as a domain admin;
- domain admins and their permissions, rate limits, TLS policies, relay hosts and transports;
- mailcow's own **netfilter** ban engine, side by side with CrowdSec or with CrowdSec enforcing its bans.

It uses mailcow's own API, restricted to localhost. [Learn more →](docs/mailcow.md)

</td>
</tr>
</table>

## How it works

<p align="center">
  <a href="docs/assets/full/architecture.webp" title="Open full size"><img src="docs/assets/architecture.svg" alt="CowSec architecture" width="100%"></a>
</p>

Everything sits alongside mailcow. CowSec only uses mailcow's supported settings (`mailcow.conf`, `data/conf/postfix/extra.cf`, `data/assets/ssl`), so `./update.sh` keeps working. See [architecture.md](docs/architecture.md).

<p align="center">
  <a href="docs/assets/full/ban-ladder.webp" title="Open full size"><img src="docs/assets/ban-ladder.svg" alt="Escalating ban ladder" width="100%"></a>
</p>

## Quick start

```bash
sha256sum -c SHA256SUMS
sudo apt update && sudo apt install ./cowsec_*_amd64.deb
sudo cowsec-setup                      # prints https://<server>:9443 and a one-time token
```

Open the address, paste the token and follow the wizard. The full walkthrough with screenshots is in [docs/guide.md](docs/guide.md).

<details>
<summary><b>Screenshots</b></summary>
<br>

| Setup wizard | |
|---|---|
| <img src="docs/img/setup/02-checks.webp" alt="Pre-flight checks"> | <img src="docs/img/setup/05-certificates.webp" alt="Certificates"> |
| <img src="docs/img/setup/06-access.webp" alt="Access"> | <img src="docs/img/setup/09-installing.webp" alt="Installing"> |

| Console | |
|---|---|
| <img src="docs/img/console/ban-policy.webp" alt="Ban policy"> | <img src="docs/img/console/decisions.webp" alt="Decisions"> |
| <img src="docs/img/console/appsec-waf.webp" alt="AppSec WAF"> | <img src="docs/img/updates/finished.webp" alt="mailcow update with health checks"> |

| mailcow management | |
|---|---|
| <img src="docs/img/mail/farm.webp" alt="Farmhouse"> | <img src="docs/img/mail/mailboxes.webp" alt="Mailboxes"> |
| <img src="docs/img/mail/dns-records.webp" alt="DNS records checklist"> | <img src="docs/img/mail/queue.webp" alt="Mail queue"> |
| <img src="docs/img/mail/farmhands.webp" alt="Domain admins"> | <img src="docs/img/console/netfilter.webp" alt="mailcow netfilter and CrowdSec"> |
| <img src="docs/img/mail/mailbox-lockdown.webp" alt="Mailbox security and the lock-down playbook"> | <img src="docs/img/mail/lookout.webp" alt="Lookout: outbound mail, admins and 2FA, password policy"> |
| <img src="docs/img/mail/quarantine-preview.webp" alt="A quarantined message, shown safely"> | <img src="docs/img/mail/domain-footer.webp" alt="Domain footer with live preview"> |
| <img src="docs/img/mail/herd-health.webp" alt="Herd Health: the mail dashboard"> | <img src="docs/img/mail/mail-journey.webp" alt="Hoofprints: one message's journey"> |
| <img src="docs/img/mail/show-ribbons.webp" alt="Show Ribbons: deliverability grades"> | <img src="docs/img/mail/new-domain-dns.webp" alt="New-domain wizard"> |

</details>

## Documentation

| | |
|---|---|
| 🚀 [Installation walkthrough](docs/guide.md) | Every step of the wizard, with screenshots |
| 📋 [Requirements & headless install](docs/install.md) | What CowSec needs and exactly what it changes |
| 🌐 [Console access](docs/access.md) | LAN, Cloudflare Tunnel, internet, SSH |
| 🔐 [Certificates](docs/certificates.md) | DNS-01 providers, per-domain certificates, renewal |
| 🐄 [Ban policy](docs/ban-policy.md) | Home countries, abroad rule, escalation, allowlists |
| 🏡 [Managing mailcow](docs/mailcow.md) | Domains, mailboxes, aliases, DKIM, quarantine, queue, logs, mailbox security and lock-down, domain admins, rate limits, TLS, relays, netfilter |
| 🛡️ [Security model](docs/security.md) | Privileges, sign-in, setup token, what leaves the server |
| 🔧 [Maintenance](docs/maintenance.md) | Updates, reverting the edge, uninstalling |
| 🩺 [Troubleshooting](docs/troubleshooting.md) | Lock-outs, clocks, certificates, OpenResty |
| 🗺️ [Architecture](docs/architecture.md) | How the pieces fit together |
| 🤝 [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) | Bug reports, pull requests, and reporting vulnerabilities privately |
| 🧭 [Roadmap](docs/roadmap.md) | What's next: deeper mailcow control, a modern white-label webmail client |

## 🥛 Feed the cow

CowSec is free and always will be. Bessie works the night shift, eats spammers for breakfast and has never taken a sick day, but she does run on hay and coffee.

If CowSec saved you a weekend, a blocklisting or an awkward call from a customer, please toss a coin in the milk pail:

<p align="center">
  <a href="https://buymeacoffee.com/OryxAstro"><img src="docs/assets/buttons/buymeacoffee.svg" alt="Buy Bessie a latte on Buy Me a Coffee" height="64"></a>
  <a href="https://ko-fi.com/OryxAstro"><img src="docs/assets/buttons/kofi.svg" alt="Buy Bessie some hay on Ko-fi" height="64"></a>
</p>

Can't spare a coin? These are free and make her moo with joy:
- ⭐ **Star the repo.** It helps other mailcow admins find the farm.
- 👣 **[Follow the herd](https://github.com/OryxAstro)** for new releases and other projects.
- 🐛 **Report a bug or share an idea** in [Issues](https://github.com/OryxAstro/cowsec/issues). Bessie reads every one, slowly, while chewing.

## Building from source

```bash
make deb        # Go 1.23+, Node 20+, dpkg-deb → build/cowsec_<version>_amd64.deb
make test       # Go vet/tests and Python checks
make e2e COWSEC_E2E_CONFIG=config.json   # browser tests against a test server, see test/e2e
python3 docs/assets/src/generate.py   # regenerate the documentation artwork
```

Tagged releases (`v*`) are built and published by GitHub Actions with a `SHA256SUMS` file.

## License

Copyright © 2026 OryxAstro.

CowSec is free software, licensed under the [GNU Affero General Public License v3.0](LICENSE). You can use, study, change and share it. If you distribute a modified version, or run one for other people over a network, you must share its source code under the same licence.

CowSec installs and works alongside other projects that keep their own licences: mailcow (GPL-3.0), CrowdSec, OpenResty and others. It contains none of their code. "mailcow" and "CrowdSec" are trademarks of their respective owners; CowSec is an independent project and is not affiliated with or endorsed by either. Country flags are [Twemoji](https://github.com/twitter/twemoji) graphics (© Twitter and contributors), licensed CC-BY 4.0.
