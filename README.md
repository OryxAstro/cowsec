<p align="center">
  <img src="docs/assets/banner.svg" alt="CowSec: the browser installer and security console for CrowdSec on mailcow" width="100%">
</p>

<p align="center">
  <img alt="Debian and Ubuntu" src="https://img.shields.io/badge/Debian%2011--13%20·%20Ubuntu%2022.04%2F24.04-0b1530?style=for-the-badge&logo=debian&logoColor=a5b4fc&labelColor=050a18">
  <img alt="mailcow-dockerized" src="https://img.shields.io/badge/mailcow--dockerized-0b1530?style=for-the-badge&logo=docker&logoColor=7dd3fc&labelColor=050a18">
  <img alt="CrowdSec 1.7+" src="https://img.shields.io/badge/CrowdSec-1.7%2B-0b1530?style=for-the-badge&logoColor=6ee7b7&labelColor=050a18">
  <img alt="amd64" src="https://img.shields.io/badge/arch-amd64-0b1530?style=for-the-badge&labelColor=050a18">
</p>

<p align="center">
  <b>Turn a stock mailcow server into a well-defended one in minutes, then run it from a friendly console.</b><br>
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

> CowSec is an independent community project. It is not affiliated with mailcow or CrowdSec.

## Features

<table>
<tr>
<td width="50%" valign="top">

**🧱 Fence & Gate: protection**
- Firewall bouncer on **`INPUT` and `DOCKER-USER`**. mailcow's mail ports are Docker-published, so a bouncer on `INPUT` alone never blocks SMTP or IMAP.
- **OpenResty edge** with the CrowdSec Lua bouncer and **AppSec WAF** (CVE virtual patching + generic rules).
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
- Console for bans, alerts, the WAF, the hub, bouncers, policy and **one-click updates**.
- **2FA sign-in** (TOTP or Duo), local accounts or LDAP, audit log.
- Reach it on your **LAN**, through a **Cloudflare Tunnel**, the internet, or SSH only.

</td>
</tr>
</table>

## How it works

<p align="center">
  <img src="docs/assets/architecture.svg" alt="CowSec architecture" width="100%">
</p>

Everything sits alongside mailcow. CowSec only uses mailcow's supported settings (`mailcow.conf`, `data/conf/postfix/extra.cf`, `data/assets/ssl`), so `./update.sh` keeps working. See [architecture.md](docs/architecture.md).

<p align="center">
  <img src="docs/assets/ban-ladder.svg" alt="Escalating ban ladder" width="100%">
</p>

## Quick start

```bash
sha256sum -c SHA256SUMS
sudo apt install ./cowsec_*_amd64.deb
sudo cowsec-setup                      # prints https://<server>:9443 and a one-time token
```

Open the address, paste the token and follow the wizard. The full walkthrough with screenshots is in [docs/guide.md](docs/guide.md).

<details>
<summary><b>Screenshots</b></summary>
<br>

| Setup wizard | |
|---|---|
| <img src="docs/img/setup/02-checks.webp" alt="Pre-flight checks"> | <img src="docs/img/setup/04-certificates.webp" alt="Certificates"> |
| <img src="docs/img/setup/05-access.webp" alt="Access"> | <img src="docs/img/setup/08-installing.webp" alt="Installing"> |

| Console | |
|---|---|
| <img src="docs/img/console/ban-policy.webp" alt="Ban policy"> | <img src="docs/img/console/decisions.webp" alt="Decisions"> |
| <img src="docs/img/console/appsec-waf.webp" alt="AppSec WAF"> | <img src="docs/img/console/updates.webp" alt="Updates"> |

</details>

## Documentation

| | |
|---|---|
| 🚀 [Installation walkthrough](docs/guide.md) | Every step of the wizard, with screenshots |
| 📋 [Requirements & headless install](docs/install.md) | What CowSec needs and exactly what it changes |
| 🌐 [Console access](docs/access.md) | LAN, Cloudflare Tunnel, internet, SSH |
| 🔐 [Certificates](docs/certificates.md) | DNS-01 providers, per-domain certificates, renewal |
| 🐄 [Ban policy](docs/ban-policy.md) | Home countries, abroad rule, escalation, allowlists |
| 🛡️ [Security model](docs/security.md) | Privileges, sign-in, setup token, what leaves the server |
| 🔧 [Maintenance](docs/maintenance.md) | Updates, reverting the edge, uninstalling |
| 🩺 [Troubleshooting](docs/troubleshooting.md) | Lock-outs, clocks, certificates, OpenResty |
| 🗺️ [Architecture](docs/architecture.md) | How the pieces fit together |

## Building from source

```bash
make deb        # Go 1.23+, Node 20+, dpkg-deb → build/cowsec_<version>_amd64.deb
make test       # Go vet/tests and Python checks
python3 docs/assets/src/generate.py   # regenerate the documentation artwork
```

Tagged releases (`v*`) are built and published by GitHub Actions with a `SHA256SUMS` file.
