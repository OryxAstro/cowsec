<p align="center">
  <img src="assets/setup-flow.svg" alt="CowSec setup: checks, protection, certificates, access, account, install" width="100%">
</p>

# Installation walkthrough

This guide follows a real installation on a fresh Debian 12 server running a stock mailcow-dockerized, from the package to a protected server with the console signed in. Every screenshot comes from that run. Domains and addresses are replaced with `example.com` and `192.0.2.x`.

> [!TIP]
> **Bare metal, VPS or VM: it all works the same.** CowSec needs Debian 11–13 or Ubuntu 22.04/24.04 (amd64), Docker with Compose v2, and mailcow already installed. On KVM guests (Proxmox and most VPSs) it can also sync the clock to the hypervisor.

## Contents

1. [Install the package](#1-install-the-package)
2. [Open the setup wizard](#2-open-the-setup-wizard)
3. [Checking the pasture](#3-checking-the-pasture)
4. [Protection](#4-protection)
5. [Certificates](#5-certificates)
6. [Console access](#6-console-access)
7. [Your admin account](#7-your-admin-account)
8. [Review and install](#8-review-and-install)
9. [First sign-in and 2FA](#9-first-sign-in-and-2fa)
10. [A tour of the console](#10-a-tour-of-the-console)

---

## 1. Install the package

Download `cowsec_<version>_amd64.deb` and `SHA256SUMS` from the latest release, then:

```bash
sha256sum -c SHA256SUMS
sudo apt install ./cowsec_<version>_amd64.deb
```

Installing the package changes nothing else on the server. It starts the `cowsec` service in **setup mode** and prints the wizard's address:

```text
  🐄 CowSec setup

  Open the setup wizard in your browser:

    https://192.0.2.10:9443

  Setup token:   3f9c…  (48 hex characters)
  Certificate SHA-256 (self-signed, check it matches your browser):
  9E:A1:5C:BB:…

  Port 9443 closes for good once setup is finished.
```

Run `sudo cowsec-setup` at any time to print it again.

## 2. Open the setup wizard

Browse to the address. The wizard uses a temporary self-signed certificate, so your browser warns once. Compare the fingerprint if you like, then continue. Paste the **setup token** to unlock it.

<p align="center"><img src="img/setup/01-unlock.webp" alt="Setup wizard: unlock with the token" width="720"></p>

> [!NOTE]
> The token is 192 bits, stored root-only, and rate-limited against guessing. Nothing in the wizard works until it's unlocked.

## 3. Checking the pasture

Before changing anything, CowSec inspects the server. It checks:

- the OS and architecture;
- systemd, Docker and Compose;
- the mailcow installation, its running containers and its domains;
- which ports are in use;
- the `DOCKER-USER` firewall chain;
- clock sync and the optional hypervisor clock;
- disk space, and that the package repositories can be reached.

A **red** check blocks the install. **Amber** is advice.

<p align="center"><img src="img/setup/02-checks.webp" alt="Checking the pasture: pre-flight checks" width="900"></p>

## 4. Protection

CrowdSec, the mailcow log readers and the firewall bouncer are always installed. Choose the extras:

| Option | What it does |
|---|---|
| **Home countries** | Failed logins from here follow CrowdSec's normal rules. Defaults to your browser's country. |
| **OpenResty edge with AppSec WAF** | A hardened reverse proxy in front of mailcow's web UI. The CrowdSec bouncer and WAF check every request. mailcow's own web server moves to localhost. |
| **Admin pages on the local network only** | `/admin` and `/domainadmin` answer only from private addresses. Webmail and ActiveSync stay public. |
| **Behind Cloudflare's proxy** | Trusts `CF-Connecting-IP` from Cloudflare's ranges (refreshed monthly), so bans hit visitors rather than Cloudflare. |
| **Accurate clock** | chrony with internet NTP; on KVM guests it also uses the hypervisor's clock. |
| **Manage mailcow from CowSec** | Domains, mailboxes, aliases, DKIM, quarantine, queue and logs from the console, via mailcow's API (localhost only). |
| **Smart ban policy** | Stricter rule for failed logins from abroad, plus escalating bans for repeat offenders. |

<p align="center"><img src="img/setup/03-protection.webp" alt="Protection options" width="900"></p>

## 5. Certificates

Pick **DNS-01** to get certificates through your DNS provider, with no port 80 and with wildcard support. Search for your provider among the 190+ that lego supports. The form shows exactly the credentials that provider needs.

<p align="center"><img src="img/setup/04-certificates.webp" alt="DNS-01 certificates with a provider picker" width="900"></p>

> [!TIP]
> Keep **One certificate per domain** on. A shared certificate lists every domain you host to anyone who looks at it. Turn on **Test run** the first time to prove your credentials against Let's Encrypt's staging servers.

Prefer to keep mailcow's own Let's Encrypt? Choose that card instead: the edge passes HTTP-01 challenges through to mailcow and reloads when mailcow renews.

## 6. Console access

Choose how you'll reach the console once setup closes:

<p align="center"><img src="img/setup/05-access.webp" alt="Console access modes" width="900"></p>

| Mode | Exposed | Best for |
|---|---|---|
| **Local network** | `https://<hostname>` on 443, refused from outside your LAN | Most homes and offices |
| **Cloudflare Tunnel** | Nothing: the server dials out to Cloudflare | Remote access without opening ports |
| **Internet, directly** | The sign-in page, behind CrowdSec, the WAF and 2FA | When a tunnel isn't an option |
| **This server only** | Nothing; use an SSH tunnel | Maximum lock-down |

See [access.md](access.md) for the details of each.

## 7. Your admin account

Create the first CowSec account. Passwords need 12+ characters. You'll enrol an authenticator app at your first sign-in.

<p align="center"><img src="img/setup/06-account.webp" alt="Create the admin account" width="720"></p>

## 8. Review and install

Check the summary, then **Install**.

<p align="center"><img src="img/setup/07-review.webp" alt="Review before installing" width="900"></p>

Each step reports live, with the full log underneath. Every file CowSec changes is backed up first (`*.cowsec-bak-<time>`). If the edge can't start, mailcow's original web settings are restored automatically.

<p align="center"><img src="img/setup/08-installing.webp" alt="Installation progress" width="900"></p>

<p align="center"><img src="img/setup/09-installed.webp" alt="Installation complete" width="900"></p>

**Finish and close setup** stops the wizard for good. Port 9443 closes.

<p align="center"><img src="img/setup/10-finished.webp" alt="Setup finished" width="720"></p>

## 9. First sign-in and 2FA

Open the console at the address you chose and sign in.

<p align="center"><img src="img/console/signin.webp" alt="CowSec sign-in" width="720"></p>

The first time, scan the QR code with an authenticator app (Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden…) and enter the 6-digit code.

<p align="center"><img src="img/console/enrol-2fa.webp" alt="Enrol an authenticator app" width="720"></p>

## 10. A tour of the console

The sidebar has four groups: **The Barn** (the host), **Fence & Gate** (protection), **The Farm** (mailcow management, see [Managing mailcow](mailcow.md)) and **Herd Watch** (detection).

### Barn Status

Health at a glance:
- services and timers;
- the firewall bouncer's ipsets;
- AppSec WAF traffic and top rules;
- log sources;
- certificate expiry;
- clock;
- mailcow containers.

It also has safe one-click service actions.

<p align="center"><img src="img/console/host.webp" alt="Barn Status: host health" width="900"></p>

### Fresh Hay (Updates)

Installed vs available versions for CrowdSec and its bouncers. Upgrades back up `/etc/crowdsec` and keep your config. This page also shows hub updates and the nightly auto-update switch.

<p align="center"><img src="img/console/updates.webp" alt="Updates" width="900"></p>

### Herd Rules (Ban policy)

The page has these sections:
- **Home countries.**
- **Abroad login rule.**
- **Escalating ban ladder.**
- **Repeat offenders.**
- **Failed logins by country:** looked up in the local GeoLite2 database, so nothing leaves the server.

See [ban-policy.md](ban-policy.md).

<p align="center"><img src="img/console/ban-policy.webp" alt="Ban policy" width="900"></p>

### Banned from the Herd (Decisions)

Active bans with country, network and scenario. Search by IP, country or scenario, ban an IP by hand, or lift a ban.

<p align="center"><img src="img/console/decisions.webp" alt="Decisions" width="900"></p>

### Electric Fence (AppSec WAF)

Every AppSec rule and CVE virtual patch, with filters and one-click toggles.

<p align="center"><img src="img/console/appsec-waf.webp" alt="AppSec WAF rules" width="900"></p>

### Trusted Herd (Allowlists)

Your own allowlist, applied instantly by CrowdSec's API and also filtering community blocklists, plus a read-only view of the whitelist parsers.

<p align="center"><img src="img/console/trusted-herd.webp" alt="Allowlists" width="900"></p>

### Moo Alerts, Feed Store (Hub), Bouncers & Herd Dogs

These three pages cover:
- **Moo Alerts:** recent alerts.
- **Feed Store:** the hub, where you install, upgrade or remove collections, parsers, scenarios and WAF rules.
- **Bouncers & Herd Dogs:** registered bouncers and machines.

<p align="center"><img src="img/console/alerts.webp" alt="Alerts" width="900"></p>
<p align="center"><img src="img/console/hub.webp" alt="Hub" width="900"></p>
<p align="center"><img src="img/console/bouncers-machines.webp" alt="Bouncers and machines" width="900"></p>

### Settings

Your account, authenticator reset and the sign-in activity log.

<p align="center"><img src="img/console/settings.webp" alt="Settings" width="720"></p>

---

**Next:** [Certificates](certificates.md) · [Ban policy](ban-policy.md) · [Security model](security.md) · [Maintenance](maintenance.md) · [Troubleshooting](troubleshooting.md)
