# CowSec 🐄🛡️

**A browser-based installer and console for [CrowdSec](https://www.crowdsec.net/) on a [mailcow-dockerized](https://github.com/mailcow/mailcow-dockerized) server.**

CowSec turns a stock mailcow host into a well-defended one in a few minutes, then gives you a friendly console to run it: who's banned and why, the WAF, hub collections, ban rules, updates and allowlists. Everything is managed from one place and protected by 2FA.

> CowSec is an independent community project. It is not affiliated with mailcow or CrowdSec.

## What you get

| Area | What CowSec sets up |
|---|---|
| **Detection** | CrowdSec with the postfix, dovecot, nginx, SSH, Linux and HTTP CVE collections, reading mailcow's logs through Docker. |
| **Firewall** | The CrowdSec firewall bouncer on `INPUT` **and `DOCKER-USER`**. mailcow's mail ports are Docker-published, so a bouncer on `INPUT` alone never blocks SMTP or IMAP. |
| **Web edge + WAF** *(optional, recommended)* | OpenResty in front of mailcow's web UI, with the CrowdSec Lua bouncer and the **AppSec WAF** (CVE virtual patching + generic rules). Admin pages can be restricted to your LAN. |
| **Certificates** *(optional)* | DNS-01 certificates via [lego](https://go-acme.github.io/lego/) with **190+ DNS providers**, wildcards, and **one certificate per domain** so your domains aren't listed together in one certificate. Deployed to the web UI, IMAP and SMTP (including SNI), and renewed automatically. New mailcow domains are picked up. |
| **Ban policy** | Home countries; a stricter rule for failed mail logins from elsewhere (stops slow password-spraying); **escalating bans** for repeat offenders (4h → 8h → … → 7 days), with home-country IPs exempt by default. |
| **Console** | Host health, bans with GeoIP (local database, nothing leaves the server), alerts, AppSec rules, hub install/upgrade, bouncers and machines, allowlists, ban policy, and package/hub updates. |
| **Access** | Local network only, internet via **Cloudflare Tunnel**, internet directly, or this server only (SSH tunnel). Switch any time. |
| **Sign-in** | Local accounts (or LDAP) plus TOTP, with optional Duo Push. Rate-limited, audited, CSRF-protected. |

<!-- Screenshots: docs/img/ (host, ban policy, updates, setup wizard) -->

## Requirements

- Debian 11/12/13 or Ubuntu 22.04/24.04, **amd64**, with systemd
- mailcow-dockerized installed and running (Docker Compose v2)
- Root access, and outbound HTTPS to `packagecloud.io`, `openresty.org` and `github.com`

See [docs/install.md](docs/install.md) for the full checklist.

## Install

```bash
# download the .deb and SHA256SUMS from the latest release, then:
sha256sum -c SHA256SUMS
sudo apt install ./cowsec_*_amd64.deb
sudo cowsec-setup          # prints the setup address and one-time token
```

Open `https://<server-ip>:9443`, paste the token, and follow the wizard:

1. Pre-flight checks.
2. Protection options.
3. Certificates.
4. Console access.
5. Your admin account.
6. Install.

The wizard shows every step live. When you finish, port 9443 closes for good and the console is available the way you chose.

Prefer the terminal? `sudo cowsec-setup install --config cowsec.json` runs the same steps headless ([example config](docs/install.md#headless-install)).

## Documentation

- [Installation and prerequisites](docs/install.md)
- [Console access: LAN, Cloudflare Tunnel, internet, SSH](docs/access.md)
- [Certificates (DNS-01, per-domain, providers)](docs/certificates.md)
- [Ban policy and escalation](docs/ban-policy.md)
- [Security model](docs/security.md)
- [Updating, reverting and uninstalling](docs/maintenance.md)
- [Troubleshooting](docs/troubleshooting.md)
- [How it fits together](docs/architecture.md)

## Building from source

```bash
make deb        # needs Go 1.23+, Node 20+, dpkg-deb
```

The package lands in `build/`. `make test` runs the Go and Python checks.
