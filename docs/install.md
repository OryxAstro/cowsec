# Installing CowSec

## Before you start

| Need | Why |
|---|---|
| Debian 11/12/13 or Ubuntu 22.04/24.04, amd64, systemd | The packages CowSec installs (CrowdSec, OpenResty, cloudflared) target these. |
| mailcow-dockerized, running | CowSec reads mailcow's config (`mailcow.conf`), containers and domain list. It looks in `/opt/mailcow-dockerized`, `/opt/mailcow` and `/srv/mailcow-dockerized`; set `MAILCOW_DIR` if yours lives elsewhere. |
| Root (sudo) | It installs packages, edits firewall and mailcow settings, and manages services. |
| Outbound HTTPS | To `packagecloud.io` (CrowdSec), `openresty.org` (OpenResty), `github.com` (lego), `pkg.cloudflare.com` (only for Cloudflare Tunnel). |
| An accurate clock | 2FA codes depend on it. On Proxmox/KVM, the wizard can sync to the hypervisor's clock. |
| No other CrowdSec | If CrowdSec already runs **in a container** (e.g. a compose override), remove it first: two engines double-ban. A CrowdSec already installed on the host is reused. |
| Ports | If you enable the edge: 80/443 are taken over by OpenResty; mailcow's web server moves to `127.0.0.1:8081/8443`. CowSec uses `127.0.0.1:8090` (console) and `:9443` (setup wizard, only until setup finishes). CrowdSec uses `127.0.0.1:8080` and `127.0.0.1:7422`. |

Back up before you start: a mailcow backup (`helper-scripts/backup_and_restore.sh`) and a VM snapshot if you can. CowSec also backs up every file it changes (`<file>.cowsec-bak-<timestamp>`).

## Install the package

```bash
sha256sum -c SHA256SUMS
sudo apt install ./cowsec_<version>_amd64.deb
```

The package installs:

| Path | What |
|---|---|
| `/usr/bin/cowsec` | the console server |
| `/usr/sbin/cowsec-setup` | the setup and management command |
| `/usr/lib/cowsec/` | the privileged helper and the installer |
| `/usr/share/cowsec/ui` | the web UI |

It then starts the `cowsec` service and prints the setup address. **Nothing else is changed until you run the setup.**

## Run the setup wizard

```bash
sudo cowsec-setup
```

This prints `https://<server-ip>:9443`, a one-time **setup token**, and the SHA-256 fingerprint of the wizard's temporary self-signed certificate. Open the address, check the fingerprint if you like, accept the browser warning, and paste the token.

1. **Checks.** These are read-only: OS, Docker, mailcow, running containers, port owners, `DOCKER-USER`, clock, disk, network. Failed checks must be fixed first; warnings are advisory.
2. **Protection.**
   - Home countries.
   - OpenResty edge + AppSec WAF.
   - Admin pages LAN-only.
   - "Behind Cloudflare's proxy" (only if your web hostnames are orange-clouded).
   - Precise clock.
   - Smart ban policy.
3. **Certificates.** Choose DNS-01 (pick your provider, enter its API credentials, then pick domains, per-domain or shared, and wildcard) or keep mailcow's own Let's Encrypt. Use **Test run** first if you're unsure about the credentials. See [certificates.md](certificates.md).
4. **Access.** Local network, Cloudflare Tunnel, internet, or this server only. See [access.md](access.md).
5. **Account.** Your first admin. You'll set up an authenticator app at the first sign-in.
6. **Install.** Each step shows live progress and a log. If the edge can't start, mailcow's web settings are restored automatically.

Click **Finish**. The wizard listener closes, and the console starts the way you chose.

## Headless install

Write a config (same fields as the wizard) and run:

```bash
sudo cowsec-setup check
sudo cowsec-setup install --config cowsec.json
sudo cowsec auth local-admin set alice
```

```json
{
  "homeCountries": ["GB"],
  "components": { "edge": true, "adminLanOnly": true, "cloudflareRealIP": false, "chronyPtp": false, "banPolicy": true },
  "certs": {
    "mode": "dns01",
    "provider": "cloudflare",
    "credentials": { "CF_DNS_API_TOKEN": "…" },
    "email": "admin@example.com",
    "domains": ["example.com", "example.org"],
    "perDomain": true,
    "wildcard": true,
    "staging": false
  },
  "access": { "mode": "lan", "hostname": "cowsec.example.com" },
  "lanRanges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8", "::1/128"]
}
```

`certs` can be `{ "mode": "mailcow" }`. For a tunnel, use `"access": { "mode": "tunnel", "tunnelToken": "…" }`. Delete the file afterwards: it holds secrets.

## What the installer changes

| Step | Changes |
|---|---|
| CrowdSec | Adds the CrowdSec apt repo (signed); installs `crowdsec`; installs the mail, web, SSH and Linux collections. |
| Detection | `/etc/crowdsec/acquis.d/cowsec-mailcow.yaml` (postfix + dovecot via Docker; web logs from OpenResty or nginx-mailcow); `parsers/s02-enrich/cowsec-private-whitelist.yaml` (your LAN). |
| Firewall | `crowdsec-firewall-bouncer-iptables`; `iptables_chains: [INPUT, DOCKER-USER]`. |
| Certificates | lego (pinned, checksum-verified) in `/usr/lib/cowsec/lego`. Secrets: `/etc/cowsec/dns.env` (root only). Certificates are copied into `data/assets/ssl/` (main + per-domain SNI folders) and `data/conf/postfix/extra.cf` + `cowsec_sni.map`. `SKIP_LETS_ENCRYPT=y`. Renewal runs on `cowsec-certs.timer`. |
| Edge | OpenResty repo + `openresty`, `crowdsec-openresty-bouncer`; `/usr/local/openresty/nginx/conf/{nginx.conf,cowsec_mailcow_proxy.conf,sites/cowsec-mailcow.conf}`; AppSec on `127.0.0.1:7422`; mailcow.conf `HTTP_BIND/HTTPS_BIND=127.0.0.1`, `HTTP_PORT=8081`, `HTTPS_PORT=8443`. |
| Cloudflare real IP | `cowsec-cloudflare-realip.timer` (monthly), writes `conf.d/cloudflare_realip.conf`. |
| Clock | chrony + `ptp_kvm` + `/etc/chrony/conf.d/cowsec-ptp.conf`. |
| Ban policy | `/etc/crowdsec/profiles.yaml` (original kept as `profiles.yaml.pre-cowsec`) and `scenarios/cowsec-auth-abroad.yaml`. |
| Access | `sites/cowsec-console.conf` (LAN/internet), or cloudflared + its service (tunnel); `/etc/cowsec/cowsec.env`. |

Everything under mailcow's directory survives `update.sh`. mailcow's own files are only changed through its supported override points (`mailcow.conf`, `data/conf/postfix/extra.cf`, `data/assets/ssl`).
