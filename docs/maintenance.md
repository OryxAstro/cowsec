# Updating, reverting and uninstalling

## Updating CowSec

```bash
sha256sum -c SHA256SUMS
sudo apt install ./cowsec_<new-version>_amd64.deb
```

Settings, accounts, the ban policy and certificates are kept.

## Updating CrowdSec and the bouncers

Use **Fresh Hay (Updates)** in the console:

| Action | What it does |
|---|---|
| **Check for new versions** | Runs `apt-get update`. |
| **Upgrade CrowdSec & bouncers** | Backs up `/etc/crowdsec` to `/root/crowdsec-backup-<time>.tgz`, then upgrades `crowdsec` and both bouncers, keeping your config files. It tests the config, restarts the engine and firewall bouncer, and reloads OpenResty only if its config passes. |
| **Update hub now** | `cscli hub update && cscli hub upgrade`, then reloads CrowdSec. |
| **Nightly auto-update** | Turns CrowdSec's own `crowdsec-hubupdate.timer` on or off. |

Upgrades are signed apt packages; OpenResty and cloudflared update with your normal system updates.

## mailcow updates

`./update.sh` is safe. CowSec only uses mailcow's supported settings (`mailcow.conf`, `data/conf/postfix/extra.cf`, `data/assets/ssl`), and reads containers by their Compose labels, so renamed or recreated containers are picked up.

## Changing your choices

```bash
sudo cowsec-setup access lan|wan|tunnel|local ...   # console access
sudo cowsec-setup reset-wizard                      # run the browser wizard again
```

Re-running the wizard is safe: every step is idempotent, and files are backed up before they change.

## Undoing the OpenResty edge

```bash
sudo cowsec-setup revert-edge
```

This stops OpenResty and restores the `mailcow.conf` from before CowSec first changed it, so mailcow's nginx takes 80/443 again. CrowdSec and the firewall bouncer keep running. If you used DNS-01, set `SKIP_LETS_ENCRYPT=n` in `mailcow.conf` and run `docker compose up -d` if you want mailcow's own Let's Encrypt back.

## Uninstalling

```bash
sudo cowsec-setup revert-edge          # if you used the edge
sudo apt remove cowsec                 # stops the console; CrowdSec keeps protecting you
sudo apt purge cowsec                  # also removes /etc/cowsec and /var/lib/cowsec
```

CrowdSec, its bouncers, OpenResty and cloudflared are separate packages and stay installed. Remove them with apt if you no longer want them. To return to CrowdSec's stock ban profile, run `sudo cp /etc/crowdsec/profiles.yaml.pre-cowsec /etc/crowdsec/profiles.yaml && sudo rm /etc/crowdsec/scenarios/cowsec-auth-abroad.yaml && sudo systemctl reload crowdsec`.
