# Troubleshooting

## Where to look

```bash
systemctl status cowsec;  journalctl -u cowsec -n 100
sudo cowsec-setup check
ls /var/lib/cowsec/jobs/            # logs of setup and update jobs
journalctl -t cowsec-hostctl        # every privileged action CowSec ran
sudo cscli metrics                  # acquisition, parsers, bouncers
```

## I locked myself out of mail or the console

Lift the ban from the server:

```bash
sudo cscli decisions list --ip <your-ip>
sudo cscli decisions delete --ip <your-ip>
sudo cscli allowlists add cowsec <your-ip> -d "my office"   # never ban it again
```

Your LAN ranges are always whitelisted.

## "TOTP code invalid" at sign-in

The server clock is off. `timedatectl` should show `System clock synchronized: yes`. On Proxmox/KVM, enable the precise clock option (`cowsec-setup reset-wizard`), or install chrony.

To reset someone's authenticator: `sudo cowsec auth totp reset <user>`.

## The wizard stopped during "OpenResty edge"

CowSec restores `mailcow.conf` and restarts mailcow's web server automatically. Check `journalctl -u openresty`. Usual causes: another web server on 80/443 (`ss -ltnp | grep -E ':80 |:443 '`), or a missing certificate path. Fix it, then run **Install** again.

## Certificates failed (DNS-01)

The job log shows lego's output. Common causes:

- The credentials lack DNS edit rights for that zone.
- The domain's DNS isn't hosted at that provider.
- A CAA record forbids Let's Encrypt.

Try **Test run (staging)** while you fix it.

## Bans don't stop mail traffic

Check that the firewall bouncer hooks Docker traffic: `sudo iptables -S DOCKER-USER | grep CROWDSEC`. If it's missing, `sudo systemctl restart crowdsec-firewall-bouncer`.

## Events are counted twice

If another acquisition file also reads mailcow's postfix or dovecot containers, every failed login counts twice. Setup warns about this. Remove the duplicate entries from `/etc/crowdsec/acquis.yaml` or `acquis.d/`.

## OpenResty fails with `module 'resty.http' not found`

The OpenResty bouncer needs the `lua-resty-http` library. Its package script downloads it from OpenResty's package server (`opm`) and silently ignores failures. CowSec checks for it and, if `opm` is unavailable, installs the same tagged release from GitHub (checksum pinned). To fix an older install by hand:

```bash
sudo opm get ledgetech/lua-resty-http=0.17.1 && sudo systemctl restart openresty
```
