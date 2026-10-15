# How it fits together

```
                 internet / LAN
                       │
          ┌────────────┴─────────────────────────────────────────┐
          │ iptables: CROWDSEC chain on INPUT and DOCKER-USER     │ ◄── crowdsec-firewall-bouncer
          └────────────┬───────────────────────┬─────────────────┘
                       │ 80/443                │ 25/465/587/143/993/110/995/4190
               ┌───────▼────────┐        ┌─────▼──────────────────────────┐
               │ OpenResty edge │        │ mailcow containers              │
               │ Lua bouncer ───┼──► AppSec (127.0.0.1:7422)              │
               │ admin: LAN only│        │ postfix · dovecot · nginx · …   │
               └───┬────────┬───┘        └─────┬──────────────────────────┘
                   │        │                  │ logs (Docker API)
     mailcow web   │        │ console host     ▼
 127.0.0.1:8443 ◄──┘        └──► CowSec    CrowdSec engine + LAPI (127.0.0.1:8080)
                                127.0.0.1:8090     ▲   profiles.yaml (ban policy, escalation)
                                    │              │   cowsec-auth-abroad scenario
                                    ├── cscli ─────┘   allowlist "cowsec"
                                    └── cowsec-hostctl (allowlisted verbs, jobs, setup engine)
```

| Component | Language | Role |
|---|---|---|
| `cowsec` | Go | HTTP API, sign-in, static UI; setup listener until setup completes |
| `cowsec-hostctl` | Python | The only privileged entry point: status, service actions, policy, updates, jobs |
| `setup_engine.py` | Python | Pre-flight checks and idempotent install steps (used by the wizard and `cowsec-setup`) |
| `cowsec-setup` | Python | Terminal front-end: token, checks, headless install, access changes, revert |
| `web/` | React + Tailwind | Console and setup wizard |

Data: `/var/lib/cowsec` (accounts, sessions, audit log, policy, job logs, certificates); `/etc/cowsec` (settings and secrets).
