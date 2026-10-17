"""CowSec setup engine: pre-flight checks and the install steps for CrowdSec, the
firewall bouncer, the web edge (OpenResty, or Debian's nginx on Debian 13) with AppSec, certificates and console access on a
mailcow-dockerized host.

Used by the setup wizard (through cowsec-hostctl jobs) and by the `cowsec-setup` CLI.
Every step is idempotent and backs up any file it changes (<file>.cowsec-bak-<time>).
Secrets (DNS provider credentials, tunnel tokens) are written only to root-only files
under /etc/cowsec and are never logged.
"""
import glob
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

STATE_DIR = os.environ.get("COWSEC_STATE_DIR", "/var/lib/cowsec")
ETC_DIR = "/etc/cowsec"
LIB_DIR = "/usr/lib/cowsec"
HOSTCTL = os.path.join(LIB_DIR, "cowsec-hostctl")
CS_DIR = "/etc/crowdsec"
OPENRESTY = "/usr/local/openresty"
NGX = OPENRESTY + "/nginx/conf"
ACME_DIR = os.path.join(STATE_DIR, "acme")
CERT_DIR = os.path.join(STATE_DIR, "certs")
MAILCOW_CANDIDATES = ("/opt/mailcow-dockerized", "/opt/mailcow", "/srv/mailcow-dockerized", "/root/mailcow-dockerized")

LEGO_VERSION = "5.5.2"
LEGO_SHA256 = "2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef"
LEGO_URL = "https://github.com/go-acme/lego/releases/download/v{v}/lego_v{v}_linux_amd64.tar.gz".format(v=LEGO_VERSION)
LEGO_BIN = os.path.join(LIB_DIR, "lego")
DEFAULT_RESOLVERS = ["1.1.1.1:53", "9.9.9.9:53"]

# Lua HTTP client the OpenResty bouncer needs. Its package script fetches it with opm and
# ignores failures, so CowSec checks and falls back to the pinned GitHub release.
RESTY_HTTP_VERSION = "0.17.1"
RESTY_HTTP_URL = "https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v%s.tar.gz" % RESTY_HTTP_VERSION
RESTY_HTTP_SHA256 = "f52a0538b20a2d45025f318c18a138b78f6f88f07713dd0ed502183cb3d16f17"
RESTY_DIR = "/usr/local/openresty/site/lualib/resty"

# The web edge in front of mailcow: OpenResty wherever its packages can be installed. On Debian 13,
# whose apt rejects OpenResty's SHA-1-bound signing key (see openresty_blocked), the edge is Debian's
# own nginx with its Lua module and CrowdSec's nginx bouncer: the same bouncer library and AppSec WAF,
# every package signed by Debian or CrowdSec. use_edge() points the globals below at one of them.
EDGES = {
    "openresty": {"name": "OpenResty", "service": "openresty", "conf": OPENRESTY + "/nginx/conf", "bin": OPENRESTY + "/bin/openresty",
                  "logs": "/var/log/openresty", "bouncer": "crowdsec-openresty-bouncer", "resty": RESTY_DIR},
    "nginx": {"name": "nginx", "service": "nginx", "conf": "/etc/nginx", "bin": "/usr/sbin/nginx",
              "logs": "/var/log/nginx", "bouncer": "crowdsec-nginx-bouncer", "resty": "/usr/local/share/lua/5.1/resty"},
}
EDGE_FILE = ETC_DIR + "/edge"   # which flavour this server's edge uses, written when the edge is installed
EDGE_KIND = "openresty"
EDGE_SVC = "openresty"
EDGE_BIN = OPENRESTY + "/bin/openresty"
EDGE_LOGS = "/var/log/openresty"
EDGE_BOUNCER = "crowdsec-openresty-bouncer"
EDGE_BOUNCER_CONF = CS_DIR + "/bouncers/crowdsec-openresty-bouncer.conf"

# mailcow's web ports move here when the OpenResty edge takes over 80/443, bound to 127.0.0.1 as
# mailcow's reverse-proxy guide says (docs.mailcow.email/post_installation/reverse-proxy/r_p/). Its
# example is 8080/8443, but 8080 is CrowdSec's local API, and the guide forbids 8081, 9081 and 65510,
# which mailcow's nginx uses internally (8081 answers postfix's forwarding-host lookups).
EDGE_MAILCOW_HTTP = 8180
OLD_EDGE_MAILCOW_HTTP = 8081  # used up to 0.3.9; it collided with mailcow's internal lookup server
EDGE_MAILCOW_HTTPS = 8443
CONSOLE_ADDR = "127.0.0.1:8090"
PRIVATE_RANGES = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"]
COLLECTIONS = ["crowdsecurity/linux", "crowdsecurity/sshd", "crowdsecurity/postfix", "crowdsecurity/dovecot",
               "crowdsecurity/nginx", "crowdsecurity/base-http-scenarios", "crowdsecurity/http-cve",
               "crowdsecurity/whitelist-good-actors"]
APPSEC_COLLECTIONS = ["crowdsecurity/appsec-virtual-patching", "crowdsecurity/appsec-generic-rules"]


class StepError(Exception):
    pass


# ---------------------------------------------------------------- utilities

class Runner:
    """Runs commands and records a log. Secrets passed in `redact` never reach the log."""

    def __init__(self, log_path=None, echo=False):
        self.log_path, self.echo, self.redact = log_path, echo, []

    def log(self, msg):
        for s in self.redact:
            if s:
                msg = msg.replace(s, "••••")
        msg = re.sub(r"(?i)(api[ _-]?key\s*[:=]\s*)\S+", r"\1••••", msg)  # e.g. bouncer postinst output
        line = time.strftime("%H:%M:%S ") + msg
        if self.echo:
            print(line, flush=True)
        if self.log_path:
            with open(self.log_path, "a") as f:
                f.write(line + "\n")

    def sh(self, cmd, check=True, env=None, timeout=900, quiet=False, input=None, cwd=None):
        shown = cmd if isinstance(cmd, str) else " ".join(cmd)
        if not quiet:
            self.log("$ " + shown)
        full_env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", **(env or {}))
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, env=full_env,
                           timeout=timeout, input=input, cwd=cwd)
        out = (p.stdout + p.stderr).strip()
        if out and not quiet:
            for l in out.splitlines()[-25:]:
                self.log("  " + l)
        if check and p.returncode != 0:
            raise StepError("command failed (%d): %s" % (p.returncode, shown))
        return p.returncode, out


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except Exception as e:
        return 1, str(e)


def backup(path, r):
    if os.path.exists(path):
        dst = "%s.cowsec-bak-%s" % (path, time.strftime("%Y%m%d%H%M%S"))
        shutil.copy2(path, dst)
        r.log("backed up %s -> %s" % (path, dst))


def write(path, text, mode=0o644, r=None, keep_backup=True):
    """Writes atomically; returns True if the content changed."""
    old = open(path).read() if os.path.exists(path) else None
    if old == text:
        return False
    if r and keep_backup and old is not None:
        backup(path, r)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".cowsec-tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    if r:
        r.log("wrote %s" % path)
    return True


def read_kv(path):
    out = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def set_kv(path, values, r):
    """Sets KEY=value lines in a shell-style config, keeping comments and order."""
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    done = set()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*#?\s*([A-Z0-9_]+)=", line)
        if m and m.group(1) in values and m.group(1) not in done:
            if line.lstrip().startswith("#") and any(re.match(r"^\s*%s=" % m.group(1), l) for l in lines):
                continue
            lines[i] = "%s=%s" % (m.group(1), values[m.group(1)])
            done.add(m.group(1))
    for k, v in values.items():
        if k not in done:
            lines.append("%s=%s" % (k, v))
    mode = os.stat(path).st_mode & 0o777 if os.path.exists(path) else 0o644
    return write(path, "\n".join(lines) + "\n", mode, r)


def os_release():
    d = read_kv("/etc/os-release")
    return d.get("ID", ""), d.get("VERSION_ID", ""), d.get("VERSION_CODENAME", "")


def ipv6_enabled():
    return os.path.exists("/proc/net/if_inet6") and os.path.getsize("/proc/net/if_inet6") > 0 if os.path.exists("/proc/net/if_inet6") else False


def download(url, dest, sha256=None, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "cowsec-setup"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest, "wb") as f:
        shutil.copyfileobj(resp, f)
    if sha256:
        h = hashlib.sha256(open(dest, "rb").read()).hexdigest()
        if h != sha256:
            os.remove(dest)
            raise StepError("checksum mismatch for %s (got %s)" % (url, h))


def apt_key_repo(r, name, key_url, line, keyring):
    """Adds a signed apt repository (key dearmored into its own keyring)."""
    list_path = "/etc/apt/sources.list.d/%s.list" % name
    if os.path.exists(keyring) and os.path.exists(list_path) and open(list_path).read().strip() == line:
        r.log("apt repository %s already configured" % name)
        return False
    url = re.search(r"https?://\S+", line).group(0).rstrip("/")
    for f in ["/etc/apt/sources.list"] + glob.glob("/etc/apt/sources.list.d/*"):
        if ".cowsec-bak-" in f or (f == list_path and not os.path.exists(keyring)):
            continue
        if os.path.isfile(f) and url.split("://", 1)[1] in open(f, errors="replace").read():
            # a second entry with a different signed-by makes apt refuse to run at all
            r.log("apt repository %s already configured in %s; using that" % (name, f))
            return False
    os.makedirs(os.path.dirname(keyring), exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        key = os.path.join(td, "key")
        download(key_url, key)
        r.sh(["gpg", "--batch", "--yes", "--dearmor", "-o", keyring, key])
    os.chmod(keyring, 0o644)
    write(list_path, line + "\n", r=r)
    return True


POLICY_RC = "/usr/sbin/policy-rc.d"


APT_LOCKS = ("/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock", "/var/lib/apt/lists/lock")


def wait_for_apt(r, timeout=1200):
    """Fresh cloud servers run unattended upgrades on first boot; wait for them rather than fail."""
    import fcntl
    deadline, said = time.time() + timeout, False
    while True:
        busy = None
        for path in APT_LOCKS:
            if not os.path.exists(path):
                continue
            with open(path, "w") as f:
                try:
                    fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.lockf(f, fcntl.LOCK_UN)
                except OSError:
                    busy = path
                    break
        if not busy:
            return
        if time.time() > deadline:
            raise StepError("apt is still busy after %d minutes (%s is locked)" % (timeout // 60, busy))
        if not said:
            r.log("waiting for another apt/dpkg run to finish (e.g. unattended upgrades)…")
            said = True
        time.sleep(5)


def apt_install(r, pkgs, no_start=False):
    """Installs missing packages. no_start keeps maintainer scripts from starting services
    (e.g. OpenResty would try to bind port 80 while mailcow still holds it)."""
    missing = [p for p in pkgs if run(["dpkg-query", "-W", "-f=${Status}", p])[1] != "install ok installed"]
    if not missing:
        r.log("already installed: " + ", ".join(pkgs))
        return
    own_policy = no_start and not os.path.exists(POLICY_RC)
    if own_policy:
        write(POLICY_RC, "#!/bin/sh\n# temporary, CowSec setup: do not start services during package installation\nexit 101\n", 0o755)
    wait_for_apt(r)
    try:
        r.sh(["dpkg", "--configure", "-a"], check=False)  # finish any interrupted earlier attempt
        r.sh(["apt-get", "update", "-q"])
        r.sh(["apt-get", "install", "-y", "-q", "-o", "DPkg::Lock::Timeout=600", "-o", "Dpkg::Options::=--force-confold"] + missing)
    finally:
        if own_policy and os.path.exists(POLICY_RC):
            os.remove(POLICY_RC)


# ---------------------------------------------------------------- mail WAF (AppSec rule curation)

APPSEC_CONFIG_NAME = "cowsec/mail-waf"
APPSEC_CONFIG_FILE = CS_DIR + "/appsec-configs/cowsec-mail-waf.yaml"
APPSEC_WATCH_SCENARIO = CS_DIR + "/scenarios/cowsec-appsec-watch.yaml"
APPSEC_ACQUIS = CS_DIR + "/acquis.d/cowsec-appsec.yaml"
APPSEC_POLICY = os.path.join(STATE_DIR, "appsec-policy.json")
# Always in the request path: probes that never belong on a mail server, whatever else it runs.
APPSEC_BLOCK_ALWAYS = ("crowdsecurity/base-config", "crowdsecurity/vpatch-env-access", "crowdsecurity/vpatch-git-config",
                       "crowdsecurity/vpatch-laravel-debug-mode", "crowdsecurity/vpatch-symfony-profiler",
                       "crowdsecurity/vpatch-CVE-2017-9841", "crowdsecurity/vpatch-CVE-2024-4577", "crowdsecurity/generic-freemarker-ssti")
# Also blocking: patches for the mail stack and webmail people run beside mailcow. Matched by
# name and description, so future patches for these products block without a CowSec update.
APPSEC_MAIL_RE = re.compile(r"\b(roundcube|squirrelmail|sogo|zimbra|exchange|smartermail|afterlogic|webmail|horde|rainloop|snappymail|"
                            r"mailcow|postfix|dovecot|rspamd|nginx|openresty)\b", re.I)
APPSEC_NEVER_BAN = ("crowdsecurity/appsec-generic-test", "crowdsecurity/experimental-no-user-agent")


def appsec_overrides():
    try:
        o = json.load(open(APPSEC_POLICY)).get("overrides") or {}
        return {k: v for k, v in o.items() if v in ("block", "watch")}
    except Exception:
        return {}


def appsec_plan():
    """Every installed AppSec rule and the mode the mail WAF gives it: block (in the request
    path), watch (checked after the response; trips ban scanners) or off (not installed)."""
    rc, out = run(["cscli", "appsec-rules", "list", "-a", "-o", "json"], timeout=60)
    if rc != 0:
        raise StepError("could not list AppSec rules: " + out[-300:])
    data = json.loads(out)
    items = data.get("appsec-rules", data) if isinstance(data, dict) else data
    rules = appsec_classify(items, appsec_overrides())
    return {"config": APPSEC_CONFIG_NAME, "active": appsec_active_config(), "rules": rules,
            "counts": {m: sum(1 for r in rules if r["mode"] == m) for m in ("block", "watch", "off")}}


def appsec_classify(items, over):
    """Each rule's mode from cscli's list and the user's pinned choices (no system access)."""
    rules = []
    for i in items:
        name = i.get("name", "")
        if name == "crowdsecurity/base-config":
            continue
        installed = (i.get("status") or "").split(",")[0] == "enabled"
        desc = i.get("description") or ""
        auto = "block" if (name in APPSEC_BLOCK_ALWAYS or APPSEC_MAIL_RE.search(name + " " + desc)) else "watch"
        mode = over.get(name, auto) if installed else "off"
        rules.append({"name": name, "description": desc, "auto": auto, "mode": mode, "override": name in over, "installed": installed})
    rules.sort(key=lambda r: ({"block": 0, "watch": 1, "off": 2}[r["mode"]], r["name"]))
    return rules


def appsec_active_config():
    try:
        m = re.search(r"^\s*appsec_config:\s*(\S+)", open(APPSEC_ACQUIS).read(), re.M)
        return m.group(1) if m else None
    except OSError:
        return None


def appsec_curate(r, only_if_default=False):
    """Writes CowSec's mail WAF config and the scanner-ban scenario, points the edge's AppSec
    engine at it, and checks CrowdSec accepts it, putting everything back if not."""
    if not os.path.exists(APPSEC_ACQUIS):
        return {"skipped": "no CowSec AppSec engine on this server"}
    acquis = open(APPSEC_ACQUIS).read()
    if only_if_default and appsec_active_config() not in ("crowdsecurity/appsec-default", APPSEC_CONFIG_NAME):
        return {"skipped": "AppSec uses %s; left alone" % appsec_active_config()}
    plan = appsec_plan()
    block = ["crowdsecurity/base-config"] + [x["name"] for x in plan["rules"] if x["mode"] == "block"]
    conf = ("# Managed by CowSec: the mail WAF. Rules for the mail stack block in the request path;\n"
            "# every other rule only watches (after the response) and bans the scanners that trip it.\n"
            "# Change a rule's mode in the console (Electric Fence) rather than here.\n"
            "name: %s\ndefault_remediation: ban\ninband_rules:\n%s"
            "outofband_rules:\n - crowdsecurity/vpatch-*\n - crowdsecurity/generic-*\n - crowdsecurity/experimental-*\n - crowdsecurity/appsec-generic-test\n"
            % (APPSEC_CONFIG_NAME, "".join(" - %s\n" % n for n in block)))
    scen = ("# Managed by CowSec: ban scanners that trip a watch-only (out-of-band) mail WAF rule.\n"
            "type: leaky\nname: cowsec/appsec-watch\n"
            "description: \"Probing for exploits of software this server doesn't run (CowSec mail WAF, watch-only rules)\"\n"
            "filter: \"evt.Meta.log_type == 'appsec-info' && evt.Meta.rule_name not in [%s]\"\n"
            "leakspeed: \"60s\"\ncapacity: 1\ngroupby: evt.Meta.source_ip\nblackhole: 1m\n"
            "labels:\n  remediation: true\n  service: http\n  behavior: \"http:exploit\"\n  label: \"Exploit probe (watch-only WAF rule)\"\n"
            "  confidence: 3\n  spoofable: 0\n" % ", ".join("'%s'" % n for n in APPSEC_NEVER_BAN))
    olds = {f: (open(f).read() if os.path.exists(f) else None) for f in (APPSEC_CONFIG_FILE, APPSEC_WATCH_SCENARIO, APPSEC_ACQUIS)}
    os.makedirs(os.path.dirname(APPSEC_CONFIG_FILE), exist_ok=True)
    write(APPSEC_CONFIG_FILE, conf, r=r, keep_backup=False)
    write(APPSEC_WATCH_SCENARIO, scen, r=r, keep_backup=False)
    write(APPSEC_ACQUIS, re.sub(r"^(\s*appsec_config:\s*)\S+", r"\g<1>" + APPSEC_CONFIG_NAME, acquis, count=1, flags=re.M), r=r,
          keep_backup=appsec_active_config() != APPSEC_CONFIG_NAME)
    rc, out = run(["crowdsec", "-c", CS_DIR + "/config.yaml", "-t"], timeout=120)
    if rc != 0:
        for f, txt in olds.items():
            if txt is None:
                os.path.exists(f) and os.remove(f)
            else:
                write(f, txt, r=r, keep_backup=False)
        raise StepError("CrowdSec rejected the mail WAF config, so the previous one was kept: " + out[-300:])
    r.sh(["systemctl", "reload-or-restart", "crowdsec"], check=False)
    r.log("mail WAF: %d rules block in the request path, %d watch for scanners" % (plan["counts"]["block"], plan["counts"]["watch"]))
    return {"counts": plan["counts"], "config": APPSEC_CONFIG_NAME}


def appsec_set_mode(name, mode, r):
    """Pin one rule to block or watch ('auto' clears the pin), then rebuild the config."""
    if not re.fullmatch(r"crowdsecurity/[A-Za-z0-9._-]+", name) or mode not in ("block", "watch", "auto"):
        raise StepError("invalid rule or mode")
    try:
        pol = json.load(open(APPSEC_POLICY))
    except Exception:
        pol = {}
    over = pol.get("overrides") or {}
    if mode == "auto":
        over.pop(name, None)
    else:
        over[name] = mode
    pol["overrides"] = over
    write(APPSEC_POLICY, json.dumps(pol, indent=2) + "\n", mode=0o600, keep_backup=False)
    return appsec_curate(r)


# ---------------------------------------------------------------- safety net

SNAPSHOT_DIR = "/var/backups/cowsec"
SNAPSHOT_POINTER = os.path.join(STATE_DIR, "pre-install-snapshot")
MAILCOW_FILES = ("mailcow.conf", "docker-compose.override.yml", "data/conf/postfix/extra.cf", "data/assets/ssl")


def step_snapshot(c, r, ctx):
    """Before anything changes: save mailcow's settings and certificates, CrowdSec's config and
    the firewall rules in one archive, so `cowsec-setup restore-mailcow` can put mailcow back."""
    import tarfile, io
    mc = ctx["mailcow"]["dir"]
    os.makedirs(SNAPSHOT_DIR, mode=0o700, exist_ok=True)
    os.chmod(SNAPSHOT_DIR, 0o700)
    path = os.path.join(SNAPSHOT_DIR, "pre-install-%s.tar.gz" % time.strftime("%Y%m%d-%H%M%S"))
    def add_text(tar, name, text):
        data = text.encode()
        info = tarfile.TarInfo(name)
        info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
        tar.addfile(info, io.BytesIO(data))
    with tarfile.open(path, "w:gz") as tar:
        for rel in MAILCOW_FILES:
            src = os.path.join(mc, rel)
            if os.path.exists(src):
                tar.add(src, arcname="mailcow/" + rel)
        if os.path.isdir(CS_DIR):
            tar.add(CS_DIR, arcname="crowdsec" + CS_DIR)
        for name, cmd in (("iptables.rules", ["iptables-save"]), ("ip6tables.rules", ["ip6tables-save"]), ("nftables.rules", ["nft", "list", "ruleset"])):
            rc, out = run(cmd)
            if rc == 0:
                add_text(tar, "firewall/" + name, out + "\n")
        add_text(tar, "MANIFEST", "CowSec pre-install snapshot\ncreated: %s\nmailcow: %s\nrestore: sudo cowsec-setup restore-mailcow --from %s\n"
                 % (time.strftime("%Y-%m-%d %H:%M:%S %Z"), mc, path))
    os.chmod(path, 0o600)
    write(SNAPSHOT_POINTER, path + "\n", mode=0o600, keep_backup=False)
    r.log("saved mailcow's settings, certificates, CrowdSec's config and the firewall rules to %s" % path)


def restore_mailcow(r, path=None):
    """Put mailcow's own files back exactly as they were before CowSec, give 80/443 back to
    mailcow's nginx and restart it. CrowdSec and its bouncers are left running."""
    import tarfile
    if not path:
        if not os.path.exists(SNAPSHOT_POINTER):
            raise StepError("no pre-install snapshot recorded; look in %s" % SNAPSHOT_DIR)
        path = open(SNAPSHOT_POINTER).read().strip()
    if not os.path.isfile(path):
        raise StepError("snapshot not found: %s" % path)
    mc = find_mailcow()
    if not mc:
        raise StepError("mailcow not found")
    with tarfile.open(path, "r:gz") as tar:
        members = [m for m in tar.getmembers() if m.name.startswith("mailcow/") and ".." not in m.name.split("/") and (m.isfile() or m.isdir())]
        if not any(m.name == "mailcow/mailcow.conf" for m in members):
            raise StepError("this snapshot has no mailcow.conf")
        # keep today's files next to the restored ones, in case they're wanted later
        for rel in MAILCOW_FILES:
            cur = os.path.join(mc, rel)
            if os.path.isfile(cur):
                shutil.copy2(cur, cur + ".before-restore-" + time.strftime("%Y%m%d%H%M%S"))
        r.log("stopping the edge so mailcow's web server can take 80/443 again")
        r.sh(["systemctl", "disable", "--now", EDGE_SVC], check=False)
        netfilter_handback(r)
        stop_cowsec_timers(r)  # or the next renewal would put CowSec's certificates back
        ssl = os.path.join(mc, "data/assets/ssl")
        if any(m.name.startswith("mailcow/data/assets/ssl/") for m in members) and os.path.isdir(ssl):
            shutil.move(ssl, ssl + ".before-restore-" + time.strftime("%Y%m%d%H%M%S"))
        for m in members:
            m.name = m.name[len("mailcow/"):]
            if m.name:
                try:
                    tar.extract(m, mc, filter="data")
                except TypeError:  # Python before 3.11.4
                    tar.extract(m, mc)
                if m.isfile():
                    r.log("restored " + m.name)
    r.log("restarting mailcow with its original settings")
    compose(mc, ["up", "-d"], r, check=False)
    return path


# ---------------------------------------------------------------- uninstall

# Everything CowSec adds to a server outside its own package, so uninstalling can take it all away.
COWSEC_UNITS = ("cowsec-certs.timer", "cowsec-certs.service", "cowsec-cert-watch.path", "cowsec-cert-watch.service",
                "cowsec-netfilter.timer", "cowsec-netfilter.service", "cowsec-cloudflare-realip.timer", "cowsec-cloudflare-realip.service")
COWSEC_FILES = ("/etc/letsencrypt/renewal-hooks/deploy/cowsec-openresty.sh", LIB_DIR + "/cowsec-cloudflare-realip", LIB_DIR + "/lego",
                "/etc/chrony/conf.d/cowsec-ptp.conf", "/etc/modules-load.d/cowsec-ptp_kvm.conf")
# the mailcow.conf keys CowSec changes; uninstalling puts back their values from before CowSec
MAILCOW_KEYS = ("HTTP_PORT", "HTTP_BIND", "HTTPS_PORT", "HTTPS_BIND", "SKIP_LETS_ENCRYPT", "API_KEY", "API_ALLOW_FROM", "ADDITIONAL_SAN")
MAILCOW_DEFAULTS = {"HTTP_PORT": "80", "HTTP_BIND": "", "HTTPS_PORT": "443", "HTTPS_BIND": "", "SKIP_LETS_ENCRYPT": "n"}
UNINSTALLED = os.path.join(STATE_DIR, "uninstalled")
ADOPTED_PREFIX = "/root/cowsec-adopted-"   # where step_adopt keeps what it took over
ROOT = "/"


def stop_cowsec_timers(r):
    """Stops CowSec's renewals and syncs, so nothing re-applies its settings to mailcow."""
    for u in COWSEC_UNITS:
        r.sh(["systemctl", "disable", "--now", u], check=False, quiet=True)


def netfilter_handback(r):
    """mailcow's netfilter enforces its own bans again (CowSec may have taken that over)."""
    if not os.path.exists(ETC_DIR + "/mailcow.env"):
        return
    try:
        s = f2b_settings(mailcow_api("GET", "get/fail2ban"))
        if s["manage_external"]:
            s["manage_external"] = 0
            mailcow_api("POST", "edit/fail2ban", {"items": ["none"], "attr": s})
            r.log("mailcow's netfilter enforces its own bans again")
    except Exception as e:  # noqa: BLE001 - mailcow may be down; say what to check
        r.log("warning: couldn't hand bans back to mailcow's netfilter (%s). In mailcow: Configuration > Netfilter, untick 'managed externally'." % e)
    rc, out = run(["cscli", "decisions", "list", "-o", "json", "--limit", "0"])
    for alert in (json.loads(out) if rc == 0 and out.strip() not in ("", "null") else []) or []:
        for d in alert.get("decisions") or []:
            if d.get("scenario") == NETFILTER_REASON:
                run(["cscli", "decisions", "delete", "--id", str(d["id"])])


def mailcow_conf_before(mc):
    """mailcow.conf as it was before CowSec changed anything: the install snapshot, else the oldest
    backup CowSec made of it (for a mailcow CowSec installed, that is mailcow's generated file)."""
    import tarfile
    snap = open(SNAPSHOT_POINTER).read().strip() if os.path.exists(SNAPSHOT_POINTER) else ""
    if snap and os.path.isfile(snap):
        try:
            with tarfile.open(snap, "r:gz") as tar:
                f = tar.extractfile("mailcow/mailcow.conf")
                if f:
                    out = {}
                    for line in f.read().decode(errors="replace").splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            out[k.strip()] = v.strip().strip('"').strip("'")
                    return out, "the snapshot taken at install (%s)" % snap
        except (OSError, KeyError, tarfile.TarError):
            pass
    baks = sorted(glob.glob(os.path.join(mc, "mailcow.conf.cowsec-bak-*")))
    if baks:
        return read_kv(baks[0]), "CowSec's first backup of it (%s)" % baks[0]
    return None, "mailcow's defaults"


def restore_adopted(r):
    """Puts back what the install took over from an earlier hand-built setup (its OpenResty sites,
    certbot hooks, log sources, clock config), from the newest /root/cowsec-adopted-* folder."""
    dirs = sorted(glob.glob(ADOPTED_PREFIX + "*"))
    restored = []
    if not dirs:
        return restored
    for f in sorted(os.listdir(dirs[-1])):
        src, dst = os.path.join(dirs[-1], f), os.path.join(ROOT, f.replace("__", "/"))
        if os.path.isfile(src) and not os.path.basename(dst).startswith("cowsec-"):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            restored.append(dst)
            r.log("put back %s (from %s)" % (dst, dirs[-1]))
    for t in ("certbot.timer", "mailcow-cert-sync.timer", "openresty-cloudflare-realip.timer"):
        if run(["systemctl", "cat", t])[0] == 0:
            r.sh(["systemctl", "enable", "--now", t], check=False, quiet=True)
            r.log("turned %s back on" % t)
    return restored


def detach_mailcow(r, mc):
    """mailcow as it was before CowSec: its web ports, certificates and API settings, with
    CowSec's postfix SNI map and per-domain certificate folders removed. Later changes by the
    admin or ./update.sh stay, because only the keys CowSec changed are reverted."""
    conf_path = os.path.join(mc, "mailcow.conf")
    conf = read_kv(conf_path)
    before, source = mailcow_conf_before(mc)
    want = {}
    for k in MAILCOW_KEYS if before is not None else ():  # no snapshot or backup: CowSec never changed it
        v = before.get(k)
        if v is None:
            v = MAILCOW_DEFAULTS.get(k, "")
        if k == "HTTP_PORT" and v == str(OLD_EDGE_MAILCOW_HTTP):
            v = str(EDGE_MAILCOW_HTTP)  # mailcow forbids 8081 (its nginx uses it inside the container)
        if conf.get(k, "") != v:
            want[k] = v
    if want:
        backup(conf_path, r)
        set_kv(conf_path, want, r)
        r.log("mailcow.conf: %s back as in %s" % (", ".join(sorted(want)), source))
    # CowSec's SNI map for postfix, and the per-domain certificate folders it fills
    pf = os.path.join(mc, "data/conf/postfix")
    sni = os.path.join(pf, "cowsec_sni.map")
    folders = set()
    if os.path.exists(sni):
        for line in open(sni).read().splitlines():
            m = re.search(r"/etc/ssl/mail/([^/\s]+)/cert\.pem", line)
            if m:
                folders.add(m.group(1))
        os.remove(sni)
        for ext in (".db", ".lmdb"):
            if os.path.exists(sni + ext):
                os.remove(sni + ext)
    extra = os.path.join(pf, "extra.cf")
    if os.path.exists(extra) and "cowsec-sni" in open(extra).read():
        cur = re.sub(r"\n?# BEGIN cowsec-sni.*?# END cowsec-sni\n?", "\n", open(extra).read(), flags=re.S).strip("\n")
        write(extra, cur + ("\n" if cur else ""), r=r)
        r.log("postfix: removed CowSec's SNI map from extra.cf")
    for d in sorted(folders):
        path = os.path.join(mc, "data/assets/ssl", d)
        if re.fullmatch(r"[A-Za-z0-9.-]+", d) and os.path.isdir(path):
            shutil.rmtree(path)
            r.log("removed CowSec's certificate folder data/assets/ssl/%s (mailcow issues its own again)" % d)
    return read_kv(conf_path)


def mailcow_answers(port, timeout=180):
    """True once mailcow's web server answers HTTPS on 127.0.0.1:port."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(urllib.request.Request("https://127.0.0.1:%s/" % port, method="HEAD"), context=ctx, timeout=5)
            return True
        except urllib.error.HTTPError:
            return True  # any HTTP answer means nginx is up
        except (urllib.error.URLError, OSError):
            time.sleep(3)
    return False


def uninstall(r):
    """Removes everything CowSec added and leaves mailcow working on its own: ports, certificates
    and API settings as before CowSec (or mailcow's defaults), its netfilter enforcing its own bans,
    and an earlier hand-built edge put back if CowSec took one over. CrowdSec keeps running on its
    stock settings. Raises StepError if mailcow doesn't come back, so a package removal stops."""
    mc = find_mailcow()
    netfilter_handback(r)              # while CowSec's API key still works
    stop_cowsec_timers(r)
    adopted = restore_adopted(r)
    conf = detach_mailcow(r, mc) if mc else {}
    for f in [x for x in adopted if x.startswith(NGX + "/sites/")]:
        txt = open(f).read()
        if "127.0.0.1:%d" % OLD_EDGE_MAILCOW_HTTP in txt:
            write(f, txt.replace("127.0.0.1:%d" % OLD_EDGE_MAILCOW_HTTP, "127.0.0.1:%d" % EDGE_MAILCOW_HTTP), r=r)
            r.log("edge: %s now uses mailcow's port %d (8081 is reserved by mailcow)" % (f, EDGE_MAILCOW_HTTP))
    # the edge: keep it only if mailcow still expects a proxy and one was put back
    proxied = conf.get("HTTPS_BIND", "") in ("127.0.0.1", "::1", "localhost")
    for f in glob.glob(NGX + "/sites/cowsec-*.conf") + [NGX + "/cowsec_mailcow_proxy.conf"]:
        if os.path.exists(f):
            os.remove(f)
            r.log("edge: removed %s" % f)
    baks = sorted(glob.glob(NGX + "/nginx.conf.cowsec-bak-*"))
    if baks:
        shutil.copy2(baks[0], NGX + "/nginx.conf")
        r.log("edge: put back %s's nginx.conf from before CowSec" % EDGES[EDGE_KIND]["name"])
    keep_edge = False
    if mc and proxied and any(x.startswith(NGX + "/sites/") for x in adopted):
        keep_edge = run([EDGE_BIN, "-t", "-q"])[0] == 0
        if not keep_edge:
            r.log("edge: your earlier OpenResty setup doesn't pass its config test; mailcow takes 80/443 itself instead")
    if mc and proxied and not keep_edge:
        set_kv(os.path.join(mc, "mailcow.conf"), {k: MAILCOW_DEFAULTS[k] for k in ("HTTP_PORT", "HTTP_BIND", "HTTPS_PORT", "HTTPS_BIND")}, r)
        r.log("mailcow.conf: web server back on 80/443 (nothing else in front of it now)")
    if keep_edge:
        r.sh(["systemctl", "restart", EDGE_SVC], check=False)
        r.log("edge: your earlier OpenResty setup serves mailcow again")
        if run(["systemctl", "cat", "certbot.timer"])[0] == 0:
            r.sh(["certbot", "renew", "--no-random-sleep-on-renew"], check=False)  # it was paused while CowSec renewed
    else:
        r.sh(["systemctl", "disable", "--now", EDGE_SVC], check=False, quiet=True)
    # CrowdSec: CowSec's own pieces go, CrowdSec stays
    removed = {}
    own_appsec = keep_edge and not any(x.startswith(CS_DIR + "/acquis.d/") for x in adopted)
    if own_appsec and os.path.exists(APPSEC_ACQUIS):
        # the earlier edge still needs a WAF listener: keep CowSec's, on CrowdSec's default rules
        removed[APPSEC_ACQUIS] = open(APPSEC_ACQUIS).read()
        write(APPSEC_ACQUIS, re.sub(r"(?m)^(\s*appsec_config:\s*)\S+", r"\1crowdsecurity/appsec-default", removed[APPSEC_ACQUIS]), r=None, keep_backup=False)
    for f in (APPSEC_CONFIG_FILE, APPSEC_WATCH_SCENARIO, CS_DIR + "/scenarios/cowsec-auth-abroad.yaml") + (() if own_appsec else (APPSEC_ACQUIS,)):
        if os.path.exists(f):
            removed[f] = open(f).read()
            os.remove(f)
    prof = CS_DIR + "/profiles.yaml"
    if os.path.exists(prof + ".pre-cowsec"):
        removed[prof] = open(prof).read()
        shutil.copy2(prof + ".pre-cowsec", prof)
    if removed:
        if run(["crowdsec", "-c", CS_DIR + "/config.yaml", "-t"])[0] == 0:
            r.sh(["systemctl", "reload", "crowdsec"], check=False)
            r.log("CrowdSec: back on its stock ban profile; CowSec's WAF config and scenarios removed")
        else:
            for f, txt in removed.items():
                write(f, txt, r=None, keep_backup=False)
            r.log("warning: CrowdSec's config test failed without CowSec's files, so they were left in place")
    for f in COWSEC_FILES:
        if os.path.exists(f):
            os.remove(f)
    for u in COWSEC_UNITS:
        p = "/etc/systemd/system/" + u
        if os.path.exists(p):
            os.remove(p)
    r.sh(["systemctl", "daemon-reload"], check=False, quiet=True)
    if run(["systemctl", "is-active", "--quiet", "chrony"])[0] == 0:
        r.sh(["systemctl", "restart", "chrony"], check=False, quiet=True)
    for f in ("setup-complete", "setup-token"):
        if os.path.exists(os.path.join(STATE_DIR, f)):
            os.remove(os.path.join(STATE_DIR, f))
    if mc:
        r.log("restarting mailcow with its own settings")
        compose(mc, ["up", "-d"], r, check=False)
        port = read_kv(os.path.join(mc, "mailcow.conf")).get("HTTPS_PORT", "443")
        if not mailcow_answers(port):
            raise StepError("mailcow's web server didn't come back on port %s. CowSec is detached, but check "
                            "'docker compose ps' in %s before removing anything else" % (port, mc))
        r.log("mailcow answers on port %s" % port)
    write(UNINSTALLED, time.strftime("%Y-%m-%dT%H:%M:%S%z") + "\n", 0o600)
    return {"mailcow": mc, "kept_edge": keep_edge, "adopted": bool(adopted)}


# ---------------------------------------------------------------- mailcow discovery

def find_mailcow():
    env_dir = os.environ.get("MAILCOW_DIR")
    for d in ([env_dir] if env_dir else []) + list(MAILCOW_CANDIDATES):
        if d and os.path.exists(os.path.join(d, "mailcow.conf")):
            return d
    return None


def compose(mc, args, r=None, check=True, env=None):
    cmd = ["docker", "compose"] + args
    if r:
        return r.sh(cmd, cwd=mc, check=check, env=env)
    p = subprocess.run(cmd, cwd=mc, capture_output=True, text=True, timeout=300, env=dict(os.environ, **(env or {})))
    return p.returncode, (p.stdout + p.stderr).strip()


def mailcow_info():
    mc = find_mailcow()
    if not mc:
        return {"found": False}
    conf = read_kv(os.path.join(mc, "mailcow.conf"))
    project = conf.get("COMPOSE_PROJECT_NAME", "mailcowdockerized")
    rc, out = run(["docker", "ps", "--filter", "label=com.docker.compose.project=" + project,
                   "--format", '{{.Names}}\t{{.Label "com.docker.compose.service"}}\t{{.Status}}'])
    containers = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            containers[parts[1]] = {"name": parts[0], "status": parts[2]}
    domains = []
    if "mysql-mailcow" in containers and conf.get("DBROOT"):
        rc, out = compose(mc, ["exec", "-T", "-e", "MYSQL_PWD=" + conf["DBROOT"], "mysql-mailcow", "mysql", "-uroot",
                               conf.get("DBNAME", "mailcow"), "-N", "-e",
                               "SELECT domain FROM domain WHERE active=1 UNION SELECT alias_domain FROM alias_domain WHERE active=1"])
        if rc == 0:
            domains = sorted({d.strip().lower() for d in out.splitlines() if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d.strip().lower())})
    return {
        "found": True, "dir": mc, "hostname": conf.get("MAILCOW_HOSTNAME", ""), "project": project,
        "httpPort": conf.get("HTTP_PORT", "80"), "httpsPort": conf.get("HTTPS_PORT", "443"),
        "httpBind": conf.get("HTTP_BIND", ""), "httpsBind": conf.get("HTTPS_BIND", ""),
        "skipLetsEncrypt": conf.get("SKIP_LETS_ENCRYPT", "n").lower() in ("y", "yes"),
        "additionalSan": conf.get("ADDITIONAL_SAN", ""), "containers": containers, "domains": domains,
    }


# ---------------------------------------------------------------- installing mailcow from scratch

MAILCOW_REPO = "https://github.com/mailcow/mailcow-dockerized"
MAILCOW_NEW_DIR = "/opt/mailcow-dockerized"
MAILCOW_PORTS = (25, 80, 110, 143, 443, 465, 587, 993, 995, 4190)
MAILCOW_BRANCHES = ("master", "nightly")  # mailcow's [1] and [2]; "legacy" stopped getting updates in February 2026
MAILCOW_ADMIN_ONCE = os.path.join(STATE_DIR, "mailcow-admin.json")  # shown once by the wizard, removed at Finish
CLAMAV_PROMPT_KIB = 2621440  # generate_config.sh offers to turn ClamAV off at or below 2.5 GiB


def host_timezone():
    """The same detection generate_config.sh uses for its default."""
    try:
        if os.path.exists("/etc/timezone"):
            return open("/etc/timezone").read().strip()
        return re.sub(r"^.*zoneinfo/", "", os.readlink("/etc/localtime"))
    except OSError:
        return ""


def mem_total_kib():
    m = re.search(r"MemTotal:\s+(\d+)", open("/proc/meminfo").read())
    return int(m.group(1)) if m else 0


def docker_major():
    rc, out = run(["docker", "version", "--format", "{{.Server.Version}}"])
    m = re.match(r"(\d+)", out) if rc == 0 else None
    return int(m.group(1)) if m else 0


def fresh_facts():
    """What the wizard needs to ask mailcow's own questions, with mailcow's defaults."""
    fqdn = socket.getfqdn()
    return {"timezone": host_timezone(), "memKiB": mem_total_kib(), "clamavPrompt": mem_total_kib() <= CLAMAV_PROMPT_KIB,
            "hostname": fqdn if fqdn.count(".") >= 2 else "", "dockerMajor": docker_major(), "branches": list(MAILCOW_BRANCHES),
            "timezones": sorted(set(l.split("\t")[2] for l in open("/usr/share/zoneinfo/zone1970.tab") if l[0] != "#")) if os.path.exists("/usr/share/zoneinfo/zone1970.tab") else []}


def fresh_checks(add, owners):
    """Pre-flight for a server that has no mailcow yet."""
    gib = mem_total_kib() / 1048576
    add("fresh-ram", "Memory for mailcow (6 GiB recommended)", "ok" if gib >= 5.5 else "warn",
        "%.1f GiB%s" % (gib, "" if gib >= 5.5 else "; mailcow may run short" + (", turn ClamAV off" if gib <= 2.5 else "")))
    st = os.statvfs("/var/lib" if os.path.isdir("/var/lib") else "/")
    free = st.f_bavail * st.f_frsize / 1e9
    add("fresh-disk", "Disk for mailcow (20 GB+)", "ok" if free >= 20 else "warn", "%.0f GB free" % free)
    busy = {p: sorted(owners.get(str(p), set())) for p in MAILCOW_PORTS if owners.get(str(p))}
    add("fresh-ports", "Mail and web ports free", "ok" if not busy else "fail",
        "25, 80, 110, 143, 443, 465, 587, 993, 995, 4190" if not busy else
        "in use: " + "; ".join("%d by %s" % (p, ", ".join(o)) for p, o in sorted(busy.items())) + ". Stop and disable those services first.")
    dm = docker_major()
    rc, out = run(["dpkg-query", "-W", "-f=${Status}", "docker.io"])
    if "installed" in out and "not-installed" not in out:
        add("fresh-docker", "Docker", "fail", "the distribution's docker.io package is installed; mailcow needs Docker CE 24+. Remove docker.io first.")
    elif shutil.which("podman") and not dm:
        add("fresh-docker", "Docker", "fail", "Podman found; mailcow needs Docker CE")
    elif dm and dm < 24:
        add("fresh-docker", "Docker", "fail", "Docker %d found; mailcow needs 24 or newer" % dm)
    else:
        add("fresh-docker", "Docker", "ok", "Docker %d" % dm if dm else "will be installed from Docker's official repository")
    try:  # a plain TCP connect, no SMTP conversation: many VPS providers block outbound 25
        socket.create_connection(("gmail-smtp-in.l.google.com", 25), timeout=6).close()
        add("fresh-smtp-out", "Outbound mail (port 25)", "ok", "open")
    except OSError:
        add("fresh-smtp-out", "Outbound mail (port 25)", "warn", "blocked or unreachable; many VPS providers block it until you ask, or you'll need a relay host")


def step_docker(c, r, ctx):
    osid, ver, code = os_release()
    flavour = "ubuntu" if osid == "ubuntu" else "debian"
    apt_install(r, ["ca-certificates", "curl", "gnupg"])
    apt_key_repo(r, "docker", "https://download.docker.com/linux/%s/gpg" % flavour,
                 "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable" % (flavour, code),
                 "/etc/apt/keyrings/docker.gpg")
    apt_install(r, ["docker-ce", "docker-ce-cli", "containerd.io", "docker-buildx-plugin", "docker-compose-plugin"])
    r.sh(["systemctl", "enable", "--now", "docker"])
    if docker_major() < 24:
        raise StepError("Docker did not start, or is older than 24")


def mailcow_up_and_healthy(d, r, minutes=15):
    """Waits for every mailcow container to be up (and healthy where it has a health check)."""
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        rc, out = compose(d, ["ps", "-a", "--format", "{{.Service}}\t{{.State}}\t{{.Health}}"])
        rows = [l.split("\t") for l in out.splitlines() if l.count("\t") == 2]
        waiting = [s for s, state, health in rows if state != "running" or health not in ("", "healthy")]
        if rows and not waiting:
            r.log("all %d containers up" % len(rows))
            return
        time.sleep(10)
    raise StepError("mailcow containers not ready after %d minutes: %s" % (minutes, ", ".join(waiting[:8])))


def set_mailcow_admin_password(d, r):
    """mailcow-reset-admin.sh without a terminal: a random admin password, hashed by dovecot,
    instead of mailcow's well-known default."""
    conf = read_kv(os.path.join(d, "mailcow.conf"))
    pw = secrets.token_urlsafe(15)
    r.redact += [pw, conf.get("DBPASS", "")]
    rc, h = compose(d, ["exec", "-T", "dovecot-mailcow", "doveadm", "pw", "-s", "SSHA256", "-p", pw])
    h = h.strip().splitlines()[-1] if rc == 0 and h.strip() else ""
    if not re.fullmatch(r"\{SSHA256\}[A-Za-z0-9+/=]+", h):
        raise StepError("could not hash the mailcow admin password")
    sql = ("DELETE FROM admin WHERE username='admin'; DELETE FROM domain_admins WHERE username='admin'; "
           "INSERT INTO admin (username, password, superadmin, active) VALUES ('admin', '%s', 1, 1); DELETE FROM tfa WHERE username='admin';" % h)
    for _ in range(30):
        rc, _out = r.sh(["docker", "compose", "exec", "-T", "-e", "MYSQL_PWD=" + conf["DBPASS"], "mysql-mailcow",
                         "mysql", "-u" + conf["DBUSER"], conf["DBNAME"]], cwd=d, input=sql, check=False, quiet=True)
        if rc == 0:
            break
        time.sleep(5)
    else:
        raise StepError("could not set the mailcow admin password (database not ready)")
    write(MAILCOW_ADMIN_ONCE, json.dumps({"username": "admin", "password": pw, "url": "https://%s/admin" % conf.get("MAILCOW_HOSTNAME", "")}) + "\n", 0o600)
    r.log("mailcow admin password set (shown once in the wizard)")


def step_mailcow_install(c, r, ctx):
    m = c["mailcow"]
    d = MAILCOW_NEW_DIR
    if find_mailcow():
        raise StepError("mailcow is already installed in %s" % find_mailcow())
    # generate_config.sh's own requirements
    apt_install(r, ["git", "jq", "curl", "openssl", "gawk", "coreutils", "grep", "sed", "iputils-ping"])
    if not os.path.isdir(os.path.join(d, ".git")):
        old = os.umask(0o022)  # mailcow's install guide: files must stay readable by its containers
        try:
            r.sh(["git", "clone", MAILCOW_REPO, d], timeout=600)
        finally:
            os.umask(old)
    host = m["hostname"]
    try:
        addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
        r.log("%s resolves to %s" % (host, ", ".join(addrs)))
    except OSError:
        r.log("note: %s doesn't resolve yet; add its A (and AAAA) record before mail can flow" % host)
    # Same questions as an interactive install, answered from the wizard. The remaining
    # prompts (no-subdomain warning, Docker IPv6 daemon.json) are confirmed with "y".
    env = {"MAILCOW_HOSTNAME": host, "MAILCOW_TZ": m["timezone"], "SKIP_CLAMD": "y" if m["skipClamd"] else "n", "MAILCOW_BRANCH": m["branch"]}
    r.sh(["bash", "./generate_config.sh"], cwd=d, env=env, input="y\n" * 6, timeout=1800)
    if not os.path.exists(os.path.join(d, "mailcow.conf")):
        raise StepError("generate_config.sh did not write mailcow.conf")
    os.chmod(os.path.join(d, "mailcow.conf"), 0o600)
    compose(d, ["pull", "-q"], r)
    compose(d, ["up", "-d"], r)
    mailcow_up_and_healthy(d, r)
    set_mailcow_admin_password(d, r)
    ctx["mailcow"] = mailcow_info()
    ctx["fresh_mailcow"] = True


# ---------------------------------------------------------------- existing CrowdSec

FW_PKGS = ("crowdsec-firewall-bouncer-iptables", "crowdsec-firewall-bouncer-nftables")
FW_CONF = CS_DIR + "/bouncers/crowdsec-firewall-bouncer.yaml"


def restart_crowdsec(r):
    """Restarts the engine; on failure, surfaces CrowdSec's own reason instead of systemd's."""
    rc, _ = r.sh(["systemctl", "restart", "crowdsec"], check=False)
    if rc != 0:
        _, j = run(["journalctl", "-u", "crowdsec", "-n", "40", "--no-pager", "-o", "cat"])
        why = [l for l in j.splitlines() if re.search(r"FATAL|level=fatal|level=error", l)]
        reason = why[-1].strip() if why else "see journalctl -u crowdsec"
        if "api.crowdsec.net" in reason:
            reason += " (CrowdSec can't reach its central API: check DNS, the firewall and /etc/hosts)"
        raise StepError("CrowdSec did not restart: " + reason[-400:])


def pkg_version(name):
    rc, out = run(["dpkg-query", "-W", "-f=${Status} ${Version}", name])
    return out.split()[-1] if rc == 0 and out.startswith("install ok installed") else None


def yaml_scalar(path, key):
    """Top-level or nested `key: value` (or `key = value`) from a simple config file (first match)."""
    try:
        m = re.search(r"^\s*%s\s*[:=]\s*['\"]?([^'\"#\n]+?)['\"]?\s*(#.*)?$" % re.escape(key), open(path).read(), re.M)
        return m.group(1).strip() if m else None
    except OSError:
        return None


def lapi_url():
    return (yaml_scalar(CS_DIR + "/local_api_credentials.yaml", "url") or "http://127.0.0.1:8080/").rstrip("/") + "/"


def crowdsec_inventory():
    """What CrowdSec is already on this server and how it was put there. Decides whether
    CowSec can build on it (apt packages on the host), or must refuse (a second engine)."""
    inv = {"package": pkg_version("crowdsec"), "binary": shutil.which("crowdsec"), "firewall": None, "firewallMode": None}
    if inv["binary"] and not inv["package"]:
        inv["manual"] = inv["binary"]
    elif inv["binary"] and run(["dpkg", "-S", os.path.realpath(inv["binary"])])[0] != 0:
        inv["manual"] = inv["binary"]  # package present, but a hand-placed binary wins on PATH
    rc, out = run(["docker", "ps", "--format", "{{.Names}} {{.Image}}"])
    inv["containers"] = [l.split()[0] for l in out.splitlines() if "crowdsecurity/crowdsec" in l or re.search(r"\bcrowdsec\b", l.split()[-1] if l.split() else "")]
    if inv["package"] or inv["binary"]:
        url = lapi_url()
        inv["lapiUrl"] = url
        host = re.sub(r"^\w+://|[:/].*$", "", url)
        inv["remoteLapi"] = host not in ("127.0.0.1", "localhost", "::1", "[::1]")
        try:
            inv["lapiServer"] = not re.search(r"^api:\n(?:[ \t].*\n)*?[ \t]+server:\n(?:[ \t].*\n)*?[ \t]+enable:\s*false", open(CS_DIR + "/config.yaml").read(), re.M)
        except OSError:
            inv["lapiServer"] = True
    for p in FW_PKGS:
        v = pkg_version(p)
        if v:
            inv["firewall"], inv["firewallVersion"] = p, v
    if os.path.exists(FW_CONF):
        inv["firewallMode"] = yaml_scalar(FW_CONF, "mode")
    inv["hostFirewalls"] = [u for u in ("ufw", "firewalld") if run(["systemctl", "is-active", "--quiet", u])[0] == 0]
    rc, out = run(["iptables", "-V"])
    inv["iptablesBackend"] = "nf_tables" if "nf_tables" in out else ("legacy" if "legacy" in out else None)
    return inv


def firewall_uses_nft(inv=None):
    inv = inv or crowdsec_inventory()
    return inv.get("firewall") == FW_PKGS[1] or inv.get("firewallMode") == "nftables"


def firewall_covers_docker():
    """True when the firewall bouncer filters traffic Docker forwards to mailcow (DNAT'd mail ports)."""
    if firewall_uses_nft():
        rc, out = run(["nft", "list", "table", "ip", yaml_scalar(FW_CONF, "table") or "crowdsec"])
        return rc == 0 and "hook forward" in out, "nftables forward hook"
    rc, out = run(["iptables", "-S", "DOCKER-USER"])
    return "CROWDSEC" in out.upper(), "iptables DOCKER-USER"


# ---------------------------------------------------------------- existing setups

LEGACY_UNIT = "/etc/systemd/system/cowsec.service"
LEGACY_MARKER = os.path.join(STATE_DIR, "legacy-migrated.json")


def cert_names_of(path):
    rc, out = run(["openssl", "x509", "-in", path, "-noout", "-ext", "subjectAltName"])
    return re.findall(r"DNS:([^,\s]+)", out) if rc == 0 else []


def replaced_acquisition(doc):
    """An acquisition doc that CowSec's own files replace: mailcow's containers, the edge's
    logs, or an AppSec engine (only one can listen on its port)."""
    live = "\n".join(l for l in doc.split("\n") if not l.lstrip().startswith("#"))
    return bool(re.search(r"^\s*-\s*\S*(postfix|dovecot|nginx)-mailcow\S*\s*$", live, re.M)
                or "/var/log/openresty/" in live or EDGE_LOGS + "/" in live or re.search(r"^\s*source:\s*appsec\b", live, re.M))


def detect_existing():
    """Finds earlier hand-built pieces CowSec can take over, so the wizard can pre-fill
    answers and the install can adopt them cleanly instead of clashing."""
    d = {}
    if os.path.exists(LEGACY_MARKER):
        try:
            d["legacyCowsec"] = json.load(open(LEGACY_MARKER))
        except Exception:
            d["legacyCowsec"] = {}
    mc = find_mailcow()
    host = read_kv(os.path.join(mc, "mailcow.conf")).get("MAILCOW_HOSTNAME", "") if mc else ""
    # certbot (or any ACME client) certificates that cover the mailcow hostname
    for live in sorted(glob.glob("/etc/letsencrypt/live/*/fullchain.pem")):
        names = cert_names_of(live)
        if host and any(n == host or (n.startswith("*.") and host.endswith(n[1:])) for n in names):
            d["certbot"] = {"name": live.split("/")[-2], "certPath": live, "keyPath": live.replace("fullchain.pem", "privkey.pem"),
                            "names": names[:20], "timers": [t for t in ("certbot.timer", "mailcow-cert-sync.timer") if run(["systemctl", "cat", t])[0] == 0],
                            "hooks": sorted(f for f in glob.glob("/etc/letsencrypt/renewal-hooks/deploy/*") if not os.path.basename(f).startswith("cowsec-")),
                            "authenticator": yaml_scalar("/etc/letsencrypt/renewal/%s.conf" % live.split("/")[-2], "authenticator") or ""}
            break
    sites = sorted(f for f in glob.glob(NGX + "/sites/*.conf") if not os.path.basename(f).startswith("cowsec-"))
    if sites:
        console = None
        for f in sites:
            txt = open(f).read()
            if "127.0.0.1:8090" in txt:
                m = re.search(r"server_name\s+([^;\s]+)", txt)
                console = m.group(1) if m else None
        d["edgeSites"] = {"files": sites, "consoleHostname": console,
                          "adminLanOnly": any(re.search(r"admin\|domainadmin", open(f).read()) for f in sites)}
    if os.path.exists(NGX + "/conf.d/cloudflare_realip.conf") or run(["systemctl", "cat", "openresty-cloudflare-realip.timer"])[0] == 0:
        d["cloudflareRealIP"] = {"timer": "openresty-cloudflare-realip.timer" if run(["systemctl", "cat", "openresty-cloudflare-realip.timer"])[0] == 0 else None}
    ptp = [f for f in glob.glob("/etc/chrony/conf.d/*.conf") if "refclock PHC" in open(f).read() and not os.path.basename(f).startswith("cowsec-")]
    if ptp:
        d["chronyPtp"] = {"files": ptp}
    dup = []
    for f in [CS_DIR + "/acquis.yaml"] + glob.glob(CS_DIR + "/acquis.d/*.yaml"):
        if os.path.basename(f).startswith("cowsec-") or not os.path.exists(f):
            continue
        if any(replaced_acquisition(doc) for doc in re.split(r"(?m)^---\s*$", open(f).read())):
            dup.append(f)
    if dup:
        d["duplicateAcquisition"] = {"files": dup}
    pol = os.path.join(STATE_DIR, "policy.json")
    if os.path.exists(pol):
        try:
            d["policy"] = {"homeCountries": json.load(open(pol)).get("homeCountries")}
        except Exception:
            pass
    return d


def migrate_legacy(r):
    """Hand-installed CowSec (before the package existed): a unit in /etc/systemd/system
    that overrides the package's, a binary in /opt/cowsec and settings with old names.
    Moves them aside and carries the settings over. Accounts, 2FA and policy stay."""
    if not os.path.exists(LEGACY_UNIT) or "/opt/cowsec/" not in open(LEGACY_UNIT).read():
        return False
    stamp = time.strftime("%Y%m%d%H%M%S")
    dst = "/root/cowsec-legacy-%s" % stamp
    os.makedirs(dst, mode=0o700, exist_ok=True)
    r.sh(["systemctl", "stop", "cowsec"], check=False)
    moved = []
    for src in (LEGACY_UNIT, "/usr/local/sbin/cowsec-hostctl", "/opt/cowsec"):
        if os.path.exists(src):
            shutil.move(src, os.path.join(dst, os.path.basename(src.rstrip("/"))))
            moved.append(src)
    envp = ETC_DIR + "/cowsec.env"
    if os.path.exists(envp):
        shutil.copy2(envp, os.path.join(dst, "cowsec.env.orig"))
        old = read_kv(envp)
        # sign-in settings may carry another prefix from a hand-made unit; the packaged names are COWSEC_*
        new = {}
        for k, v in old.items():
            m = re.fullmatch(r"[A-Z][A-Z0-9]*_((?:LDAP|DUO)_[A-Z0-9_]+|TRUSTED_PROXIES)", k)
            if m and v:
                new.setdefault("COWSEC_" + m.group(1), v)
            elif k.startswith("COWSEC_") and k not in ("COWSEC_UI_DIR", "COWSEC_HELPER") and v:
                new[k] = v
        write(envp, "# Migrated from a hand-installed CowSec by cowsec-setup (original in %s)\n" % dst
              + "".join('%s="%s"\n' % (k, v.replace("\\", "\\\\").replace('"', '\\"')) for k, v in sorted(new.items())), 0o600)
    write(LEGACY_MARKER, json.dumps({"migrated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "backup": dst, "moved": moved}) + "\n", 0o600)
    r.sh(["systemctl", "daemon-reload"], check=False)
    r.log("migrated the hand-installed CowSec; originals kept in %s" % dst)
    return True


def step_adopt(c, r, ctx):
    """Takes over earlier hand-built pieces so they don't clash with what CowSec installs.
    Everything moved or changed is kept under /root/cowsec-adopted-<time>/."""
    d = detect_existing()
    bdir = ADOPTED_PREFIX + time.strftime("%Y%m%d%H%M%S")
    def keep(path):
        os.makedirs(bdir, mode=0o700, exist_ok=True)
        dst = os.path.join(bdir, path.strip("/").replace("/", "__"))
        shutil.copy2(path, dst) if os.path.isfile(path) else shutil.copytree(path, dst)
        return dst
    if c["components"]["edge"] and d.get("edgeSites"):
        for f in d["edgeSites"]["files"]:
            keep(f)
            os.remove(f)
            r.log("edge: moved %s aside (CowSec's edge replaces it)" % f)
    if c["components"]["edge"] and c["components"]["cloudflareRealIP"] and (d.get("cloudflareRealIP") or {}).get("timer"):
        r.sh(["systemctl", "disable", "--now", "openresty-cloudflare-realip.timer"], check=False)
        r.log("Cloudflare real-IP: the old timer is off; CowSec's timer takes over")
    if c["components"]["chronyPtp"] and d.get("chronyPtp"):
        for f in d["chronyPtp"]["files"]:
            keep(f)
            os.remove(f)
            r.log("clock: moved %s aside (CowSec's chrony config replaces it)" % f)
    for f in (d.get("duplicateAcquisition") or {}).get("files", []):
        keep(f)
        docs = re.split(r"(?m)^---\s*$", open(f).read())
        out = []
        for doc in docs:
            if replaced_acquisition(doc):
                out.append("\n".join("# cowsec-adopted: " + l if l.strip() else l for l in doc.split("\n")))
            else:
                out.append(doc)
        write(f, "---\n".join(out), r=None, keep_backup=False)
        r.log("log sources: commented out entries in %s that CowSec's own acquisition replaces" % f)
        ctx["reload_crowdsec"] = True
    if d.get("certbot") and c["certs"]["mode"] == "dns01":
        for t in d["certbot"]["timers"]:
            r.sh(["systemctl", "disable", "--now", t], check=False)
        for h in d["certbot"]["hooks"]:
            keep(h)
            os.remove(h)
        r.log("certificates: certbot's renewals and deploy hook are off; CowSec's DNS-01 renewal takes over (/etc/letsencrypt is untouched)")
    if os.path.isdir(bdir):
        r.log("originals kept in %s" % bdir)
    else:
        r.log("nothing to take over")


# ---------------------------------------------------------------- pre-flight

def preflight():
    checks = []

    def add(cid, title, status, detail=""):
        checks.append({"id": cid, "title": title, "status": status, "detail": detail})

    add("root", "Running as root", "ok" if os.geteuid() == 0 else "fail", "" if os.geteuid() == 0 else "run with sudo")
    arch = os.uname().machine
    add("arch", "64-bit x86 (amd64)", "ok" if arch == "x86_64" else "fail", arch)
    osid, ver, code = os_release()
    supported = (osid == "debian" and ver in ("12", "13")) or (osid == "ubuntu" and ver in ("22.04", "24.04"))
    add("os", "Supported OS (Debian 12/13, Ubuntu 22.04/24.04)", "ok" if supported else "warn", "%s %s (%s)" % (osid, ver, code))
    add("systemd", "systemd", "ok" if os.path.isdir("/run/systemd/system") else "fail")
    mc = mailcow_info()
    if mc["found"]:  # without mailcow, the fresh-install checks below cover Docker
        rc, out = run(["docker", "compose", "version", "--short"])
        add("docker", "Docker with Compose v2", "ok" if rc == 0 else "fail", out.splitlines()[0] if out else "not found")
    if not mc["found"]:
        add("mailcow", "mailcow-dockerized installation", "info", "not installed: CowSec can install it for you "
            "(already installed somewhere else? set MAILCOW_DIR in /etc/cowsec/cowsec.env)")
    else:
        add("mailcow", "mailcow-dockerized installation", "ok", "%s · %s" % (mc["dir"], mc["hostname"]))
        need = ("postfix-mailcow", "dovecot-mailcow", "nginx-mailcow")
        down = [s for s in need if not mc["containers"].get(s, {}).get("status", "").startswith("Up")]
        add("mailcow-running", "mailcow containers running", "ok" if not down else "fail", "down: " + ", ".join(down) if down else "%d containers" % len(mc["containers"]))
        add("mailcow-domains", "mailcow domains", "ok" if mc["domains"] else "warn", ", ".join(mc["domains"][:8]) + (" …" if len(mc["domains"]) > 8 else "") or "none found")
    inv = crowdsec_inventory()
    if inv.get("manual"):
        add("crowdsec", "CrowdSec", "fail", "%s was installed by hand, not from CrowdSec's apt repository. "
            "CowSec manages CrowdSec through apt; remove it first (your /etc/crowdsec config can stay)." % inv["manual"])
    elif inv["package"] and inv.get("remoteLapi"):
        add("crowdsec", "CrowdSec", "fail", "this server is an agent of a central CrowdSec at %s; multi-server setups are not supported yet" % inv["lapiUrl"])
    elif inv["package"] and not inv.get("lapiServer", True):
        add("crowdsec", "CrowdSec", "fail", "the local API is turned off in /etc/crowdsec/config.yaml; CowSec needs it on this server")
    elif inv["package"]:
        add("crowdsec", "CrowdSec", "ok", "%s already installed: kept, with your collections, scenarios and allowlists" % inv["package"])
    else:
        add("crowdsec", "CrowdSec", "ok", "will be installed from CrowdSec's apt repository")
    if inv["containers"]:
        add("crowdsec-docker", "No second CrowdSec engine", "fail", "CrowdSec container running (%s); two engines would read the same logs and fight over bans. "
            "Stop and remove it first." % ", ".join(inv["containers"]))
    if inv["firewall"] == FW_PKGS[1] or inv.get("firewallMode") == "nftables":
        add("firewall-bouncer", "Firewall bouncer", "ok", "nftables bouncer %s kept; CowSec makes sure it also hooks forwarded traffic (mailcow's mail ports)" % (inv.get("firewallVersion") or ""))
    elif inv["firewall"]:
        add("firewall-bouncer", "Firewall bouncer", "ok", "iptables bouncer %s kept; CowSec adds DOCKER-USER to its chains" % inv["firewallVersion"])
    elif os.path.exists(FW_CONF):
        add("firewall-bouncer", "Firewall bouncer", "warn", "a firewall bouncer config exists but no bouncer package; the iptables bouncer will be installed")
    if inv["iptablesBackend"] == "legacy":
        add("iptables-backend", "iptables backend", "warn", "iptables-legacy is selected; make sure Docker uses the same backend or bans may not reach mail ports")
    if inv["hostFirewalls"]:
        add("host-firewall", "Other host firewalls", "info", "%s active: fine alongside CrowdSec, but reloading %s can drop the bouncer's rules until it restarts"
            % (", ".join(inv["hostFirewalls"]), " or ".join(inv["hostFirewalls"])))
    rc, ss = run(["ss", "-ltnpH"])
    owners = {}
    for line in ss.splitlines():
        m = re.search(r"[:\]](25|80|110|143|443|465|587|993|995|4190|8081|8180|8443|8090|9443|7422|8080)\s.*users:\(\(\"([^\"]+)\",pid=(\d+)", line)
        if m:
            name = m.group(2)
            try:  # the edge's processes are all called "nginx"; tell CowSec's edge apart by executable
                exe = os.readlink("/proc/%s/exe" % m.group(3))
                if "/openresty/" in exe or (EDGE_KIND == "nginx" and exe == EDGE_BIN and edge_installed()):
                    name = "edge"
            except OSError:
                pass
            owners.setdefault(m.group(1), set()).add(name)
    web = set().union(*[owners.get(p, set()) for p in ("80", "443")])
    rc_ng, _ = run(["systemctl", "is-active", "--quiet", "nginx"])
    host_nginx = rc_ng == 0 and not (EDGE_KIND == "nginx" and edge_installed())
    others = web - {"docker-proxy", "edge"}
    if host_nginx or others:
        add("web-ports", "Web ports 80/443 available", "warn", "used by %s on the host; the edge needs 80/443" % ", ".join(sorted(others) or ["nginx"]))
    elif "edge" in web:
        add("web-ports", "Web ports 80/443 available", "ok", "already served by CowSec's edge")
    else:
        add("web-ports", "Web ports 80/443 available", "ok", "served by mailcow now; the edge takes them over and moves mailcow to localhost" if "docker-proxy" in web else "free")
    if not mc["found"]:
        fresh_checks(add, owners)
    for port, what in ((str(EDGE_MAILCOW_HTTP), "mailcow HTTP (edge)"), ("8443", "mailcow HTTPS (edge)"), ("8090", "CowSec console")):
        o = owners.get(port, set()) - {"docker-proxy", "cowsec"}
        if o:
            add("port-" + port, "Port %s free (%s)" % (port, what), "warn", "in use by " + ", ".join(o))
    if firewall_uses_nft(inv):
        add("docker-user", "Forwarded traffic (mail ports)", "ok", "covered by the nftables bouncer's forward hook")
    else:
        rc, out = run(["iptables", "-S", "DOCKER-USER"])
        if rc == 0:
            add("docker-user", "iptables DOCKER-USER chain", "ok", "")
        elif not mc["found"] and not docker_major():
            add("docker-user", "iptables DOCKER-USER chain", "info", "Docker creates it when it's installed")
        else:
            add("docker-user", "iptables DOCKER-USER chain", "warn", "not found; bans will only cover host services")
    rc, out = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    add("time", "Clock synchronised", "ok" if out.strip() == "yes" else "warn", "" if out.strip() == "yes" else "TOTP sign-in needs an accurate clock")
    ptp = os.path.exists("/dev/ptp0") or run(["modprobe", "-n", "ptp_kvm"])[0] == 0
    add("ptp", "Hypervisor clock (KVM PTP, optional)", "ok" if ptp else "info", "available: Proxmox/KVM guest" if ptp else "not available (bare metal or non-KVM): chrony uses internet NTP")
    st = os.statvfs("/var")
    free_gb = st.f_bavail * st.f_frsize / 1e9
    add("disk", "Free disk space in /var", "ok" if free_gb > 2 else "warn", "%.1f GB" % free_gb)
    for host in ("packagecloud.io", "github.com") + (("openresty.org",) if EDGE_KIND == "openresty" else ()):
        try:
            socket.create_connection((host, 443), timeout=5).close()
            add("net-" + host, "Reach " + host, "ok")
        except OSError as e:
            add("net-" + host, "Reach " + host, "fail", str(e))
    if EDGE_KIND == "nginx":
        add("edge-nginx", "Web edge", "info", EDGE_NGINX_MSG)
        theirs = [f for f in glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/conf.d/*.conf")
                  if os.path.basename(f) not in ("default", "crowdsec_nginx.conf", "cloudflare_realip.conf")]
        if theirs and not edge_installed():
            add("edge-nginx-sites", "nginx on this server", "warn", "nginx already serves other sites here (%s). The edge replaces nginx's main "
                "config (the original is kept), so those sites would stop; turn the edge off or move them first." % ", ".join(sorted(theirs)[:4]))
    existing = detect_existing()
    labels = {"legacyCowsec": "Earlier hand-installed CowSec (already migrated by the package)", "certbot": "Existing certificates (%s)",
              "edgeSites": "Existing OpenResty sites (will be replaced, originals kept)", "cloudflareRealIP": "Existing Cloudflare real-IP setup",
              "chronyPtp": "Existing KVM clock config", "duplicateAcquisition": "CrowdSec already reads mailcow logs or runs AppSec (duplicates will be commented out)",
              "policy": "Existing ban policy (kept)"}
    for k, v in existing.items():
        title = labels[k] % v.get("name") if k == "certbot" else labels[k]
        if k == "certbot" and v.get("authenticator") in ("standalone", "webroot", "nginx", "apache"):
            add("existing-certbot-http01", "Existing certificates renew over HTTP-01", "warn",
                "certbot uses '%s', which needs port 80; behind the edge it can't renew. Choose DNS-01 in the wizard instead." % v["authenticator"])
        detail = ", ".join(v.get("files", [])[:3]) if isinstance(v, dict) and v.get("files") else (", ".join(v.get("names", [])[:4]) if k == "certbot" else "")
        add("existing-" + k, title, "info", detail)
    return {"checks": checks, "mailcow": mc, "ok": not any(c["status"] == "fail" for c in checks), "ipv6": ipv6_enabled(), "existing": existing,
            "fresh": fresh_facts() if not mc["found"] else None}


# ---------------------------------------------------------------- DNS providers (lego)

def ensure_lego(r=None):
    if os.path.exists(LEGO_BIN):
        rc, out = run([LEGO_BIN, "--version"])
        if LEGO_VERSION in out:
            return LEGO_BIN
    with tempfile.TemporaryDirectory() as td:
        tgz = os.path.join(td, "lego.tgz")
        if r:
            r.log("downloading lego %s (checksum pinned)" % LEGO_VERSION)
        download(LEGO_URL, tgz, LEGO_SHA256)
        with tarfile.open(tgz) as t:
            member = t.getmember("lego")
            src = t.extractfile(member)
            os.makedirs(LIB_DIR, exist_ok=True)
            with open(LEGO_BIN + ".tmp", "wb") as f:
                shutil.copyfileobj(src, f)
    os.chmod(LEGO_BIN + ".tmp", 0o755)
    os.replace(LEGO_BIN + ".tmp", LEGO_BIN)
    return LEGO_BIN


def dns_providers():
    rc, out = run([ensure_lego(), "dnshelp"], timeout=30)
    m = re.search(r"Supported DNS providers:\s*(.+?)\n\s*\n", out + "\n\n", re.S)
    codes = [c.strip() for c in m.group(1).replace("\n", " ").split(",")] if m else []
    return [c for c in codes if re.fullmatch(r"[a-z0-9-]+", c) and c not in ("exec", "manual", "httpreq")]


def dns_provider_help(code):
    if not re.fullmatch(r"[a-z0-9-]+", code or ""):
        raise StepError("bad provider code")
    rc, out = run([ensure_lego(), "dnshelp", "-c", code], timeout=30)
    if rc != 0:
        raise StepError("unknown provider " + code)
    title = re.search(r"Configuration for (.+?)\.\n", out)

    def section(name):
        m = re.search(name + r":\n(.*?)(?:\n\n|\Z)", out, re.S)
        items = []
        for line in (m.group(1).splitlines() if m else []):
            mm = re.match(r'\s*-\s*"([A-Z0-9_]+)":\s*(.*)', line)
            if mm:
                items.append({"name": mm.group(1), "description": mm.group(2).strip(), "alias": mm.group(2).startswith("Alias to")})
        return items
    url = re.search(r"More information: (\S+)", out)
    return {"code": code, "name": title.group(1) if title else code, "credentials": section("Credentials"),
            "additional": section("Additional Configuration"), "docs": url.group(1) if url else None}


# ---------------------------------------------------------------- config

def validate_config(c):
    """Validates the wizard / CLI config; returns a clean copy (secrets included)."""
    if not isinstance(c, dict):
        raise StepError("config must be an object")
    out = {"homeCountries": [], "components": {}, "certs": {"mode": "mailcow"}, "access": {"mode": "local"}, "lanRanges": PRIVATE_RANGES}
    hc = c.get("homeCountries") or []
    if not hc or not all(isinstance(x, str) and re.fullmatch(r"[A-Z]{2}", x) for x in hc):
        raise StepError("homeCountries must be ISO country codes, e.g. [\"GB\"]")
    out["homeCountries"] = sorted(set(hc))
    comp = c.get("components") or {}
    for k, default in (("edge", True), ("adminLanOnly", True), ("cloudflareRealIP", False), ("chronyPtp", False), ("banPolicy", True), ("mailcowApi", True)):
        v = comp.get(k, default)
        if not isinstance(v, bool):
            raise StepError("components.%s must be true/false" % k)
        out["components"][k] = v
    ranges = c.get("lanRanges") or PRIVATE_RANGES
    try:
        out["lanRanges"] = [str(ipaddress.ip_network(x, strict=False)) for x in ranges]
    except ValueError as e:
        raise StepError("lanRanges: %s" % e)
    m = c.get("mailcow") or {"mode": "existing"}
    if m.get("mode") not in ("existing", "install"):
        raise StepError("mailcow.mode must be existing or install")
    out["mailcow"] = {"mode": m["mode"]}
    if m["mode"] == "install":
        host = str(m.get("hostname", "")).strip().lower()
        if not re.fullmatch(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
            raise StepError("the mail server hostname must be a full name like mail.example.com")
        if host.count(".") == 1 and not m.get("acceptNoSubdomain"):
            raise StepError("%s has no subdomain; mailcow doesn't fully test that. Use e.g. mail.%s, or confirm it" % (host, host))
        tz = str(m.get("timezone", ""))
        if not re.fullmatch(r"[A-Za-z0-9_+/-]{1,64}", tz) or not os.path.exists("/usr/share/zoneinfo/" + tz):
            raise StepError("choose a valid timezone")
        if m.get("branch", "master") not in MAILCOW_BRANCHES:
            raise StepError("mailcow.branch must be master or nightly")
        out["mailcow"].update(hostname=host, timezone=tz, skipClamd=bool(m.get("skipClamd", False)), branch=m.get("branch", "master"))
    certs = c.get("certs") or {"mode": "mailcow"}
    if certs.get("mode") not in ("mailcow", "dns01", "existing"):
        raise StepError("certs.mode must be mailcow, dns01 or existing")
    if certs["mode"] == "dns01":
        if not out["components"]["edge"]:
            raise StepError("DNS-01 certificates are deployed through the edge; enable it")
        prov = certs.get("provider", "")
        if not re.fullmatch(r"[a-z0-9-]+", prov):
            raise StepError("choose a DNS provider")
        creds = certs.get("credentials") or {}
        if not creds or not all(re.fullmatch(r"[A-Z0-9_]+", k) and isinstance(v, str) and v and "\n" not in v for k, v in creds.items()):
            raise StepError("enter the DNS provider credentials")
        email = certs.get("email", "")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            raise StepError("enter a valid e-mail address for Let's Encrypt")
        doms = certs.get("domains") or []
        if not doms or not all(re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d) for d in doms):
            raise StepError("choose at least one domain for certificates")
        resolvers = certs.get("resolvers") or DEFAULT_RESOLVERS
        if not all(isinstance(x, str) and re.fullmatch(r"[0-9a-fA-F.:\[\]]+:\d+", x) for x in resolvers):
            raise StepError("resolvers must look like 1.1.1.1:53")
        out["certs"] = {"mode": "dns01", "provider": prov, "credentials": creds, "email": email, "domains": sorted(set(doms)),
                        "perDomain": bool(certs.get("perDomain", True)), "wildcard": bool(certs.get("wildcard", True)),
                        "staging": bool(certs.get("staging", False)), "resolvers": resolvers}
    if certs["mode"] == "existing":
        cp, kp = str(certs.get("certPath", "")), str(certs.get("keyPath", ""))
        if not (cp.startswith("/") and kp.startswith("/") and os.path.isfile(cp) and os.path.isfile(kp)):
            raise StepError("the existing certificate and key files were not found")
        out["certs"] = {"mode": "existing", "certPath": cp, "keyPath": kp}
    acc = c.get("access") or {"mode": "local"}
    mode = acc.get("mode")
    if mode not in ("local", "lan", "wan", "tunnel"):
        raise StepError("access.mode must be local, lan, wan or tunnel")
    out["access"] = {"mode": mode}
    if mode in ("lan", "wan"):
        if not out["components"]["edge"]:
            raise StepError("LAN and internet access are served by the edge; enable it")
        host = (acc.get("hostname") or "").lower()
        if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", host):
            raise StepError("enter the hostname for the console, e.g. cowsec.example.com")
        out["access"]["hostname"] = host
    if mode == "tunnel":
        tok = acc.get("tunnelToken", "")
        if not re.fullmatch(r"[A-Za-z0-9_\-=.]{40,4096}", tok):
            raise StepError("paste the Cloudflare Tunnel token (from Zero Trust > Networks > Tunnels)")
        out["access"]["tunnelToken"] = tok
    return out


def public_config(c):
    """The config without secrets, safe to store and show."""
    p = json.loads(json.dumps(c))
    if "credentials" in p.get("certs", {}):
        p["certs"]["credentials"] = {k: "••••" for k in p["certs"]["credentials"]}
    if "tunnelToken" in p.get("access", {}):
        p["access"]["tunnelToken"] = "••••"
    return p


# Newest first. A repository that doesn't publish a release yet usually works with the one before.
RELEASE_ORDER = {"debian": ["forky", "trixie", "bookworm"], "ubuntu": ["questing", "plucky", "noble", "jammy"]}


def codename_candidates(flavour, code):
    """This release first, then the older ones, newest first."""
    order = RELEASE_ORDER.get(flavour, [])
    return [code] + (order[order.index(code) + 1:] if code in order else list(order))


def repo_codename(base, flavour, code, r=None):
    """The release a package repository actually publishes for this system: this system's own
    if it has one, otherwise the nearest older release (e.g. CrowdSec's packages for Debian 12
    on Debian 13 until CrowdSec publishes a trixie section)."""
    for cand in codename_candidates(flavour, code):
        for name in ("InRelease", "Release"):
            try:
                req = urllib.request.Request("%s/dists/%s/%s" % (base.rstrip("/"), cand, name), method="HEAD",
                                             headers={"User-Agent": "cowsec-setup"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    if resp.status == 200:
                        if cand != code and r:
                            r.log("%s has no %s release yet; using its %s packages" % (base, code, cand))
                        return cand
            except Exception:
                continue
    return code


# ---------------------------------------------------------------- steps

def step_crowdsec(c, r, ctx):
    osid, ver, code = os_release()
    flavour = "ubuntu" if osid == "ubuntu" else "debian"
    code = repo_codename("https://packagecloud.io/crowdsec/crowdsec/" + flavour, flavour, code, r)
    apt_key_repo(r, "crowdsec_crowdsec", "https://packagecloud.io/crowdsec/crowdsec/gpgkey",
                 "deb [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/%s/ %s main" % (flavour, code),
                 "/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg")
    apt_install(r, ["crowdsec"])
    r.sh(["cscli", "hub", "update"])
    r.sh(["cscli", "collections", "install"] + COLLECTIONS)


def mailcow_acquis(c, mc):
    names = mc["containers"]
    mail = [names[s]["name"] for s in ("postfix-mailcow", "dovecot-mailcow") if s in names]
    docs = ["# Managed by CowSec: mailcow logs (read through the Docker API).",
            "source: docker\ncontainer_name:\n" + "".join("  - %s\n" % n for n in mail) + "labels:\n  type: syslog\n"]
    if c["components"]["edge"]:
        docs.append("source: file\nfilenames:\n  - %s/access.log\n  - %s/error.log\nlabels:\n  type: nginx\n" % (EDGE_LOGS, EDGE_LOGS))
    elif "nginx-mailcow" in names:
        docs.append("source: docker\ncontainer_name:\n  - %s\nlabels:\n  type: nginx\n" % names["nginx-mailcow"]["name"])
    return docs[0] + "\n" + "---\n".join(docs[1:])


def private_whitelist(c):
    return ("# Managed by CowSec: never ban the local network.\n"
            "name: cowsec/private-whitelist\ndescription: \"Local network ranges (CowSec)\"\n"
            "whitelist:\n  reason: \"local network\"\n  cidr:\n" + "".join('    - "%s"\n' % x for x in c["lanRanges"]))


def step_detection(c, r, ctx):
    mc = ctx["mailcow"]
    ours = {CS_DIR + "/acquis.d/cowsec-mailcow.yaml", CS_DIR + "/acquis.d/cowsec-appsec.yaml"}
    for f in [CS_DIR + "/acquis.yaml"] + glob.glob(CS_DIR + "/acquis.d/*.yaml"):
        if f in ours or not os.path.exists(f):
            continue
        txt = "\n".join(l for l in open(f).read().split("\n") if not l.lstrip().startswith("#"))
        dup = [v["name"] for k, v in mc["containers"].items() if k in ("postfix-mailcow", "dovecot-mailcow", "nginx-mailcow") and v["name"] in txt]
        if dup:
            r.log("WARNING: %s already reads %s; remove those entries or every event is counted twice" % (f, ", ".join(dup)))
    write(CS_DIR + "/acquis.d/cowsec-mailcow.yaml", mailcow_acquis(c, mc), r=r)
    write(CS_DIR + "/parsers/s02-enrich/cowsec-private-whitelist.yaml", private_whitelist(c), r=r)
    ctx["reload_crowdsec"] = True


def step_firewall(c, r, ctx):
    inv = crowdsec_inventory()
    nft = firewall_uses_nft(inv)
    if inv["firewall"]:
        r.log("keeping the installed %s %s" % (inv["firewall"], inv["firewallVersion"]))
    else:
        apt_install(r, [FW_PKGS[1] if nft else FW_PKGS[0]])
    txt = open(FW_CONF).read()
    if nft:
        # mailcow's mail ports are DNAT'd by Docker, so they pass the forward hook, not input
        key, block = "nftables_hooks", "nftables_hooks:\n  - input\n  - forward\n"
    else:
        key, block = "iptables_chains", "iptables_chains:\n  - INPUT\n  - DOCKER-USER\n"
    m = re.search(r"^%s:\n((?:[ \t]*#?[ \t]*-[^\n]*\n)+)" % key, txt, re.M)
    new = txt.replace(m.group(0), block) if m else txt.rstrip("\n") + "\n\n" + block
    url = lapi_url()
    new = re.sub(r"(?m)^api_url:.*$", "api_url: " + url, new)
    if write(FW_CONF, new, 0o600, r):
        r.sh(["systemctl", "restart", "crowdsec-firewall-bouncer"])
    r.sh(["systemctl", "enable", "--now", "crowdsec-firewall-bouncer"])
    for _ in range(5):
        ok, how = firewall_covers_docker()
        if ok:
            break
        time.sleep(2)
    r.log("mail ports protected (%s)" % how if ok else "warning: %s rule not found yet" % how)


# --- the web edge (OpenResty, or Debian's nginx on Debian 13)

NGINX_CONF = """# Managed by CowSec: {name} edge in front of mailcow (CrowdSec bouncer + AppSec WAF).
{head}worker_processes auto;
events { worker_connections 2048; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    server_tokens off;
    access_log {logs}/access.log combined;
    error_log  {logs}/error.log warn;
    map $http_upgrade $connection_upgrade { default upgrade; "" close; }
    include conf.d/*.conf;
    include sites/*.conf;
}
"""


def edge_nginx_conf():
    # Debian's nginx loads the Lua module from modules-enabled and its unit expects /run/nginx.pid
    head = "user www-data;\npid /run/nginx.pid;\ninclude /etc/nginx/modules-enabled/*.conf;\n" if EDGE_KIND == "nginx" else ""
    return NGINX_CONF.replace("{name}", EDGES[EDGE_KIND]["name"]).replace("{head}", head).replace("{logs}", EDGE_LOGS)


def edge_installed():
    return os.path.exists(NGX + "/sites/cowsec-mailcow.conf")


def edge_test_reload(r, check=True):
    """Tests the edge's configuration, then reloads it."""
    rc = r.sh([EDGE_BIN, "-t", "-q"], check=check)[0]
    if rc == 0:
        r.sh(["systemctl", "reload", EDGE_SVC], check=check)
    return rc == 0

PROXY_CONF = """# Managed by CowSec: proxy to mailcow's nginx (bound to localhost).
proxy_pass https://127.0.0.1:{https};
proxy_ssl_server_name on;
proxy_ssl_name $host;
proxy_set_header Host $host;
# Overwrite (never append) so clients cannot spoof their address; mailcow trusts this header.
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_buffering off;
proxy_request_buffering off;
proxy_read_timeout 3600s;   # ActiveSync long-polling
proxy_send_timeout 3600s;
"""


def listen(port, ssl, default, v6):
    opts = (" ssl" if ssl else "") + (" default_server" if default else "")
    return "    listen %d%s;\n" % (port, opts) + ("    listen [::]:%d%s;\n" % (port, opts) if v6 else "")


def site_body(c, cert, key):
    allow = "".join("        allow %s;\n" % x for x in c["lanRanges"])
    admin = ("    # mailcow admin and domain-admin UI: local network only\n"
             "    location ~* ^/(admin|domainadmin)(/|$) {\n%s        deny all;\n        include cowsec_mailcow_proxy.conf;\n    }\n" % allow) if c["components"]["adminLanOnly"] else ""
    return ("    http2 on;\n    ssl_certificate     %s;\n    ssl_certificate_key %s;\n    ssl_protocols TLSv1.2 TLSv1.3;\n"
            "    ssl_session_cache shared:SSL:10m;\n    client_max_body_size 0;\n%s    location / { include cowsec_mailcow_proxy.conf; }\n" % (cert, key, admin))


def http_status(host, port, path="/", timeout=3):
    """HTTP status code from a plain-HTTP server, without following redirects (None if it doesn't answer)."""
    import http.client
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"Host": "localhost"})
        return conn.getresponse().status
    except (OSError, http.client.HTTPException):
        return None


def fix_mailcow_http_port(r):
    """Move mailcow's local web port off 8081, which CowSec used for the edge up to 0.3.9.

    mailcow's nginx already listens on 8081 inside its container for postfix's forwarding-host
    lookups, so with HTTP_PORT=8081 those lookups got mailcow's HTTP-to-HTTPS redirect instead of
    an answer, and forwarding hosts weren't recognised. Changes only HTTP_PORT and the edge's ACME
    proxy line, recreates only nginx-mailcow, and puts everything back if any step fails."""
    mc = find_mailcow()
    site = NGX + "/sites/cowsec-mailcow.conf"
    if not mc or not os.path.exists(site):
        return {"changed": False, "reason": "the edge isn't in front of mailcow"}
    conf_path = os.path.join(mc, "mailcow.conf")
    conf = read_kv(conf_path)
    if conf.get("HTTP_PORT") != str(OLD_EDGE_MAILCOW_HTTP) or conf.get("HTTP_BIND") != "127.0.0.1":
        return {"changed": False, "reason": "not affected"}
    if http_status("127.0.0.1", EDGE_MAILCOW_HTTP) is not None:
        raise StepError("port %d is already in use, so mailcow can't move there" % EDGE_MAILCOW_HTTP)
    old_conf, old_site = open(conf_path).read(), open(site).read()
    r.log("moving mailcow's local web port from %d to %d (8081 clashes with mailcow's internal lookups)" % (OLD_EDGE_MAILCOW_HTTP, EDGE_MAILCOW_HTTP))
    try:
        set_kv(conf_path, {"HTTP_PORT": str(EDGE_MAILCOW_HTTP)}, r)
        write(site, old_site.replace("127.0.0.1:%d" % OLD_EDGE_MAILCOW_HTTP, "127.0.0.1:%d" % EDGE_MAILCOW_HTTP), r=r)
        if r.sh([EDGE_BIN, "-t", "-q"], check=False)[0] != 0:
            raise StepError("the edge's configuration test failed")
        compose(mc, ["up", "-d", "--no-deps", "nginx-mailcow"], r)
        for _ in range(60):
            if http_status("127.0.0.1", EDGE_MAILCOW_HTTP) is not None:
                break
            time.sleep(1)
        else:
            raise StepError("mailcow's web server didn't come back on port %d" % EDGE_MAILCOW_HTTP)
        r.sh(["systemctl", "reload", EDGE_SVC])
    except Exception as e:
        r.log("putting the old port back: %s" % e)
        write(conf_path, old_conf, r=r, keep_backup=False)
        write(site, old_site, r=r, keep_backup=False)
        compose(mc, ["up", "-d", "--no-deps", "nginx-mailcow"], r, check=False)
        r.sh(["systemctl", "reload", EDGE_SVC], check=False)
        raise
    rc, out = compose(mc, ["exec", "-T", "postfix-mailcow", "curl", "-s", "http://nginx:8081/forwardinghosts.php?host=127.0.0.1"], check=False)
    ok = rc == 0 and "<html" not in out.lower()
    r.log("postfix's forwarding-host lookup %s" % ("answers again" if ok else "still doesn't answer: " + out[:120]))
    return {"changed": True, "lookup_ok": ok}


def edge_sites(c, ctx):
    v6 = ctx["ipv6"]
    mc = ctx["mailcow"]
    cert, key = default_cert(c, ctx)
    out = ["# Managed by CowSec: mailcow behind the edge.\n",
           "server {\n" + listen(80, False, True, v6) + "    server_name _;\n"
           "    # mailcow's own Let's Encrypt (HTTP-01) keeps working through the edge\n"
           "    location ^~ /.well-known/acme-challenge/ { proxy_pass http://127.0.0.1:%d; proxy_set_header Host $host; }\n"
           "    location / { return 301 https://$host$request_uri; }\n}\n" % EDGE_MAILCOW_HTTP,
           "server {\n" + listen(443, True, True, v6) + "    server_name _;\n" + site_body(c, cert, key) + "}\n"]
    for dom, (dcert, dkey) in sorted(ctx.get("domain_certs", {}).items()):
        out.append("server {\n" + listen(443, True, False, v6) + "    server_name .%s;\n" % dom + site_body(c, dcert, dkey) + "}\n")
    return "\n".join(out)


def default_cert(c, ctx):
    if c["certs"]["mode"] == "dns01" and ctx.get("main_cert"):
        return ctx["main_cert"]
    if c["certs"]["mode"] == "existing":
        return c["certs"]["certPath"], c["certs"]["keyPath"]
    ssl = os.path.join(ctx["mailcow"]["dir"], "data/assets/ssl")
    return os.path.join(ssl, "cert.pem"), os.path.join(ssl, "key.pem")


def ensure_resty_http(r):
    if os.path.exists(os.path.join(RESTY_DIR, "http.lua")):
        r.log("lua-resty-http present")
        return
    if shutil.which("opm"):
        rc, out = r.sh(["opm", "get", "ledgetech/lua-resty-http=" + RESTY_HTTP_VERSION], check=False)
        if rc == 0 and os.path.exists(os.path.join(RESTY_DIR, "http.lua")):
            return
    r.log("installing lua-resty-http %s from GitHub (checksum pinned)" % RESTY_HTTP_VERSION)
    with tempfile.TemporaryDirectory() as td:
        tgz = os.path.join(td, "resty-http.tgz")
        download(RESTY_HTTP_URL, tgz, RESTY_HTTP_SHA256)
        os.makedirs(RESTY_DIR, exist_ok=True)
        with tarfile.open(tgz) as t:
            for m in t.getmembers():
                if m.isfile() and "/lib/resty/" in m.name and m.name.endswith(".lua"):
                    with open(os.path.join(RESTY_DIR, os.path.basename(m.name)), "wb") as f:
                        shutil.copyfileobj(t.extractfile(m), f)
    if not os.path.exists(os.path.join(RESTY_DIR, "http.lua")):
        raise StepError("could not install lua-resty-http")


def openresty_blocked():
    """Debian 13's apt verifies signatures with sqv, which has rejected SHA-1-bound keys since
    2026-02-01. OpenResty's repository key is still SHA-1-bound (openresty/openresty#1072), so
    apt refuses the repository. Weakening apt's policy for every repository isn't acceptable,
    so the edge there is Debian's own nginx instead (see EDGES)."""
    osid, ver, _ = os_release()
    if osid != "debian" or not ver.isdigit() or int(ver) < 13 or not os.path.exists("/usr/bin/sqv"):
        return False
    return os.environ.get("COWSEC_OPENRESTY_KEY_FIXED") != "1"


EDGE_NGINX_MSG = ("Debian 13's apt rejects OpenResty's package signing key because it still uses SHA-1 "
                  "(openresty/openresty#1072), so the edge here is Debian's own nginx with its Lua module and CrowdSec's "
                  "nginx bouncer. Same WAF and bans, and every package is signed by Debian or CrowdSec.")


def edge_kind():
    """Which edge this server uses: the one already installed, else OpenResty unless it's blocked."""
    forced = os.environ.get("COWSEC_EDGE")
    if forced in EDGES:
        return forced
    try:
        kind = open(EDGE_FILE).read().strip()
        if kind in EDGES:
            return kind
    except OSError:
        pass
    if os.path.exists(EDGES["openresty"]["bin"]):
        return "openresty"
    return "nginx" if openresty_blocked() else "openresty"


def use_edge(kind):
    global EDGE_KIND, EDGE_SVC, EDGE_BIN, EDGE_LOGS, EDGE_BOUNCER, EDGE_BOUNCER_CONF, NGX, RESTY_DIR
    e = EDGES[kind]
    EDGE_KIND, EDGE_SVC, EDGE_BIN, EDGE_LOGS, EDGE_BOUNCER = kind, e["service"], e["bin"], e["logs"], e["bouncer"]
    EDGE_BOUNCER_CONF = CS_DIR + "/bouncers/%s.conf" % e["bouncer"]
    NGX, RESTY_DIR = e["conf"], e["resty"]


def step_edge(c, r, ctx):
    mc = ctx["mailcow"]
    if EDGE_KIND == "nginx":
        r.log(EDGE_NGINX_MSG)
        # lua-cjson from Debian: the bouncer's own script would build it with luarocks, which needs a compiler
        apt_install(r, ["nginx", "libnginx-mod-http-lua", "lua-resty-core", "lua-resty-lrucache", "lua-cjson", "luarocks", EDGE_BOUNCER],
                    no_start=True)
    else:
        osid, ver, code = os_release()
        flavour, comp = ("ubuntu", "main") if osid == "ubuntu" else ("debian", "openresty")
        code = repo_codename("https://openresty.org/package/" + flavour, flavour, code, r)
        apt_key_repo(r, "openresty", "https://openresty.org/package/pubkey.gpg",
                     "deb [signed-by=/usr/share/keyrings/openresty.gpg] https://openresty.org/package/%s %s %s" % (flavour, code, comp),
                     "/usr/share/keyrings/openresty.gpg")
        apt_install(r, ["openresty", EDGE_BOUNCER], no_start=True)
    write(EDGE_FILE, EDGE_KIND + "\n", r=r, keep_backup=False)
    r.sh(["systemctl", "stop", EDGE_SVC], check=False)
    ensure_resty_http(r)
    os.makedirs(EDGE_LOGS, exist_ok=True)
    os.makedirs(NGX + "/sites", exist_ok=True)
    conf_path = os.path.join(mc["dir"], "mailcow.conf")
    moving = (mc["httpsBind"] != "127.0.0.1" or mc["httpsPort"] != str(EDGE_MAILCOW_HTTPS)
              or mc["httpPort"] != str(EDGE_MAILCOW_HTTP))
    write(NGX + "/nginx.conf", edge_nginx_conf(), r=r)
    write(NGX + "/cowsec_mailcow_proxy.conf", PROXY_CONF.replace("{https}", str(EDGE_MAILCOW_HTTPS)), r=r)
    write(NGX + "/sites/cowsec-mailcow.conf", edge_sites(c, ctx), r=r)
    # AppSec WAF: engine on localhost, bouncer asks it about every request
    write(CS_DIR + "/acquis.d/cowsec-appsec.yaml",
          "# Managed by CowSec: AppSec (WAF) engine for the edge.\nappsec_config: crowdsecurity/appsec-default\n"
          "labels:\n  type: appsec\nlisten_addr: 127.0.0.1:7422\nsource: appsec\n", r=r)
    r.sh(["cscli", "collections", "install"] + APPSEC_COLLECTIONS)
    try:
        appsec_curate(r)  # mail WAF: mail-stack rules block, everything else watches for scanners
    except StepError as e:
        r.log("mail WAF not applied, CrowdSec's default AppSec config stays: %s" % e)
    bconf = EDGE_BOUNCER_CONF
    set_kv(bconf, {"API_URL": lapi_url().rstrip("/"), "APPSEC_URL": "http://127.0.0.1:7422", "APPSEC_FAILURE_ACTION": "passthrough", "MODE": "live"}, r)
    os.chmod(bconf, 0o600)
    restart_crowdsec(r)
    if moving:
        r.log("moving mailcow's web server to 127.0.0.1:%d/%d so the edge can own ports 80/443" % (EDGE_MAILCOW_HTTP, EDGE_MAILCOW_HTTPS))
        backup(conf_path, r)
        r.sh(["systemctl", "stop", EDGE_SVC], check=False)
        set_kv(conf_path, {"HTTP_PORT": str(EDGE_MAILCOW_HTTP), "HTTP_BIND": "127.0.0.1",
                           "HTTPS_PORT": str(EDGE_MAILCOW_HTTPS), "HTTPS_BIND": "127.0.0.1"}, r)
        compose(mc["dir"], ["up", "-d"], r)
        ctx["rollback_mailcow_conf"] = True
    rc, out = r.sh([EDGE_BIN, "-t"], check=False)
    if rc != 0:
        raise StepError("the edge's configuration test failed")
    r.sh(["systemctl", "enable", EDGE_SVC])
    r.sh(["systemctl", "restart", EDGE_SVC])
    for _ in range(20):
        if run(["systemctl", "is-active", "--quiet", EDGE_SVC])[0] == 0:
            break
        time.sleep(1)
    else:
        raise StepError("the edge did not start (see journalctl -u %s)" % EDGE_SVC)
    ctx.pop("rollback_mailcow_conf", None)
    # Reload the edge when mailcow (or the existing ACME client) renews the certificate.
    if c["certs"]["mode"] in ("mailcow", "existing"):
        cert = c["certs"]["certPath"] if c["certs"]["mode"] == "existing" else os.path.join(mc["dir"], "data/assets/ssl/cert.pem")
        if cert.startswith("/etc/letsencrypt/"):
            # certbot swaps symlinks on renewal, which a path watch can miss
            write("/etc/letsencrypt/renewal-hooks/deploy/cowsec-openresty.sh",
                  "#!/bin/sh\n# Managed by CowSec: reload the edge after certbot renews.\n"
                  "systemctl is-active -q %s && systemctl reload %s || true\n" % (EDGE_SVC, EDGE_SVC), 0o755, r=r)
        write("/etc/systemd/system/cowsec-cert-watch.path",
              "[Unit]\nDescription=Reload the edge when the mail certificate is renewed (CowSec)\n\n"
              "[Path]\nPathChanged=%s\n\n[Install]\nWantedBy=multi-user.target\n" % cert, r=r)
        write("/etc/systemd/system/cowsec-cert-watch.service",
              "[Unit]\nDescription=Reload the edge after a mailcow certificate change (CowSec)\n\n"
              "[Service]\nType=oneshot\nExecStartPre=/bin/sleep 10\nExecStart=/bin/systemctl reload %s\n" % EDGE_SVC, r=r)
        r.sh(["systemctl", "daemon-reload"])
        r.sh(["systemctl", "enable", "--now", "cowsec-cert-watch.path"])
    write(CS_DIR + "/acquis.d/cowsec-mailcow.yaml", mailcow_acquis(c, mc), r=r)
    ctx["reload_crowdsec"] = True


def rollback_edge(c, r, ctx):
    mc = ctx["mailcow"]
    conf_path = os.path.join(mc["dir"], "mailcow.conf")
    baks = sorted(glob.glob(conf_path + ".cowsec-bak-*"))
    if baks:
        r.log("rolling back: restoring %s and restarting mailcow's web server" % baks[-1])
        r.sh(["systemctl", "stop", EDGE_SVC], check=False)
        shutil.copy2(baks[-1], conf_path)
        compose(mc["dir"], ["up", "-d"], r, check=False)


# --- certificates (DNS-01 via lego)

def cert_names(dom, c, mc):
    if c["certs"]["wildcard"]:
        return [dom, "*." + dom]
    names = [dom, "mail." + dom, "autodiscover." + dom, "autoconfig." + dom, "mta-sts." + dom]
    return names


def lego_env(c):
    env = dict(c["certs"]["credentials"])
    env.update({"LEGO_PATH": ACME_DIR})
    return env


def issue(name, domains, c, r):
    args = [ensure_lego(r), "run", "--path", ACME_DIR, "--cert.name", name, "--accept-tos", "--email", c["certs"]["email"],
            "--dns", c["certs"]["provider"], "--key-type", "EC256", "--no-random-sleep"]
    # Check propagation against the zone's authoritative nameservers, not the local resolver:
    # home routers, Pi-hole, Blocky etc. cache the earlier "no such record" answer.
    args += ["--dns.propagation.disable-rns"]
    for res in c["certs"].get("resolvers") or DEFAULT_RESOLVERS:
        args += ["--dns.resolvers", res]
    if c["certs"].get("staging"):
        args += ["--server", "https://acme-staging-v02.api.letsencrypt.org/directory"]
    for d in domains:
        args += ["-d", d]
    r.sh(args, env=lego_env(c), timeout=900)
    crt = glob.glob(os.path.join(ACME_DIR, "certificates", name + ".crt")) or glob.glob(os.path.join(ACME_DIR, "**", name + ".crt"), recursive=True)
    key = glob.glob(os.path.join(ACME_DIR, "certificates", name + ".key")) or glob.glob(os.path.join(ACME_DIR, "**", name + ".key"), recursive=True)
    if not crt or not key:
        raise StepError("lego finished but no certificate files for %s were found" % name)
    dst = os.path.join(CERT_DIR, name)
    os.makedirs(dst, mode=0o700, exist_ok=True)
    full, priv = os.path.join(dst, "fullchain.pem"), os.path.join(dst, "privkey.pem")
    old = open(full, "rb").read() if os.path.exists(full) else None
    shutil.copy2(crt[0], full)
    shutil.copy2(key[0], priv)
    os.chmod(priv, 0o600)
    return full, priv, open(full, "rb").read() != old


def deploy_certs(c, r, ctx):
    """Installs issued certificates into mailcow (main + per-hostname SNI folders) and the edge."""
    mc = ctx["mailcow"]
    ssl = os.path.join(mc["dir"], "data/assets/ssl")
    mcert, mkey = ctx["main_cert"]
    shutil.copy2(mcert, os.path.join(ssl, "cert.pem"))
    shutil.copy2(mkey, os.path.join(ssl, "key.pem"))
    os.chmod(os.path.join(ssl, "key.pem"), 0o600)
    sni_lines = []
    for dom, (crt, key) in sorted(ctx.get("domain_certs", {}).items()):
        d = os.path.join(ssl, dom)
        os.makedirs(d, exist_ok=True)
        shutil.copy2(crt, os.path.join(d, "cert.pem"))
        shutil.copy2(key, os.path.join(d, "key.pem"))
        os.chmod(os.path.join(d, "key.pem"), 0o600)
        names = [dom, "mail." + dom, "autodiscover." + dom, "autoconfig." + dom, "mta-sts." + dom]
        with open(os.path.join(d, "domains"), "w") as f:
            f.write(" ".join(names))
        for n in names:
            sni_lines.append("%s /etc/ssl/mail/%s/key.pem /etc/ssl/mail/%s/cert.pem" % (n, dom, dom))
    # Postfix ignores mailcow's SNI folders when SKIP_LETS_ENCRYPT=y, so CowSec adds its own map.
    pf = os.path.join(mc["dir"], "data/conf/postfix")
    extra = os.path.join(pf, "extra.cf")
    cur = open(extra).read() if os.path.exists(extra) else ""
    cur = re.sub(r"\n?# BEGIN cowsec-sni.*?# END cowsec-sni\n?", "\n", cur, flags=re.S).rstrip("\n")
    if sni_lines:
        write(os.path.join(pf, "cowsec_sni.map"), "\n".join(sni_lines) + "\n", r=r)
        cur += "\n# BEGIN cowsec-sni (managed by CowSec: per-domain certificates for SMTP)\ntls_server_sni_maps = hash:/opt/postfix/conf/cowsec_sni.map\n# END cowsec-sni\n"
    write(extra, cur.lstrip("\n") + ("\n" if cur and not cur.endswith("\n") else ""), r=r)
    set_kv(os.path.join(mc["dir"], "mailcow.conf"), {"SKIP_LETS_ENCRYPT": "y"}, r)
    compose(mc["dir"], ["up", "-d"], r)
    compose(mc["dir"], ["restart", "postfix-mailcow", "dovecot-mailcow", "nginx-mailcow"], r)
    if sni_lines:
        compose(mc["dir"], ["exec", "-T", "postfix-mailcow", "postmap", "-F", "hash:/opt/postfix/conf/cowsec_sni.map"], r)
        compose(mc["dir"], ["exec", "-T", "postfix-mailcow", "postfix", "reload"], r, check=False)
    if os.path.exists(NGX + "/sites/cowsec-mailcow.conf"):
        write(NGX + "/sites/cowsec-mailcow.conf", edge_sites(c, ctx), r=r)
        r.sh([EDGE_BIN, "-t", "-q"])
        r.sh(["systemctl", "reload", EDGE_SVC], check=False)


def host_covered(host, c):
    """True if a configured certificate already covers this hostname."""
    for d in c["certs"]["domains"]:
        if host == d or (host.endswith("." + d) and (c["certs"]["wildcard"] and host.count(".") == d.count(".") + 1
                                                     or host[: -len(d) - 1] in ("mail", "autodiscover", "autoconfig"))):
            return d
    return None


def step_certs(c, r, ctx, force_deploy=True):
    mc = ctx["mailcow"]
    os.makedirs(ETC_DIR, mode=0o700, exist_ok=True)
    env_lines = "".join('%s="%s"\n' % (k, v.replace("\\", "\\\\").replace('"', '\\"')) for k, v in c["certs"]["credentials"].items())
    write(ETC_DIR + "/dns.env", "# DNS provider credentials for lego (CowSec). Root only.\n" + env_lines, 0o600, r=None)
    r.redact += list(c["certs"]["credentials"].values())
    host = mc["hostname"]
    extra = sorted(set(c["certs"].get("extraHosts", [])))
    if c["access"]["mode"] in ("lan", "wan") and not host_covered(c["access"]["hostname"], c):
        extra = sorted(set(extra + [c["access"]["hostname"]]))
    c["certs"]["extraHosts"] = extra
    write(ETC_DIR + "/certs.json", json.dumps({k: v for k, v in c["certs"].items() if k != "credentials"}, indent=2) + "\n", 0o600, r=r)
    changed = False
    ctx["domain_certs"], ctx["host_certs"] = {}, {}
    if c["certs"]["perDomain"]:
        for d in c["certs"]["domains"]:
            crt, key, ch = issue(d, cert_names(d, c, mc), c, r)
            ctx["domain_certs"][d], changed = (crt, key), changed or ch
        parent = host_covered(host, c)
        if parent:
            ctx["main_cert"] = ctx["domain_certs"][parent]
        else:
            crt, key, ch = issue("mailcow-host", [host], c, r)
            ctx["main_cert"], changed = (crt, key), changed or ch
    else:
        names = []
        for d in c["certs"]["domains"]:
            names += cert_names(d, c, mc)
        if not host_covered(host, c):
            names.append(host)
        crt, key, ch = issue("mailcow", names, c, r)
        ctx["main_cert"], changed = (crt, key), ch
    for h in extra:
        crt, key, ch = issue("host-" + h, [h], c, r)
        ctx["host_certs"][h], changed = (crt, key), changed or ch
    if changed or force_deploy:
        deploy_certs(c, r, ctx)
    else:
        r.log("no certificate changed; nothing to deploy")
    write("/etc/systemd/system/cowsec-certs.service",
          "[Unit]\nDescription=Renew CowSec certificates (lego DNS-01)\nAfter=network-online.target\n\n"
          "[Service]\nType=oneshot\nEnvironment=SSH_ORIGINAL_COMMAND=certs-renew\nEnvironment=SSH_CLIENT=timer\nExecStart=%s\n" % HOSTCTL, r=r)
    write("/etc/systemd/system/cowsec-certs.timer",
          "[Unit]\nDescription=Daily CowSec certificate renewal check\n\n[Timer]\nOnCalendar=*-*-* 03:17\nRandomizedDelaySec=1h\nPersistent=true\n\n"
          "[Install]\nWantedBy=timers.target\n", r=r)
    r.sh(["systemctl", "daemon-reload"], quiet=True)
    r.sh(["systemctl", "enable", "--now", "cowsec-certs.timer"], quiet=True)
    r.sh(["systemctl", "disable", "--now", "cowsec-cert-watch.path"], check=False, quiet=True)


def certs_renew(r):
    """Timer entry point: renew due certificates, add new mailcow domains (per-domain mode)
    and redeploy only when something changed."""
    cfgp = ETC_DIR + "/certs.json"
    if not os.path.exists(cfgp):
        r.log("no DNS-01 certificate configuration")
        return
    saved = json.load(open(STATE_DIR + "/setup.json")) if os.path.exists(STATE_DIR + "/setup.json") else {}
    certs = json.load(open(cfgp))
    certs["credentials"] = read_kv(ETC_DIR + "/dns.env")
    r.redact += list(certs["credentials"].values())
    c = {"certs": certs, "components": saved.get("components", {"adminLanOnly": True}),
         "lanRanges": saved.get("lanRanges", PRIVATE_RANGES), "access": {"mode": "local"}}
    mc = mailcow_info()
    ctx = {"mailcow": mc, "ipv6": ipv6_enabled()}
    if certs.get("perDomain") and certs.get("autoAddDomains", True):
        for d in sorted(set(mc.get("domains", [])) - set(certs["domains"])):
            try:
                issue(d, cert_names(d, c, mc), c, r)
                certs["domains"].append(d)
                r.log("added new mailcow domain %s" % d)
            except StepError as e:
                r.log("could not issue a certificate for new domain %s (is it managed by this DNS provider?): %s" % (d, e))
    step_certs(c, r, ctx, force_deploy=False)


# --- smaller components

REALIP_SCRIPT = r"""#!/bin/sh
# Managed by CowSec: trust CF-Connecting-IP only from Cloudflare's published ranges.
set -eu
OUT=@CONF@/conf.d/cloudflare_realip.conf
TMP=$(mktemp)
{ echo "# generated by cowsec-cloudflare-realip $(date -I)"
  for u in https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6; do
    curl -fsS -m 20 "$u" | grep -E '^[0-9a-f.:]+/[0-9]+$' | sed 's/.*/set_real_ip_from &;/'
  done
  echo "real_ip_header CF-Connecting-IP;"; } > "$TMP"
if [ "$(grep -c set_real_ip_from "$TMP")" -lt 10 ]; then echo "too few ranges fetched, keeping old file" >&2; rm -f "$TMP"; exit 1; fi
install -m 644 "$TMP" "$OUT"; rm -f "$TMP"
@BIN@ -t -q && systemctl reload @SVC@
"""


def step_cloudflare_realip(c, r, ctx):
    write(LIB_DIR + "/cowsec-cloudflare-realip", REALIP_SCRIPT.replace("@CONF@", NGX).replace("@BIN@", EDGE_BIN).replace("@SVC@", EDGE_SVC), 0o755, r=r)
    write("/etc/systemd/system/cowsec-cloudflare-realip.service",
          "[Unit]\nDescription=Refresh Cloudflare real-IP ranges for the edge (CowSec)\nAfter=network-online.target\n\n"
          "[Service]\nType=oneshot\nExecStart=%s/cowsec-cloudflare-realip\n" % LIB_DIR, r=r)
    write("/etc/systemd/system/cowsec-cloudflare-realip.timer",
          "[Unit]\nDescription=Monthly Cloudflare real-IP refresh (CowSec)\n\n[Timer]\nOnCalendar=monthly\nPersistent=true\n\n"
          "[Install]\nWantedBy=timers.target\n", r=r)
    r.sh(["systemctl", "daemon-reload"])
    r.sh(["systemctl", "enable", "--now", "cowsec-cloudflare-realip.timer"])
    r.sh(["systemctl", "start", "cowsec-cloudflare-realip.service"])


def step_chrony(c, r, ctx):
    """chrony with internet NTP everywhere; on KVM guests (Proxmox, most VPSs) also the
    hypervisor's clock through the paravirtual PTP device, which is far more precise."""
    apt_install(r, ["chrony"])
    if run(["modprobe", "ptp_kvm"])[0] == 0 and os.path.exists("/dev/ptp0"):
        write("/etc/modules-load.d/cowsec-ptp_kvm.conf", "ptp_kvm\n", r=r)
        write("/etc/chrony/conf.d/cowsec-ptp.conf",
              "# Managed by CowSec: hypervisor clock via the KVM paravirtual PTP device.\n"
              "refclock PHC /dev/ptp0 poll 2 dpoll -2 offset 0 stratum 2 prefer\n", r=r)
    else:
        r.log("no KVM PTP device: using internet NTP servers only")
    r.sh(["systemctl", "enable", "--now", "chrony"])
    r.sh(["systemctl", "restart", "chrony"])


def step_ban_policy(c, r, ctx):
    policy = {"homeCountries": c["homeCountries"],
              "abroad": {"enabled": True, "smtp": True, "imap": True, "failures": 2, "windowHours": 24},
              "escalation": {"enabled": True, "includeHome": False, "baseHours": 4, "mode": "double", "maxHours": 168, "lookbackDays": 7}}
    if os.path.exists(STATE_DIR + "/policy.json"):
        r.log("keeping the existing ban policy")
        return
    write(STATE_DIR + "/policy.pending.json", json.dumps(policy, indent=2), 0o600, r=r)
    r.sh([HOSTCTL], env={"SSH_ORIGINAL_COMMAND": "policy-apply", "SSH_CLIENT": "setup 0 0", "COWSEC_STATE_DIR": STATE_DIR})


def step_mailcow_api(c, r, ctx):
    """Gives CowSec mailcow's API: reuses an existing read-write key (other tools keep
    working), allows only localhost and mailcow's Docker gateway, and stores the key
    root-only in /etc/cowsec/mailcow.env."""
    mc = ctx["mailcow"]
    conf_path = os.path.join(mc["dir"], "mailcow.conf")
    conf = read_kv(conf_path)
    key = conf.get("API_KEY", "")
    if not re.fullmatch(r"[A-Za-z0-9-]{24,}", key):
        key = secrets.token_hex(24)
        r.log("generated a new mailcow API key")
    else:
        r.log("reusing mailcow's existing API key")
    r.redact.append(key)
    gateway = (conf.get("IPV4_NETWORK") or "172.22.1") + ".1"
    allow = [a.strip() for a in conf.get("API_ALLOW_FROM", "").split(",") if a.strip()]
    for a in ("127.0.0.1", "::1", gateway):
        if a not in allow:
            allow.append(a)
    changed = set_kv(conf_path, {"API_KEY": key, "API_ALLOW_FROM": ",".join(allow)}, r)
    port = conf.get("HTTPS_PORT", "443")
    write(ETC_DIR + "/mailcow.env",
          "# mailcow API access for CowSec (root only). Managed by cowsec-setup.\n"
          'COWSEC_MAILCOW_URL="https://127.0.0.1:%s"\nCOWSEC_MAILCOW_HOST="%s"\nCOWSEC_MAILCOW_API_KEY="%s"\n' % (port, mc["hostname"], key), 0o600)
    r.log("wrote /etc/cowsec/mailcow.env (key redacted)")
    if changed:
        compose(mc["dir"], ["up", "-d"], r)
    ctx["restart_cowsec"] = True
    if not os.path.exists(NETFILTER_STATE):
        # mailcow's netfilter and CrowdSec side by side, with trusted networks kept in step
        try:
            netfilter_coordinate("side-by-side", True, r)
        except Exception as e:  # mailcow may still be starting; the console can apply it later
            r.log("netfilter coordination not applied yet: %s" % e)


CONSOLE_SITE = """# Managed by CowSec: the console at {host} ({mode}).
server {{
{listen}    server_name {host};
    http2 on;
    ssl_certificate     {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
{allow}    location / {{
        proxy_pass http://{console};
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
"""


def step_access(c, r, ctx):
    mode = c["access"]["mode"]
    site = NGX + "/sites/cowsec-console.conf"
    envp = ETC_DIR + "/cowsec.env"
    if mode in ("lan", "wan"):
        host = c["access"]["hostname"]
        cert, key = default_cert(c, ctx)
        if c["certs"]["mode"] == "dns01":
            parent = host_covered(host, c)
            if host in ctx.get("host_certs", {}):
                cert, key = ctx["host_certs"][host]
            elif parent and c["certs"]["perDomain"]:
                cert, key = ctx["domain_certs"][parent]
        elif c["certs"]["mode"] == "existing":
            names = cert_names_of(cert)
            if not any(n == host or (n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count(".")) for n in names):
                r.log("warning: your existing certificate doesn't cover %s (it has %s); browsers will warn until it does" % (host, ", ".join(names[:6])))
        else:
            mc = ctx["mailcow"]
            san = [s.strip() for s in mc["additionalSan"].split(",") if s.strip()]
            if host not in san:
                set_kv(os.path.join(mc["dir"], "mailcow.conf"), {"ADDITIONAL_SAN": ",".join(san + [host])}, r)
                compose(mc["dir"], ["up", "-d"], r)
                r.log("added %s to mailcow's certificate (ADDITIONAL_SAN); its DNS record must point at this server" % host)
        allow = ("".join("    allow %s;\n" % x for x in c["lanRanges"]) + "    deny all;\n") if mode == "lan" else ""
        write(site, CONSOLE_SITE.format(host=host, mode=mode, listen=listen(443, True, False, ctx["ipv6"]), cert=cert, key=key,
                                        allow=allow, console=CONSOLE_ADDR), r=r)
        r.sh([EDGE_BIN, "-t", "-q"])
        r.sh(["systemctl", "reload", EDGE_SVC])
    elif os.path.exists(site):
        os.remove(site)
        r.log("removed %s" % site)
        if run(["systemctl", "is-active", "--quiet", EDGE_SVC])[0] == 0:
            r.sh(["systemctl", "reload", EDGE_SVC])
    if mode == "tunnel":
        r.redact.append(c["access"]["tunnelToken"])
        apt_key_repo(r, "cloudflared", "https://pkg.cloudflare.com/cloudflare-main.gpg",
                     "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main",
                     "/usr/share/keyrings/cloudflare-main.gpg")
        apt_install(r, ["cloudflared"])
        if run(["systemctl", "is-enabled", "--quiet", "cloudflared"])[0] != 0:
            r.sh(["cloudflared", "service", "install", c["access"]["tunnelToken"]])
        r.log("tunnel installed: in Cloudflare Zero Trust, point the tunnel's public hostname at http://%s and protect it with an Access policy" % CONSOLE_ADDR)
    kv = read_kv(envp)
    kv.update({"COWSEC_LISTEN": CONSOLE_ADDR, "COWSEC_TRUSTED_PROXIES": "127.0.0.1/32,::1/128", "COWSEC_ACCESS_MODE": mode})
    write(envp, "# CowSec settings (managed by cowsec-setup)\n" + "".join('%s="%s"\n' % (k, v) for k, v in kv.items()), 0o600, r=r)


def step_finish(c, r, ctx):
    r.sh(["systemctl", "enable", "--now", "crowdsec-hubupdate.timer"], check=False)
    rc, out = r.sh(["crowdsec", "-c", CS_DIR + "/config.yaml", "-t"], check=False)
    if rc != 0:
        raise StepError("CrowdSec configuration test failed")
    restart_crowdsec(r)
    time.sleep(5)
    for svc in ("crowdsec", "crowdsec-firewall-bouncer") + ((EDGE_SVC,) if c["components"]["edge"] else ()):
        rc, _ = run(["systemctl", "is-active", "--quiet", svc])
        r.log("%s: %s" % (svc, "running" if rc == 0 else "NOT RUNNING"))
        if rc != 0:
            raise StepError("%s is not running" % svc)
    r.sh(["cscli", "lapi", "status"], check=False)
    write(STATE_DIR + "/setup.json", json.dumps(public_config(c), indent=2) + "\n", 0o600, r=r)


STEPS = [
    ("snapshot", "Save mailcow's settings, CrowdSec and the firewall rules first", lambda c: c["mailcow"]["mode"] == "existing", step_snapshot),
    ("docker", "Install Docker from its official repository", lambda c: c["mailcow"]["mode"] == "install" and docker_major() < 24, step_docker),
    ("mailcow-install", "Install mailcow-dockerized (mailcow's own installer)", lambda c: c["mailcow"]["mode"] == "install", step_mailcow_install),
    ("adopt", "Take over the existing setup (originals kept)", lambda c: bool(detect_existing()), step_adopt),
    ("crowdsec", "Install CrowdSec and the mail, web and SSH collections", lambda c: True, step_crowdsec),
    ("detection", "Read mailcow's logs and never ban the local network", lambda c: True, step_detection),
    ("firewall", "Firewall bouncer (host services and Docker-published mail ports)", lambda c: True, step_firewall),
    ("certs", "Certificates via DNS-01 (lego)", lambda c: c["certs"]["mode"] == "dns01", step_certs),
    ("edge", "Web edge with the CrowdSec bouncer and AppSec WAF", lambda c: c["components"]["edge"], step_edge),
    ("realip", "Cloudflare real visitor IPs", lambda c: c["components"]["edge"] and c["components"]["cloudflareRealIP"], step_cloudflare_realip),
    ("chrony", "Accurate clock (chrony)", lambda c: c["components"]["chronyPtp"], step_chrony),
    ("policy", "Ban policy: home countries, abroad login rule, escalating bans", lambda c: c["components"]["banPolicy"], step_ban_policy),
    ("mailcow-api", "mailcow management API for the console", lambda c: c["components"].get("mailcowApi", True), step_mailcow_api),
    ("access", "Console access", lambda c: True, step_access),
    ("finish", "Test configuration and start everything", lambda c: True, step_finish),
]


def plan(c):
    return [{"id": sid, "title": title} for sid, title, enabled, _ in STEPS if enabled(c)]


def install(c, r, progress=None):
    """Runs the enabled steps in order. progress(step_id, state) is called around each step."""
    ctx = {"mailcow": mailcow_info(), "ipv6": ipv6_enabled()}
    if c["mailcow"]["mode"] == "install" and ctx["mailcow"]["found"]:
        raise StepError("mailcow is already installed; choose 'Protect my existing mailcow'")
    if c["mailcow"]["mode"] == "existing" and not ctx["mailcow"]["found"]:
        raise StepError("mailcow not found")
    for sid, title, enabled, fn in STEPS:
        if not enabled(c):
            continue
        r.log("=== " + title)
        if progress:
            progress(sid, "running")
        try:
            fn(c, r, ctx)
        except Exception as e:
            r.log("FAILED: %s" % e)
            if ctx.get("rollback_mailcow_conf"):
                rollback_edge(c, r, ctx)
            if progress:
                progress(sid, "failed")
            raise
        if ctx.pop("reload_crowdsec", False) and sid != "finish":
            r.sh(["systemctl", "reload-or-restart", "crowdsec"], check=False)
        if progress:
            progress(sid, "ok")
    r.log("=== setup complete")


# ---------------------------------------------------------------- CowSec self-update

UPDATE_ENV = ETC_DIR + "/update.env"          # release source; the optional token never leaves this file
RELEASE_CACHE = os.path.join(STATE_DIR, "cowsec-release.json")
UPDATE_DIR = os.path.join(STATE_DIR, "updates")
DEFAULT_REPO = "OryxAstro/cowsec"


def update_source():
    env = read_kv(UPDATE_ENV) if os.path.exists(UPDATE_ENV) else {}
    repo = env.get("COWSEC_UPDATE_REPO") or DEFAULT_REPO
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        repo = DEFAULT_REPO
    return repo, env.get("COWSEC_UPDATE_TOKEN") or ""


def set_update_source(repo=None, token=None, clear_token=False):
    """Stores the release source root-only. The token is write-only: nothing ever returns it."""
    cur_repo, cur_token = update_source()
    repo = (repo or cur_repo).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise StepError("repository must look like owner/name")
    if clear_token:
        cur_token = ""
    elif token is not None:
        token = token.strip()
        if not re.fullmatch(r"[A-Za-z0-9_]{20,255}", token):
            raise StepError("that doesn't look like a GitHub token")
        cur_token = token
    body = "# CowSec release source (root only). The token only needs read access to releases.\n"
    body += 'COWSEC_UPDATE_REPO="%s"\n' % repo
    if cur_token:
        body += 'COWSEC_UPDATE_TOKEN="%s"\n' % cur_token
    write(UPDATE_ENV, body, 0o600)
    if os.path.exists(RELEASE_CACHE):
        os.remove(RELEASE_CACHE)
    return {"repo": repo, "tokenSet": bool(cur_token)}


def _gh(url, accept="application/vnd.github+json", dest=None):
    """GitHub request with the token in a header only (never a command line or a log)."""
    import ssl
    repo, token = update_source()
    req = urllib.request.Request(url, headers={"Accept": accept, "User-Agent": "cowsec-updater", "X-GitHub-Api-Version": "2022-11-28"})
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=60) as resp:
            if dest:
                with open(dest, "wb") as f:
                    shutil.copyfileobj(resp, f)
                return None
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise StepError("GitHub refused the request (%d): check the token" % e.code)
        if e.code == 404:
            raise StepError("no releases found for %s%s" % (repo, "" if token else " (a private repository needs a read-only token)"))
        raise StepError("GitHub returned %d" % e.code)
    except urllib.error.URLError as e:
        raise StepError("could not reach GitHub: %s" % e.reason)


def installed_version():
    rc, out = run(["dpkg-query", "-W", "-f=${Version}", "cowsec"])
    return out.strip() if rc == 0 else None


def newer(a, b):
    """True when Debian version a sorts after b."""
    return bool(a and b) and run(["dpkg", "--compare-versions", a, "gt", b])[0] == 0


def cowsec_release_status(force=False):
    repo, token = update_source()
    if not force and os.path.exists(RELEASE_CACHE) and time.time() - os.path.getmtime(RELEASE_CACHE) < 3600:
        try:
            st = json.load(open(RELEASE_CACHE))
            st["installed"] = installed_version()
            st["updateAvailable"] = newer((st.get("latest") or {}).get("version"), st["installed"])
            return st
        except Exception:
            pass
    st = {"repo": repo, "tokenSet": bool(token), "installed": installed_version(), "checked": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "latest": None, "error": None}
    try:
        rel = _gh("https://api.github.com/repos/%s/releases/latest" % repo)
        deb = next((a for a in rel.get("assets", []) if re.fullmatch(r"cowsec_[A-Za-z0-9.+~-]+_amd64\.deb", a.get("name", ""))), None)
        sums = next((a for a in rel.get("assets", []) if a.get("name") == "SHA256SUMS"), None)
        if not deb or not sums:
            raise StepError("the latest release has no package and checksum file")
        st["latest"] = {"tag": rel.get("tag_name"), "name": rel.get("name") or rel.get("tag_name"), "published": rel.get("published_at"),
                        "notes": (rel.get("body") or "")[:4000], "url": rel.get("html_url"),
                        "version": deb["name"][len("cowsec_"):-len("_amd64.deb")], "deb": {"name": deb["name"], "api": deb["url"], "size": deb.get("size")},
                        "sums": {"api": sums["url"]}}
    except StepError as e:
        st["error"] = str(e)
    st["updateAvailable"] = newer((st.get("latest") or {}).get("version"), st["installed"])
    write(RELEASE_CACHE, json.dumps(st) + "\n", 0o600)
    return st


def cowsec_self_update(r, progress):
    """Downloads the latest release, checks its SHA-256 against the release's SHA256SUMS,
    installs it with apt (the console restarts), then waits for the console to answer."""
    steps = [("check", "Find the latest release"), ("download", "Download the package"), ("verify", "Verify its checksum"),
             ("install", "Install it (the console restarts)"), ("health", "Wait for the console")]
    progress(None, "plan", [{"id": s, "title": t} for s, t in steps])
    repo, token = update_source()
    if token:
        r.redact.append(token)
    os.makedirs(UPDATE_DIR, mode=0o700, exist_ok=True)
    st, deb = None, None
    for sid, title in steps:
        progress(sid, "running")
        r.log("=== " + title)
        if sid == "check":
            st = cowsec_release_status(force=True)
            if st.get("error"):
                raise StepError(st["error"])
            if not st["updateAvailable"]:
                raise StepError("already on the latest version (%s)" % st["installed"])
            r.log("installed %s, latest %s (%s)" % (st["installed"], st["latest"]["version"], st["latest"]["tag"]))
        elif sid == "download":
            deb = os.path.join(UPDATE_DIR, st["latest"]["deb"]["name"])
            _gh(st["latest"]["deb"]["api"], "application/octet-stream", deb)
            _gh(st["latest"]["sums"]["api"], "application/octet-stream", os.path.join(UPDATE_DIR, "SHA256SUMS"))
            r.log("downloaded %s (%d bytes)" % (os.path.basename(deb), os.path.getsize(deb)))
        elif sid == "verify":
            want = None
            for line in open(os.path.join(UPDATE_DIR, "SHA256SUMS")):
                parts = line.split()
                if len(parts) == 2 and parts[1].lstrip("*") == os.path.basename(deb):
                    want = parts[0].lower()
            h = hashlib.sha256()
            with open(deb, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            if not want or h.hexdigest() != want:
                os.remove(deb)
                raise StepError("checksum mismatch: the download was removed and nothing was installed")
            r.log("SHA-256 matches the release's SHA256SUMS")
        elif sid == "install":
            wait_for_apt(r)
            r.sh(["apt-get", "install", "-y", "-q", "-o", "Dpkg::Options::=--force-confold", deb], timeout=900)
        elif sid == "health":
            for _ in range(30):
                if run(["systemctl", "is-active", "--quiet", "cowsec"])[0] == 0:
                    break
                time.sleep(2)
            else:
                raise StepError("the console did not start (journalctl -u cowsec)")
            r.log("CowSec %s is running" % installed_version())
            for f in os.listdir(UPDATE_DIR):
                os.remove(os.path.join(UPDATE_DIR, f))
        progress(sid, "ok")


# ---------------------------------------------------------------- mailcow netfilter <-> CrowdSec

NETFILTER_STATE = os.path.join(STATE_DIR, "netfilter.json")
NETFILTER_REASON = "mailcow netfilter"   # marks decisions CowSec imported from netfilter
NETFILTER_PERM = "8760h"                 # permanent bans: re-asserted every minute anyway
F2B_FIELDS = ("ban_time", "max_ban_time", "ban_time_increment", "max_attempts", "retry_window",
              "netban_ipv4", "netban_ipv6", "whitelist", "blacklist", "manage_external")


def mailcow_api(method, path, body=None):
    """mailcow's API on localhost with the key from /etc/cowsec/mailcow.env."""
    import ssl
    env = read_kv(ETC_DIR + "/mailcow.env")
    key = env.get("COWSEC_MAILCOW_API_KEY")
    if not key:
        raise StepError("mailcow management isn't set up (sudo cowsec-setup mailcow-api)")
    req = urllib.request.Request(env.get("COWSEC_MAILCOW_URL", "https://127.0.0.1:8443").rstrip("/") + "/api/v1/" + path,
                                 data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"X-API-Key": key, "Content-Type": "application/json", "Accept": "application/json"})
    if env.get("COWSEC_MAILCOW_HOST"):
        req.add_header("Host", env["COWSEC_MAILCOW_HOST"])
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # localhost only
    # mailcow's web server answers 502/503/504 (or refuses) for a few seconds while it restarts
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            if e.code not in (502, 503, 504) or attempt == 4:
                raise
        except urllib.error.URLError:
            if attempt == 4:
                raise
        time.sleep(3 * (attempt + 1))


def netfilter_state():
    try:
        st = json.load(open(NETFILTER_STATE))
    except Exception:
        st = {}
    return {"mode": st.get("mode", "side-by-side"), "syncTrusted": st.get("syncTrusted", True), "lastSync": st.get("lastSync"),
            "imported": st.get("imported", 0), "lastError": st.get("lastError")}


def f2b_settings(cur):
    """The full settings object: mailcow resets anything an edit leaves out."""
    out = {k: cur.get(k) for k in F2B_FIELDS}
    out["ban_time_increment"] = "1" if cur.get("ban_time_increment") in (True, 1, "1") else "0"
    out["manage_external"] = 1 if cur.get("manage_external") in (True, 1, "1") else 0
    for k in ("whitelist", "blacklist"):
        out[k] = cur.get(k) or ""
    return out


def trusted_networks():
    """CowSec's allowlist plus the LAN ranges the install never bans."""
    nets = []
    try:
        cfg = json.load(open(os.path.join(STATE_DIR, "setup.json")))
        nets += cfg.get("lanRanges") or []
    except Exception:
        nets += PRIVATE_RANGES
    rc, out = run(["cscli", "allowlists", "inspect", "cowsec", "-o", "json"])
    if rc == 0:
        try:
            for it in (json.loads(out).get("items") or []):
                v = it.get("value")
                if v:
                    nets.append(v if "/" in v else (v + ("/128" if ":" in v else "/32")))
        except ValueError:
            pass
    clean = []
    for n in nets:
        try:
            clean.append(str(ipaddress.ip_network(n, strict=False)))
        except ValueError:
            pass
    return sorted(set(clean))


def remaining_seconds(text):
    m = re.match(r"\s*(-?\d+)h\s+(-?\d+)m\s+(-?\d+)s", text or "")
    return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3)) if m else 0


def netfilter_sync(r=None):
    """Runs every minute from cowsec-netfilter.timer (and right after a mode change):
    keeps netfilter's whitelist in line with CowSec's trusted networks and, in
    'crowdsec' mode, mirrors netfilter's bans into CrowdSec decisions."""
    st = netfilter_state()
    try:
        cur = mailcow_api("GET", "get/fail2ban")
        want_external = 1 if st["mode"] == "crowdsec" else 0
        settings = f2b_settings(cur)
        changed = settings["manage_external"] != want_external
        settings["manage_external"] = want_external
        if st["syncTrusted"]:
            have = [x for x in re.split(r"[\s,;]+", settings["whitelist"]) if x]
            merged = sorted(set(have) | set(trusted_networks()))
            if merged != sorted(set(have)):
                settings["whitelist"] = "\n".join(merged)
                changed = True
        if changed:
            mailcow_api("POST", "edit/fail2ban", {"items": ["none"], "attr": settings})
        imported = 0
        if st["mode"] == "crowdsec":
            rc, out = run(["cscli", "decisions", "list", "-o", "json", "--limit", "0"])
            have = {}
            for alert in (json.loads(out) if rc == 0 and out.strip() not in ("", "null") else []) or []:
                for d in alert.get("decisions") or []:
                    if d.get("scenario") == NETFILTER_REASON:
                        have[d["value"]] = d
            want = {}
            for b in cur.get("active_bans") or []:
                if isinstance(b, dict) and b.get("network") and not b.get("queued_for_unban"):
                    secs = remaining_seconds(b.get("banned_until"))
                    if secs > 30:
                        want[b["network"]] = "%ds" % secs
            # the same set mailcow publishes for external firewalls: its blacklist plus active bans
            perm = [b["network"] for b in (cur.get("perm_bans") or []) if isinstance(b, dict) and b.get("network")]
            for x in perm + [x for x in re.split(r"[\s,;]+", cur.get("blacklist") or "") if x]:
                try:
                    want[str(ipaddress.ip_network(x, strict=False))] = NETFILTER_PERM
                except ValueError:
                    pass
            for net, dur in want.items():
                key = net[:-3] if net.endswith("/32") else net
                if key not in have and net not in have:
                    rng = ["--ip", key] if "/" not in key else ["--range", net]
                    run(["cscli", "decisions", "add"] + rng + ["--duration", dur, "--reason", NETFILTER_REASON, "--type", "ban"])
                    imported += 1
            for val in have:
                if val not in want and val + "/32" not in want:
                    run(["cscli", "decisions", "delete", "--ip" if "/" not in val else "--range", val])
        st.update(lastSync=time.strftime("%Y-%m-%dT%H:%M:%S%z"), imported=st.get("imported", 0) + imported, lastError=None)
    except Exception as e:
        st.update(lastError=str(e)[:300])
        if r:
            r.log("netfilter sync: %s" % e)
    write(NETFILTER_STATE, json.dumps(st) + "\n", 0o600)
    return st


def netfilter_coordinate(mode, sync_trusted, r):
    if mode not in ("side-by-side", "crowdsec") or not isinstance(sync_trusted, bool):
        raise StepError("mode must be side-by-side or crowdsec")
    st = netfilter_state()
    st.update(mode=mode, syncTrusted=sync_trusted)
    write(NETFILTER_STATE, json.dumps(st) + "\n", 0o600)
    write("/etc/systemd/system/cowsec-netfilter.service",
          "[Unit]\nDescription=Coordinate mailcow netfilter with CrowdSec (CowSec)\nAfter=crowdsec.service docker.service\n\n"
          "[Service]\nType=oneshot\nEnvironment=SSH_ORIGINAL_COMMAND=netfilter-sync\nEnvironment=SSH_CLIENT=timer\nExecStart=%s\n" % HOSTCTL, r=r)
    write("/etc/systemd/system/cowsec-netfilter.timer",
          "[Unit]\nDescription=Coordinate mailcow netfilter with CrowdSec every minute (CowSec)\n\n"
          "[Timer]\nOnBootSec=2min\nOnUnitActiveSec=1min\nAccuracySec=10s\n\n[Install]\nWantedBy=timers.target\n", r=r)
    r.sh(["systemctl", "daemon-reload"])
    if mode == "crowdsec" or sync_trusted:
        r.sh(["systemctl", "enable", "--now", "cowsec-netfilter.timer"])
    else:
        r.sh(["systemctl", "disable", "--now", "cowsec-netfilter.timer"], check=False)
    if mode == "side-by-side":
        # hand enforcement back to netfilter and drop what CowSec imported
        rc, out = run(["cscli", "decisions", "list", "-o", "json", "--limit", "0"])
        for alert in (json.loads(out) if rc == 0 and out.strip() not in ("", "null") else []) or []:
            for d in alert.get("decisions") or []:
                if d.get("scenario") == NETFILTER_REASON:
                    run(["cscli", "decisions", "delete", "--id", str(d["id"])])
    return netfilter_sync(r)


def mailcow_da_acl():
    """Domain-admin permissions straight from mailcow's database (the API doesn't return them)."""
    mc = find_mailcow()
    if not mc:
        return {"keys": [], "acls": {}}
    conf = read_kv(os.path.join(mc, "mailcow.conf"))
    def q(sql):
        rc, out = compose(mc, ["exec", "-T", "-e", "MYSQL_PWD=" + conf.get("DBPASS", ""), "mysql-mailcow", "mysql", "-u" + conf.get("DBUSER", "mailcow"),
                               conf.get("DBNAME", "mailcow"), "-B", "-N", "-e", sql])
        if rc != 0:
            raise StepError("could not read domain-admin permissions")
        return [l.split("\t") for l in out.splitlines() if l.strip()]
    head = [c[0] for c in q("SHOW COLUMNS FROM da_acl")]  # an empty table prints no header
    keys = [k for k in head if k != "username"]
    lines = [head] + q("SELECT * FROM da_acl")
    acls = {row[head.index("username")]: {k: row[head.index(k)] == "1" for k in keys} for row in lines[1:] if len(row) == len(head)}
    return {"keys": keys, "acls": acls}


def mailcow_footer(domain):
    """A domain's footer from mailcow's database: the API can set it but not read it."""
    if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", domain):
        raise StepError("invalid domain")
    mc = find_mailcow()
    if not mc:
        raise StepError("mailcow not found")
    conf = read_kv(os.path.join(mc, "mailcow.conf"))
    sql = ("SELECT JSON_OBJECT('html', html, 'plain', plain, 'mbox_exclude', mbox_exclude, 'alias_domain_exclude', alias_domain_exclude, "
           "'skip_replies', skip_replies) FROM domain_wide_footer WHERE domain = '%s'" % domain)
    rc, out = compose(mc, ["exec", "-T", "-e", "MYSQL_PWD=" + conf.get("DBPASS", ""), "mysql-mailcow", "mysql", "-u" + conf.get("DBUSER", "mailcow"),
                           conf.get("DBNAME", "mailcow"), "-B", "-N", "-r", "-e", sql])
    if rc != 0:
        raise StepError("could not read the footer")
    row = json.loads(out.strip() or "{}")
    def as_list(v):
        try:
            v = json.loads(v) if isinstance(v, str) else v
        except ValueError:
            v = []
        return v if isinstance(v, list) else []
    return {"html": row.get("html") or "", "plain": row.get("plain") or "", "skip_replies": str(row.get("skip_replies") or "0") == "1",
            "exclude": as_list(row.get("mbox_exclude")) + as_list(row.get("alias_domain_exclude"))}


def mailcow_mta_sts(domain):
    """A domain's MTA-STS policy from mailcow's database (the API can set it but not read it)."""
    if not re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", domain):
        raise StepError("invalid domain")
    mc = find_mailcow()
    if not mc:
        raise StepError("mailcow not found")
    conf = read_kv(os.path.join(mc, "mailcow.conf"))
    sql = ("SELECT JSON_OBJECT('id', id, 'version', version, 'mode', mode, 'mx', mx, 'max_age', max_age, 'active', active) "
           "FROM mta_sts WHERE domain = '%s'" % domain)
    rc, out = compose(mc, ["exec", "-T", "-e", "MYSQL_PWD=" + conf.get("DBPASS", ""), "mysql-mailcow", "mysql", "-u" + conf.get("DBUSER", "mailcow"),
                           conf.get("DBNAME", "mailcow"), "-B", "-N", "-r", "-e", sql])
    if rc != 0:
        raise StepError("could not read the MTA-STS policy")
    row = json.loads(out.strip() or "{}")
    if not row:
        return {"exists": False, "active": False}
    return {"exists": True, "active": str(row.get("active")) == "1", "id": str(row.get("id") or ""), "version": row.get("version") or "STSv1",
            "mode": row.get("mode") or "testing", "max_age": int(row.get("max_age") or 86400), "mx": [m for m in str(row.get("mx") or "").split(",") if m]}


# ---------------------------------------------------------------- mailcow updates

MAILCOW_UPDATE_CACHE = os.path.join(STATE_DIR, "mailcow-update.json")
MAILCOW_UPDATE_OPTIONS = os.path.join(STATE_DIR, "mailcow-update.options.json")
DEFAULT_BACKUP_DIR = "/var/backups/cowsec/mailcow"  # parent is root-only (0700)
# Directories the folder picker never offers (pseudo filesystems and the OS itself).
FS_DENY = ("/proc", "/sys", "/dev", "/run", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc", "/snap")


def mailcow_version(mc_dir):
    rc, tag = run(["git", "-C", mc_dir, "describe", "--tags", "--abbrev=0"])
    rc2, branch = run(["git", "-C", mc_dir, "rev-parse", "--abbrev-ref", "HEAD"])
    rc3, commit = run(["git", "-C", mc_dir, "rev-parse", "--short", "HEAD"])
    rc4, date = run(["git", "-C", mc_dir, "log", "-1", "--format=%cs"])
    return {"tag": tag if rc == 0 else None, "branch": branch if rc2 == 0 else None,
            "commit": commit if rc3 == 0 else None, "date": date if rc4 == 0 else None}


def mailcow_update_status():
    mc = find_mailcow()
    if not mc:
        return {"found": False}
    cache = {}
    if os.path.exists(MAILCOW_UPDATE_CACHE):
        try:
            cache = json.load(open(MAILCOW_UPDATE_CACHE))
        except Exception:
            cache = {}
    opts = {"backup": True, "path": DEFAULT_BACKUP_DIR, "keepDays": 14}
    if os.path.exists(MAILCOW_UPDATE_OPTIONS):
        try:
            opts.update(json.load(open(MAILCOW_UPDATE_OPTIONS)))
        except Exception:
            pass
    return {"found": True, "dir": mc, "version": mailcow_version(mc), "check": cache, "options": opts,
            "defaultBackupDir": DEFAULT_BACKUP_DIR}


def mailcow_check(r):
    """./update.sh --check: exit 0 = update available, 3 = up to date."""
    mc = find_mailcow()
    rc, out = r.sh(["./update.sh", "--check"], cwd=mc, check=False, timeout=300)
    state = {0: "available", 3: "current"}.get(rc, "error")
    res = {"state": state, "checked": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "detail": out.splitlines()[-1][:300] if out else ""}
    write(MAILCOW_UPDATE_CACHE, json.dumps(res) + "\n", 0o600)
    if state == "error":
        raise StepError("update check failed (exit %d)" % rc)
    r.log("mailcow update %s" % ("available" if state == "available" else "not needed: already current"))
    return res


def safe_dir(path, must_exist=True):
    """Validates a directory for backups: absolute, resolved, outside system directories."""
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path or len(path) > 4096:
        raise StepError("choose an absolute path")
    real = os.path.realpath(path)
    if real == "/" or any(real == d or real.startswith(d + "/") for d in FS_DENY):
        raise StepError("%s is a system directory; choose another location" % real)
    mc = find_mailcow()
    if mc and (real == os.path.realpath(mc) or real.startswith(os.path.realpath(mc) + "/")):
        raise StepError("don't keep backups inside the mailcow directory")
    if must_exist and not os.path.isdir(real):
        raise StepError("%s is not a directory" % real)
    return real


def fs_list(path):
    """Lists sub-directories for the folder picker (a path that doesn't exist yet shows its
    nearest existing parent)."""
    real = os.path.realpath(path or "/")
    while not os.path.isdir(real) and real != "/":
        real = os.path.dirname(real)
    entries = []
    try:
        names = sorted(os.listdir(real), key=str.lower)
    except PermissionError:
        names = []
    for n in names:
        p = os.path.join(real, n)
        if not os.path.isdir(p) or os.path.islink(p):
            continue
        denied = p in FS_DENY or any(p.startswith(d + "/") for d in FS_DENY)
        entries.append({"name": n, "path": p, "selectable": not denied, "hidden": n.startswith(".")})
    st = os.statvfs(real)
    parts, acc = [], ""
    for seg in [s for s in real.split("/") if s]:
        acc += "/" + seg
        parts.append({"name": seg, "path": acc})
    try:
        safe_dir(real)
        selectable = True
    except StepError:
        selectable = False
    return {"path": real, "parent": os.path.dirname(real) if real != "/" else None, "crumbs": parts, "dirs": entries,
            "selectable": selectable, "freeBytes": st.f_bavail * st.f_frsize, "totalBytes": st.f_blocks * st.f_frsize}


def fs_mkdir(path):
    path = path.rstrip("/")
    parent, name = os.path.dirname(path) or "/", os.path.basename(path)
    if not os.path.isdir(os.path.realpath(parent)):
        raise StepError("%s does not exist" % parent)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name) or name in (".", ".."):
        raise StepError("folder names may use letters, digits, . _ and -")
    target = safe_dir(os.path.join(os.path.realpath(parent), name), must_exist=False)
    os.makedirs(target, mode=0o700, exist_ok=True)
    return fs_list(target)


def validate_update_options(o):
    if not isinstance(o, dict):
        raise StepError("bad options")
    out = {"backup": bool(o.get("backup", True)), "path": DEFAULT_BACKUP_DIR, "keepDays": 14}
    if out["backup"]:
        out["path"] = safe_dir(str(o.get("path") or DEFAULT_BACKUP_DIR), must_exist=False)
    kd = o.get("keepDays", 14)
    if not isinstance(kd, int) or not 0 <= kd <= 3650:
        raise StepError("keep backups for 0-3650 days")
    out["keepDays"] = kd
    return out


def crowdsec_upgrade(r, progress):
    """Staged CrowdSec + bouncer upgrade with a config backup and tests before restarts."""
    steps = [("backup", "Back up /etc/crowdsec"), ("refresh", "Check package versions"), ("upgrade", "Upgrade CrowdSec and bouncers"),
             ("test", "Test the configuration"), ("restart", "Restart the engine and bouncers"), ("verify", "Verify everything is protecting")]
    progress(None, "plan", [{"id": s, "title": t} for s, t in steps])
    pkgs = [p for p in ("crowdsec",) + FW_PKGS + ("crowdsec-openresty-bouncer", "crowdsec-nginx-bouncer")
            if run(["dpkg-query", "-W", "-f=${Status}", p])[1] == "install ok installed"]
    for sid, title in steps:
        progress(sid, "running")
        r.log("=== " + title)
        if sid == "backup":
            dst = "/root/crowdsec-backup-%s.tgz" % time.strftime("%Y%m%d%H%M%S")
            r.sh(["tar", "-czf", dst, "/etc/crowdsec"])
            progress(sid, "running", backup=dst)
        elif sid == "refresh":
            r.sh(["apt-get", "update", "-q"])
        elif sid == "upgrade":
            r.sh(["apt-get", "install", "-y", "-q", "--only-upgrade", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef"] + pkgs, timeout=1800)
        elif sid == "test":
            r.sh(["crowdsec", "-c", CS_DIR + "/config.yaml", "-t"])
            if run(["systemctl", "is-active", "--quiet", EDGE_SVC])[0] == 0:
                r.sh([EDGE_BIN, "-t", "-q"])
        elif sid == "restart":
            restart_crowdsec(r)
            time.sleep(5)
            r.sh(["systemctl", "restart", "crowdsec-firewall-bouncer"])
            if run(["systemctl", "is-active", "--quiet", EDGE_SVC])[0] == 0:
                r.sh(["systemctl", "reload", EDGE_SVC])
        elif sid == "verify":
            time.sleep(3)
            checks = []
            edge = os.path.exists("/lib/systemd/system/openresty.service") if EDGE_KIND == "openresty" else edge_installed()
            for svc in ["crowdsec", "crowdsec-firewall-bouncer"] + ([EDGE_SVC] if edge else []):
                ok = run(["systemctl", "is-active", "--quiet", svc])[0] == 0
                checks.append({"name": svc + " running", "ok": ok, "detail": ""})
            rc, out = run(["cscli", "lapi", "status"])
            checks.append({"name": "Local API answers", "ok": rc == 0, "detail": ""})
            ok, how = firewall_covers_docker()
            checks.append({"name": "Firewall covers mail ports", "ok": ok, "detail": how})
            progress(sid, "running", checks=checks)
            if not all(c["ok"] for c in checks):
                raise StepError("some checks failed: " + ", ".join(c["name"] for c in checks if not c["ok"]))
        progress(sid, "ok")
    r.log("=== CrowdSec upgraded")


def mailcow_containers():
    """Container states straight from Docker (works while mailcow's API is down mid-update)."""
    info = mailcow_info()
    out = []
    for svc, c in sorted((info.get("containers") or {}).items()):
        st = c["status"]
        out.append({"service": svc, "name": c["name"], "up": st.startswith("Up"), "healthy": "unhealthy" not in st,
                    "starting": "starting" in st, "status": st})
    return {"containers": out, "total": len(out), "up": sum(1 for c in out if c["up"])}


def mailcow_post_checks(r, ctx_certs=True):
    """Verifies everything CowSec set up still works after mailcow changed under it."""
    mc = mailcow_info()
    conf = read_kv(os.path.join(mc["dir"], "mailcow.conf"))
    results = []

    def check(name, ok, detail=""):
        results.append({"name": name, "ok": bool(ok), "detail": detail})
        r.log(("✔ " if ok else "✘ ") + name + (": " + detail if detail else ""))

    # containers
    for _ in range(60):
        c = mailcow_containers()
        if c["total"] and c["up"] == c["total"] and not any(x["starting"] for x in c["containers"]):
            break
        time.sleep(10)
    check("All mailcow containers running", c["up"] == c["total"], "%d/%d up" % (c["up"], c["total"]))
    # web server behind the edge
    port = conf.get("HTTPS_PORT", "443")
    rc, code = run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-m", "15", "https://127.0.0.1:%s/" % port])
    check("mailcow web answers on 127.0.0.1:%s" % port, code in ("200", "301", "302"), "HTTP %s" % code)
    if run(["systemctl", "is-active", "--quiet", EDGE_SVC])[0] == 0 and edge_installed():
        rc, code = run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "-m", "15", "-H", "Host: " + conf.get("MAILCOW_HOSTNAME", ""), "https://127.0.0.1/"])
        check("Edge reaches mailcow", code in ("200", "301", "302"), "HTTP %s" % code)
    # firewall
    ok, how = firewall_covers_docker()
    if not ok:
        r.sh(["systemctl", "restart", "crowdsec-firewall-bouncer"], check=False)
        time.sleep(5)
        ok, how = firewall_covers_docker()
    check("Firewall bouncer covers mail ports", ok, how)
    # log acquisition
    acq = CS_DIR + "/acquis.d/cowsec-mailcow.yaml"
    names = {x["name"] for x in mc.get("containers", {}).values()}
    if os.path.exists(acq):
        wanted = re.findall(r"^\s+-\s+(\S+-mailcow-\S+)$", open(acq).read(), re.M)
        missing = [w for w in wanted if w not in names]
        if missing:
            c0 = {"components": {"edge": run(["systemctl", "is-active", "--quiet", EDGE_SVC])[0] == 0 and edge_installed()}}
            write(acq, mailcow_acquis(c0, mc), r=r)
            r.sh(["systemctl", "reload", "crowdsec"], check=False)
        check("CrowdSec reads postfix and dovecot", True, "container names %s" % ("updated" if missing else "unchanged"))
    # per-domain certificates
    if ctx_certs and os.path.exists(ETC_DIR + "/certs.json"):
        extra = os.path.join(mc["dir"], "data/conf/postfix/extra.cf")
        ok = os.path.exists(extra) and "cowsec-sni" in open(extra).read()
        skip = conf.get("SKIP_LETS_ENCRYPT", "n").lower() in ("y", "yes")
        check("DNS-01 certificates still in place", ok and skip, "SNI map %s, SKIP_LETS_ENCRYPT=%s" % ("present" if ok else "missing", conf.get("SKIP_LETS_ENCRYPT")))
    return results


def prepare_backup_dir(path, r):
    """mailcow's backup script requires the folder to be readable and traversable by others
    (its containers write into it). Keep the backups private by putting that folder inside a
    root-only parent: the default /var/backups/cowsec is created 0700."""
    if path == DEFAULT_BACKUP_DIR:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        os.chmod(os.path.dirname(path), 0o700)
    os.makedirs(path, exist_ok=True)
    mode = os.stat(path).st_mode & 0o777
    if mode & 0o005 != 0o005:
        os.chmod(path, mode | 0o005)
        r.log("made %s traversable for mailcow's backup containers (mode %o)" % (path, mode | 0o005))
    parent_private = any((os.stat(p).st_mode & 0o001) == 0 for p in _parents(path))
    if not parent_private:
        r.log("note: backups in %s are readable by local users; prefer a folder inside a root-only (0700) parent" % path)


def _parents(path):
    p = os.path.dirname(path)
    while p and p != "/":
        yield p
        p = os.path.dirname(p)


def mailcow_update(r, progress, opts):
    """Staged mailcow update: optional backup, prefetch, update.sh --force, health checks."""
    mc = find_mailcow()
    steps = []
    if opts.get("backup"):
        steps.append(("backup", "Back up mail, config and database"))
    steps += [("prefetch", "Download new images"), ("update", "Run mailcow's update.sh"), ("health", "Wait for the herd to come back"), ("checks", "Check CowSec's protections")]
    progress(None, "plan", [{"id": s, "title": t} for s, t in steps])
    for sid, title in steps:
        progress(sid, "running")
        r.log("=== " + title)
        if sid == "backup":
            path = safe_dir(opts["path"], must_exist=False)
            prepare_backup_dir(path, r)
            env = {"MAILCOW_BACKUP_LOCATION": path, "THREADS": str(max(1, (os.cpu_count() or 2) // 2))}
            args = ["./helper-scripts/backup_and_restore.sh", "backup", "all"]
            if int(opts.get("keepDays") or 0) > 0:
                args += ["--delete-days", str(int(opts["keepDays"]))]
            r.sh(args, cwd=mc, env=env, timeout=6 * 3600)
        elif sid == "prefetch":
            r.sh(["./update.sh", "--prefetch", "--skip-ping-check"], cwd=mc, timeout=3600)
        elif sid == "update":
            r.sh(["./update.sh", "--force", "--skip-ping-check"], cwd=mc, timeout=3600)
        elif sid == "health":
            for _ in range(90):
                c = mailcow_containers()
                progress(sid, "running", containers=c)
                if c["total"] and c["up"] == c["total"] and not any(x["starting"] for x in c["containers"]):
                    break
                time.sleep(5)
            else:
                raise StepError("not all containers came back within 7 minutes")
        elif sid == "checks":
            res = mailcow_post_checks(r)
            progress(sid, "running", checks=res)
            if not all(x["ok"] for x in res):
                raise StepError("some checks failed: " + ", ".join(x["name"] for x in res if not x["ok"]))
        progress(sid, "ok")
    write(MAILCOW_UPDATE_CACHE, json.dumps({"state": "current", "checked": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "detail": "updated by CowSec"}) + "\n", 0o600)
    r.log("=== mailcow updated")


use_edge(edge_kind())
