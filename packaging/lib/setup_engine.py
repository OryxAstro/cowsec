"""CowSec setup engine: pre-flight checks and the install steps for CrowdSec, the
firewall bouncer, the OpenResty edge with AppSec, certificates and console access on a
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
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
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

# mailcow's web ports move here when the OpenResty edge takes over 80/443 (8080 is CrowdSec's LAPI).
EDGE_MAILCOW_HTTP = 8081
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
    os.makedirs(os.path.dirname(keyring), exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        key = os.path.join(td, "key")
        download(key_url, key)
        r.sh(["gpg", "--batch", "--yes", "--dearmor", "-o", keyring, key])
    os.chmod(keyring, 0o644)
    write(list_path, line + "\n", r=r)
    return True


POLICY_RC = "/usr/sbin/policy-rc.d"


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
    try:
        r.sh(["dpkg", "--configure", "-a"], check=False)  # finish any interrupted earlier attempt
        r.sh(["apt-get", "update", "-q"])
        r.sh(["apt-get", "install", "-y", "-q", "-o", "Dpkg::Options::=--force-confold"] + missing)
    finally:
        if own_policy and os.path.exists(POLICY_RC):
            os.remove(POLICY_RC)


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


# ---------------------------------------------------------------- pre-flight

def preflight():
    checks = []

    def add(cid, title, status, detail=""):
        checks.append({"id": cid, "title": title, "status": status, "detail": detail})

    add("root", "Running as root", "ok" if os.geteuid() == 0 else "fail", "" if os.geteuid() == 0 else "run with sudo")
    arch = os.uname().machine
    add("arch", "64-bit x86 (amd64)", "ok" if arch == "x86_64" else "fail", arch)
    osid, ver, code = os_release()
    supported = (osid == "debian" and ver in ("11", "12", "13")) or (osid == "ubuntu" and ver in ("22.04", "24.04"))
    add("os", "Supported OS (Debian 11-13, Ubuntu 22.04/24.04)", "ok" if supported else "warn", "%s %s (%s)" % (osid, ver, code))
    add("systemd", "systemd", "ok" if os.path.isdir("/run/systemd/system") else "fail")
    rc, out = run(["docker", "compose", "version", "--short"])
    add("docker", "Docker with Compose v2", "ok" if rc == 0 else "fail", out.splitlines()[0] if out else "not found")
    mc = mailcow_info()
    if not mc["found"]:
        add("mailcow", "mailcow-dockerized installation", "fail", "mailcow.conf not found (set MAILCOW_DIR if it lives elsewhere)")
    else:
        add("mailcow", "mailcow-dockerized installation", "ok", "%s · %s" % (mc["dir"], mc["hostname"]))
        need = ("postfix-mailcow", "dovecot-mailcow", "nginx-mailcow")
        down = [s for s in need if not mc["containers"].get(s, {}).get("status", "").startswith("Up")]
        add("mailcow-running", "mailcow containers running", "ok" if not down else "fail", "down: " + ", ".join(down) if down else "%d containers" % len(mc["containers"]))
        add("mailcow-domains", "mailcow domains", "ok" if mc["domains"] else "warn", ", ".join(mc["domains"][:8]) + (" …" if len(mc["domains"]) > 8 else "") or "none found")
    rc, out = run(["dpkg-query", "-W", "-f=${Version}", "crowdsec"])
    add("crowdsec", "CrowdSec", "ok", "installed " + out if rc == 0 and out else "will be installed")
    rc, out = run(["docker", "ps", "--format", "{{.Image}}"])
    if "crowdsecurity/crowdsec" in out:
        add("crowdsec-docker", "No CrowdSec container", "warn", "a CrowdSec container is running; two engines would double-ban. Remove it first.")
    rc, ss = run(["ss", "-ltnpH"])
    owners = {}
    for line in ss.splitlines():
        m = re.search(r"[:\]](80|443|8081|8443|8090|9443|7422|8080)\s.*users:\(\(\"([^\"]+)\"", line)
        if m:
            owners.setdefault(m.group(1), set()).add(m.group(2))
    web = set().union(*[owners.get(p, set()) for p in ("80", "443")])
    rc_ng, _ = run(["systemctl", "is-active", "--quiet", "nginx"])
    others = web - {"docker-proxy", "openresty"}
    if rc_ng == 0 or others:
        add("web-ports", "Web ports 80/443 available", "warn", "used by %s on the host; the edge needs 80/443" % ", ".join(sorted(others) or ["nginx"]))
    elif "openresty" in web:
        add("web-ports", "Web ports 80/443 available", "ok", "already served by the OpenResty edge")
    else:
        add("web-ports", "Web ports 80/443 available", "ok", "served by mailcow now; the edge takes them over and moves mailcow to localhost" if "docker-proxy" in web else "free")
    for port, what in (("8081", "mailcow HTTP (edge)"), ("8443", "mailcow HTTPS (edge)"), ("8090", "CowSec console")):
        o = owners.get(port, set()) - {"docker-proxy", "cowsec"}
        if o:
            add("port-" + port, "Port %s free (%s)" % (port, what), "warn", "in use by " + ", ".join(o))
    rc, out = run(["iptables", "-S", "DOCKER-USER"])
    add("docker-user", "iptables DOCKER-USER chain", "ok" if rc == 0 else "warn", "" if rc == 0 else "not found; bans will only cover host services")
    rc, out = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
    add("time", "Clock synchronised", "ok" if out.strip() == "yes" else "warn", "" if out.strip() == "yes" else "TOTP sign-in needs an accurate clock")
    ptp = os.path.exists("/dev/ptp0") or run(["modprobe", "-n", "ptp_kvm"])[0] == 0
    add("ptp", "KVM PTP clock (optional, Proxmox/KVM guests)", "ok" if ptp else "info", "available" if ptp else "not a KVM guest")
    st = os.statvfs("/var")
    free_gb = st.f_bavail * st.f_frsize / 1e9
    add("disk", "Free disk space in /var", "ok" if free_gb > 2 else "warn", "%.1f GB" % free_gb)
    for host in ("packagecloud.io", "openresty.org", "github.com"):
        try:
            socket.create_connection((host, 443), timeout=5).close()
            add("net-" + host, "Reach " + host, "ok")
        except OSError as e:
            add("net-" + host, "Reach " + host, "fail", str(e))
    return {"checks": checks, "mailcow": mc, "ok": not any(c["status"] == "fail" for c in checks), "ipv6": ipv6_enabled()}


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
    for k, default in (("edge", True), ("adminLanOnly", True), ("cloudflareRealIP", False), ("chronyPtp", False), ("banPolicy", True)):
        v = comp.get(k, default)
        if not isinstance(v, bool):
            raise StepError("components.%s must be true/false" % k)
        out["components"][k] = v
    ranges = c.get("lanRanges") or PRIVATE_RANGES
    try:
        out["lanRanges"] = [str(ipaddress.ip_network(x, strict=False)) for x in ranges]
    except ValueError as e:
        raise StepError("lanRanges: %s" % e)
    certs = c.get("certs") or {"mode": "mailcow"}
    if certs.get("mode") not in ("mailcow", "dns01"):
        raise StepError("certs.mode must be mailcow or dns01")
    if certs["mode"] == "dns01":
        if not out["components"]["edge"]:
            raise StepError("DNS-01 certificates are deployed through the OpenResty edge; enable it")
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
        out["certs"] = {"mode": "dns01", "provider": prov, "credentials": creds, "email": email, "domains": sorted(set(doms)),
                        "perDomain": bool(certs.get("perDomain", True)), "wildcard": bool(certs.get("wildcard", True)),
                        "staging": bool(certs.get("staging", False))}
    acc = c.get("access") or {"mode": "local"}
    mode = acc.get("mode")
    if mode not in ("local", "lan", "wan", "tunnel"):
        raise StepError("access.mode must be local, lan, wan or tunnel")
    out["access"] = {"mode": mode}
    if mode in ("lan", "wan"):
        if not out["components"]["edge"]:
            raise StepError("LAN and internet access are served by the OpenResty edge; enable it")
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


# ---------------------------------------------------------------- steps

def step_crowdsec(c, r, ctx):
    osid, ver, code = os_release()
    flavour = "ubuntu" if osid == "ubuntu" else "debian"
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
        docs.append("source: file\nfilenames:\n  - /var/log/openresty/access.log\n  - /var/log/openresty/error.log\nlabels:\n  type: nginx\n")
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
        txt = open(f).read()
        dup = [v["name"] for k, v in mc["containers"].items() if k in ("postfix-mailcow", "dovecot-mailcow", "nginx-mailcow") and v["name"] in txt]
        if dup:
            r.log("WARNING: %s already reads %s; remove those entries or every event is counted twice" % (f, ", ".join(dup)))
    write(CS_DIR + "/acquis.d/cowsec-mailcow.yaml", mailcow_acquis(c, mc), r=r)
    write(CS_DIR + "/parsers/s02-enrich/cowsec-private-whitelist.yaml", private_whitelist(c), r=r)
    ctx["reload_crowdsec"] = True


def step_firewall(c, r, ctx):
    apt_install(r, ["crowdsec-firewall-bouncer-iptables"])
    path = CS_DIR + "/bouncers/crowdsec-firewall-bouncer.yaml"
    txt = open(path).read()
    m = re.search(r"^iptables_chains:\n((?:[ \t]*#?[ \t]*-[^\n]*\n)+)", txt, re.M)
    block = "iptables_chains:\n  - INPUT\n  - DOCKER-USER\n"
    new = txt.replace(m.group(0), block) if m else txt + "\n" + block
    if write(path, new, 0o600, r):
        r.sh(["systemctl", "restart", "crowdsec-firewall-bouncer"])
    r.sh(["systemctl", "enable", "--now", "crowdsec-firewall-bouncer"])
    rc, out = run(["iptables", "-S", "DOCKER-USER"])
    r.log("DOCKER-USER protected" if "CROWDSEC" in out.upper() else "warning: DOCKER-USER rule not found yet")


# --- OpenResty edge

NGINX_CONF = """# Managed by CowSec: OpenResty edge in front of mailcow (CrowdSec bouncer + AppSec WAF).
worker_processes auto;
events { worker_connections 2048; }
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;
    server_tokens off;
    access_log /var/log/openresty/access.log combined;
    error_log  /var/log/openresty/error.log warn;
    map $http_upgrade $connection_upgrade { default upgrade; "" close; }
    include conf.d/*.conf;
    include sites/*.conf;
}
"""

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


def edge_sites(c, ctx):
    v6 = ctx["ipv6"]
    mc = ctx["mailcow"]
    cert, key = default_cert(c, ctx)
    out = ["# Managed by CowSec: mailcow behind the OpenResty edge.\n",
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
    ssl = os.path.join(ctx["mailcow"]["dir"], "data/assets/ssl")
    return os.path.join(ssl, "cert.pem"), os.path.join(ssl, "key.pem")


def step_edge(c, r, ctx):
    mc = ctx["mailcow"]
    osid, ver, code = os_release()
    flavour, comp = ("ubuntu", "main") if osid == "ubuntu" else ("debian", "openresty")
    apt_key_repo(r, "openresty", "https://openresty.org/package/pubkey.gpg",
                 "deb [signed-by=/usr/share/keyrings/openresty.gpg] https://openresty.org/package/%s %s %s" % (flavour, code, comp),
                 "/usr/share/keyrings/openresty.gpg")
    apt_install(r, ["openresty", "crowdsec-openresty-bouncer"], no_start=True)
    r.sh(["systemctl", "stop", "openresty"], check=False)
    os.makedirs("/var/log/openresty", exist_ok=True)
    os.makedirs(NGX + "/sites", exist_ok=True)
    conf_path = os.path.join(mc["dir"], "mailcow.conf")
    moving = mc["httpsBind"] != "127.0.0.1" or mc["httpsPort"] != str(EDGE_MAILCOW_HTTPS)
    write(NGX + "/nginx.conf", NGINX_CONF, r=r)
    write(NGX + "/cowsec_mailcow_proxy.conf", PROXY_CONF.replace("{https}", str(EDGE_MAILCOW_HTTPS)), r=r)
    write(NGX + "/sites/cowsec-mailcow.conf", edge_sites(c, ctx), r=r)
    # AppSec WAF: engine on localhost, bouncer asks it about every request
    write(CS_DIR + "/acquis.d/cowsec-appsec.yaml",
          "# Managed by CowSec: AppSec (WAF) engine for the OpenResty edge.\nappsec_config: crowdsecurity/appsec-default\n"
          "labels:\n  type: appsec\nlisten_addr: 127.0.0.1:7422\nsource: appsec\n", r=r)
    r.sh(["cscli", "collections", "install"] + APPSEC_COLLECTIONS)
    bconf = CS_DIR + "/bouncers/crowdsec-openresty-bouncer.conf"
    set_kv(bconf, {"APPSEC_URL": "http://127.0.0.1:7422", "APPSEC_FAILURE_ACTION": "passthrough", "MODE": "live"}, r)
    os.chmod(bconf, 0o600)
    r.sh(["systemctl", "restart", "crowdsec"])
    if moving:
        r.log("moving mailcow's web server to 127.0.0.1:%d/%d so the edge can own ports 80/443" % (EDGE_MAILCOW_HTTP, EDGE_MAILCOW_HTTPS))
        backup(conf_path, r)
        r.sh(["systemctl", "stop", "openresty"], check=False)
        set_kv(conf_path, {"HTTP_PORT": str(EDGE_MAILCOW_HTTP), "HTTP_BIND": "127.0.0.1",
                           "HTTPS_PORT": str(EDGE_MAILCOW_HTTPS), "HTTPS_BIND": "127.0.0.1"}, r)
        compose(mc["dir"], ["up", "-d"], r)
        ctx["rollback_mailcow_conf"] = True
    rc, out = r.sh([OPENRESTY + "/bin/openresty", "-t"], check=False)
    if rc != 0:
        raise StepError("OpenResty configuration test failed")
    r.sh(["systemctl", "enable", "openresty"])
    r.sh(["systemctl", "restart", "openresty"])
    for _ in range(20):
        if run(["systemctl", "is-active", "--quiet", "openresty"])[0] == 0:
            break
        time.sleep(1)
    else:
        raise StepError("OpenResty did not start (see journalctl -u openresty)")
    ctx.pop("rollback_mailcow_conf", None)
    # Reload OpenResty when mailcow renews its own certificate.
    if c["certs"]["mode"] == "mailcow":
        cert = os.path.join(mc["dir"], "data/assets/ssl/cert.pem")
        write("/etc/systemd/system/cowsec-cert-watch.path",
              "[Unit]\nDescription=Reload OpenResty when mailcow renews its certificate (CowSec)\n\n"
              "[Path]\nPathChanged=%s\n\n[Install]\nWantedBy=multi-user.target\n" % cert, r=r)
        write("/etc/systemd/system/cowsec-cert-watch.service",
              "[Unit]\nDescription=Reload OpenResty after a mailcow certificate change (CowSec)\n\n"
              "[Service]\nType=oneshot\nExecStartPre=/bin/sleep 10\nExecStart=/bin/systemctl reload openresty\n", r=r)
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
        r.sh(["systemctl", "stop", "openresty"], check=False)
        shutil.copy2(baks[-1], conf_path)
        compose(mc["dir"], ["up", "-d"], r, check=False)


# --- certificates (DNS-01 via lego)

def cert_names(dom, c, mc):
    if c["certs"]["wildcard"]:
        return [dom, "*." + dom]
    names = [dom, "mail." + dom, "autodiscover." + dom, "autoconfig." + dom]
    return names


def lego_env(c):
    env = dict(c["certs"]["credentials"])
    env.update({"LEGO_PATH": ACME_DIR})
    return env


def issue(name, domains, c, r):
    args = [ensure_lego(r), "run", "--path", ACME_DIR, "--cert.name", name, "--accept-tos", "--email", c["certs"]["email"],
            "--dns", c["certs"]["provider"], "--key-type", "EC256", "--no-random-sleep"]
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
        names = [dom, "mail." + dom, "autodiscover." + dom, "autoconfig." + dom]
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
        r.sh([OPENRESTY + "/bin/openresty", "-t", "-q"])
        r.sh(["systemctl", "reload", "openresty"], check=False)


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
OUT=/usr/local/openresty/nginx/conf/conf.d/cloudflare_realip.conf
TMP=$(mktemp)
{ echo "# generated by cowsec-cloudflare-realip $(date -I)"
  for u in https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6; do
    curl -fsS -m 20 "$u" | grep -E '^[0-9a-f.:]+/[0-9]+$' | sed 's/.*/set_real_ip_from &;/'
  done
  echo "real_ip_header CF-Connecting-IP;"; } > "$TMP"
if [ "$(grep -c set_real_ip_from "$TMP")" -lt 10 ]; then echo "too few ranges fetched, keeping old file" >&2; rm -f "$TMP"; exit 1; fi
install -m 644 "$TMP" "$OUT"; rm -f "$TMP"
/usr/local/openresty/bin/openresty -t -q && systemctl reload openresty
"""


def step_cloudflare_realip(c, r, ctx):
    write(LIB_DIR + "/cowsec-cloudflare-realip", REALIP_SCRIPT, 0o755, r=r)
    write("/etc/systemd/system/cowsec-cloudflare-realip.service",
          "[Unit]\nDescription=Refresh Cloudflare real-IP ranges for OpenResty (CowSec)\nAfter=network-online.target\n\n"
          "[Service]\nType=oneshot\nExecStart=%s/cowsec-cloudflare-realip\n" % LIB_DIR, r=r)
    write("/etc/systemd/system/cowsec-cloudflare-realip.timer",
          "[Unit]\nDescription=Monthly Cloudflare real-IP refresh (CowSec)\n\n[Timer]\nOnCalendar=monthly\nPersistent=true\n\n"
          "[Install]\nWantedBy=timers.target\n", r=r)
    r.sh(["systemctl", "daemon-reload"])
    r.sh(["systemctl", "enable", "cowsec-cloudflare-realip.timer"])
    r.sh(["systemctl", "start", "cowsec-cloudflare-realip.service"])


def step_chrony(c, r, ctx):
    apt_install(r, ["chrony"])
    write("/etc/modules-load.d/cowsec-ptp_kvm.conf", "ptp_kvm\n", r=r)
    r.sh(["modprobe", "ptp_kvm"], check=False)
    write("/etc/chrony/conf.d/cowsec-ptp.conf",
          "# Managed by CowSec: hypervisor clock via the KVM paravirtual PTP device.\n"
          "refclock PHC /dev/ptp0 poll 2 dpoll -2 offset 0 stratum 2 prefer\n", r=r)
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
        r.sh([OPENRESTY + "/bin/openresty", "-t", "-q"])
        r.sh(["systemctl", "reload", "openresty"])
    elif os.path.exists(site):
        os.remove(site)
        r.log("removed %s" % site)
        if run(["systemctl", "is-active", "--quiet", "openresty"])[0] == 0:
            r.sh(["systemctl", "reload", "openresty"])
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
    r.sh(["systemctl", "restart", "crowdsec"])
    time.sleep(5)
    for svc in ("crowdsec", "crowdsec-firewall-bouncer") + (("openresty",) if c["components"]["edge"] else ()):
        rc, _ = run(["systemctl", "is-active", "--quiet", svc])
        r.log("%s: %s" % (svc, "running" if rc == 0 else "NOT RUNNING"))
        if rc != 0:
            raise StepError("%s is not running" % svc)
    r.sh(["cscli", "lapi", "status"], check=False)
    write(STATE_DIR + "/setup.json", json.dumps(public_config(c), indent=2) + "\n", 0o600, r=r)


STEPS = [
    ("crowdsec", "Install CrowdSec and the mail, web and SSH collections", lambda c: True, step_crowdsec),
    ("detection", "Read mailcow's logs and never ban the local network", lambda c: True, step_detection),
    ("firewall", "Firewall bouncer (host services and Docker-published mail ports)", lambda c: True, step_firewall),
    ("certs", "Certificates via DNS-01 (lego)", lambda c: c["certs"]["mode"] == "dns01", step_certs),
    ("edge", "OpenResty edge with the CrowdSec bouncer and AppSec WAF", lambda c: c["components"]["edge"], step_edge),
    ("realip", "Cloudflare real visitor IPs", lambda c: c["components"]["edge"] and c["components"]["cloudflareRealIP"], step_cloudflare_realip),
    ("chrony", "Precise clock from the hypervisor (KVM PTP)", lambda c: c["components"]["chronyPtp"], step_chrony),
    ("policy", "Ban policy: home countries, abroad login rule, escalating bans", lambda c: c["components"]["banPolicy"], step_ban_policy),
    ("access", "Console access", lambda c: True, step_access),
    ("finish", "Test configuration and start everything", lambda c: True, step_finish),
]


def plan(c):
    return [{"id": sid, "title": title} for sid, title, enabled, _ in STEPS if enabled(c)]


def install(c, r, progress=None):
    """Runs the enabled steps in order. progress(step_id, state) is called around each step."""
    ctx = {"mailcow": mailcow_info(), "ipv6": ipv6_enabled()}
    if not ctx["mailcow"]["found"]:
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
