"""Tests for setup_engine.py: run with `python3 -m unittest discover -s packaging/tests`.
Nothing here touches the system: paths point into a scratch folder and system calls are recorded."""
import importlib.util
import io
import json
import atexit
import os
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))


def mkdtemp(**kw):
    """A scratch folder whose path has no "_": adopted files encode "/" as "__" in their names."""
    while True:
        d = tempfile.mkdtemp(**kw)
        if "_" not in d:
            return d
        os.rmdir(d)


SCRATCH = mkdtemp(prefix="cowsec-test-")
atexit.register(shutil.rmtree, SCRATCH, ignore_errors=True)
os.environ["COWSEC_STATE_DIR"] = os.path.join(SCRATCH, "state")
os.makedirs(os.environ["COWSEC_STATE_DIR"], exist_ok=True)
os.environ["COWSEC_EDGE"] = "openresty"  # the same edge on every build host; EdgeFlavour tests the choice itself
spec = importlib.util.spec_from_file_location("setup_engine", os.path.join(HERE, "..", "lib", "setup_engine.py"))
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)


def read(path):
    with open(path) as f:
        return f.read()


class FakeRunner:
    """Stands in for se.Runner: records commands instead of running them."""
    def __init__(self):
        self.cmds, self.lines = [], []

    def sh(self, cmd, **kw):
        self.cmds.append(cmd)
        return 0, ""

    def log(self, msg):
        self.lines.append(msg)


def rule(name, desc="", status="enabled"):
    return {"name": "crowdsecurity/" + name, "description": desc, "status": status}


class MailWAF(unittest.TestCase):
    ITEMS = [rule("base-config"), rule("vpatch-CVE-2025-49113", "Roundcube RCE via PHP object deserialization"),
             rule("vpatch-CVE-2024-27956", "WordPress Automatic Plugin - SQLi"), rule("vpatch-env-access", "Detect access to .env files"),
             rule("vpatch-CVE-2022-41082", "Microsoft Exchange - RCE"), rule("vpatch-CVE-2023-9999", "Some router", status="disabled,update-available")]

    def test_classifies_by_product(self):
        modes = {r["name"].split("/")[1]: r["mode"] for r in se.appsec_classify(self.ITEMS, {})}
        self.assertNotIn("base-config", modes, "base-config is always in the request path, not a choice")
        self.assertEqual(modes["vpatch-CVE-2025-49113"], "block")  # webmail
        self.assertEqual(modes["vpatch-CVE-2022-41082"], "block")  # Exchange
        self.assertEqual(modes["vpatch-env-access"], "block")      # probe that never belongs on a mail server
        self.assertEqual(modes["vpatch-CVE-2024-27956"], "watch")  # software a mail server doesn't run
        self.assertEqual(modes["vpatch-CVE-2023-9999"], "off")     # not installed

    def test_user_choice_wins_and_order(self):
        rules = se.appsec_classify(self.ITEMS, {"crowdsecurity/vpatch-CVE-2025-49113": "watch"})
        roundcube = next(r for r in rules if r["name"].endswith("49113"))
        self.assertEqual((roundcube["mode"], roundcube["auto"], roundcube["override"]), ("watch", "block", True))
        order = [r["mode"] for r in rules]
        self.assertEqual(order, sorted(order, key=["block", "watch", "off"].index), "blocking rules first, then watching, then off")

    def test_curate_writes_valid_config(self):
        d = os.path.join(SCRATCH, "cs")
        os.makedirs(os.path.join(d, "acquis.d"), exist_ok=True)
        acquis = os.path.join(d, "acquis.d", "cowsec-appsec.yaml")
        with open(acquis, "w") as f:
            f.write("appsec_config: crowdsecurity/appsec-default\nsource: appsec\n")
        listing = json.dumps({"appsec-rules": self.ITEMS})
        runs = {"cscli": (0, listing), "crowdsec": (0, "")}
        with mock.patch.multiple(se, APPSEC_ACQUIS=acquis, APPSEC_CONFIG_FILE=os.path.join(d, "appsec-configs", "cowsec-mail-waf.yaml"),
                                 APPSEC_WATCH_SCENARIO=os.path.join(d, "scenarios", "cowsec-appsec-watch.yaml"),
                                 APPSEC_POLICY=os.path.join(SCRATCH, "pol.json")), \
             mock.patch.object(se, "run", side_effect=lambda cmd, timeout=60: runs[cmd[0]]):
            os.makedirs(os.path.join(d, "scenarios"), exist_ok=True)
            res = se.appsec_curate(FakeRunner())
            self.assertEqual(res["counts"], {"block": 3, "watch": 1, "off": 1})
            conf = read(se.APPSEC_CONFIG_FILE)
            self.assertIn(" - crowdsecurity/base-config\n", conf)
            self.assertIn(" - crowdsecurity/vpatch-CVE-2025-49113\n", conf)
            self.assertNotIn("vpatch-CVE-2024-27956\n", conf.split("outofband_rules")[0], "a watch rule must not be in the request path")
            self.assertIn("appsec_config: cowsec/mail-waf", read(acquis))
            scen = read(se.APPSEC_WATCH_SCENARIO)
            filt = next(l for l in scen.splitlines() if l.startswith("filter:"))
            self.assertEqual(filt.count('"'), 2, "the filter is one double-quoted string with single quotes inside")
            try:
                import yaml
                self.assertEqual(yaml.safe_load(scen)["name"], "cowsec/appsec-watch")
            except ImportError:
                pass

    def test_curate_reverts_when_crowdsec_refuses(self):
        d = os.path.join(SCRATCH, "cs2")
        os.makedirs(os.path.join(d, "acquis.d"), exist_ok=True)
        acquis = os.path.join(d, "acquis.d", "cowsec-appsec.yaml")
        original = "appsec_config: crowdsecurity/appsec-default\n"
        with open(acquis, "w") as f:
            f.write(original)
        runs = {"cscli": (0, json.dumps({"appsec-rules": self.ITEMS})), "crowdsec": (1, "FATAL bad config")}
        cfg = os.path.join(d, "appsec-configs", "cowsec-mail-waf.yaml")
        with mock.patch.multiple(se, APPSEC_ACQUIS=acquis, APPSEC_CONFIG_FILE=cfg, APPSEC_WATCH_SCENARIO=os.path.join(d, "w.yaml"),
                                 APPSEC_POLICY=os.path.join(SCRATCH, "pol2.json")), \
             mock.patch.object(se, "run", side_effect=lambda cmd, timeout=60: runs[cmd[0]]):
            with self.assertRaises(se.StepError):
                se.appsec_curate(FakeRunner())
            self.assertEqual(read(acquis), original, "the previous AppSec config must be put back")
            self.assertFalse(os.path.exists(cfg), "the rejected config must not be left behind")


class Releases(unittest.TestCase):
    def test_candidates(self):
        self.assertEqual(se.codename_candidates("debian", "trixie"), ["trixie", "bookworm"])
        self.assertEqual(se.codename_candidates("ubuntu", "noble"), ["noble", "jammy"])
        self.assertEqual(se.codename_candidates("debian", "duke")[0], "duke")
        self.assertIn("bookworm", se.codename_candidates("debian", "duke"), "an unknown release still falls back to known ones")

    def test_openresty_blocked_only_on_debian_13_with_sqv(self):
        cases = [(("debian", "13", "trixie"), True, True), (("debian", "12", "bookworm"), True, False),
                 (("ubuntu", "24.04", "noble"), True, False), (("debian", "13", "trixie"), False, False)]
        for rel, sqv, want in cases:
            with mock.patch.object(se, "os_release", return_value=rel), \
                 mock.patch.object(se.os.path, "exists", side_effect=lambda p, sqv=sqv: sqv if p == "/usr/bin/sqv" else os.path.lexists(p)):
                self.assertEqual(se.openresty_blocked(), want, rel)


class EdgeFlavour(unittest.TestCase):
    """Debian 13 can't verify OpenResty's packages, so its edge is Debian's own nginx."""

    def tearDown(self):
        se.use_edge("openresty")

    def kind(self, blocked, edge_file=None, openresty_installed=False):
        path = os.path.join(mkdtemp(dir=SCRATCH), "edge")
        if edge_file:
            with open(path, "w") as f:
                f.write(edge_file + "\n")
        real = os.path.exists
        with mock.patch.dict(os.environ, {"COWSEC_EDGE": ""}), mock.patch.object(se, "EDGE_FILE", path), \
             mock.patch.object(se, "openresty_blocked", return_value=blocked), \
             mock.patch.object(se.os.path, "exists", side_effect=lambda p: openresty_installed if p == se.EDGES["openresty"]["bin"] else real(p)):
            return se.edge_kind()

    def test_choice(self):
        self.assertEqual(self.kind(blocked=False), "openresty")
        self.assertEqual(self.kind(blocked=True), "nginx", "Debian 13 gets Debian's nginx")
        self.assertEqual(self.kind(blocked=True, openresty_installed=True), "openresty", "an OpenResty that's already there stays")
        self.assertEqual(self.kind(blocked=False, edge_file="nginx"), "nginx", "the installed flavour wins")

    def test_nginx_paths_and_config(self):
        se.use_edge("nginx")
        self.assertEqual((se.NGX, se.EDGE_SVC, se.EDGE_BIN, se.EDGE_LOGS), ("/etc/nginx", "nginx", "/usr/sbin/nginx", "/var/log/nginx"))
        self.assertEqual(se.EDGE_BOUNCER_CONF, "/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf")
        conf = se.edge_nginx_conf()
        self.assertIn("include /etc/nginx/modules-enabled/*.conf;", conf, "Debian's nginx loads the Lua module from modules-enabled")
        self.assertIn("pid /run/nginx.pid;", conf)
        self.assertIn("/var/log/nginx/access.log", conf)
        for ph in ("{name}", "{head}", "{logs}"):
            self.assertNotIn(ph, conf, "no template placeholders left")
        acq = se.mailcow_acquis({"components": {"edge": True}}, {"containers": {}})
        self.assertIn("/var/log/nginx/access.log", acq, "CrowdSec reads the edge's own logs")

    def test_openresty_config_unchanged(self):
        se.use_edge("openresty")
        conf = se.edge_nginx_conf()
        self.assertNotIn("modules-enabled", conf)
        self.assertIn("/var/log/openresty/access.log", conf)

    def test_nginx_install_uses_debian_packages(self):
        se.use_edge("nginx")
        r = FakeRunner()
        installed = []
        with mock.patch.object(se, "apt_install", side_effect=lambda r, pkgs, no_start=False: installed.extend(pkgs)), \
             mock.patch.object(se, "apt_key_repo") as repo, mock.patch.object(se, "write"), \
             mock.patch.object(se, "ensure_resty_http", side_effect=se.StepError("stop here")):
            with self.assertRaises(se.StepError):
                se.step_edge({}, r, {"mailcow": {}})
        repo.assert_not_called()  # never OpenResty's repository
        self.assertIn("nginx", installed)
        self.assertIn("libnginx-mod-http-lua", installed)
        self.assertIn("crowdsec-nginx-bouncer", installed)
        self.assertIn("lua-cjson", installed, "Debian's lua-cjson, so luarocks needn't compile it")
        self.assertNotIn("openresty", installed)


class SafetyNet(unittest.TestCase):
    def setUp(self):
        self.root = mkdtemp(dir=SCRATCH)
        self.mc = os.path.join(self.root, "mailcow")
        os.makedirs(os.path.join(self.mc, "data/conf/postfix"))
        os.makedirs(os.path.join(self.mc, "data/assets/ssl"))
        self.files = {"mailcow.conf": "HTTP_PORT=80\nHTTPS_PORT=443\n", "data/conf/postfix/extra.cf": "smtpd_tls = yes\n",
                      "data/assets/ssl/cert.pem": "ORIGINAL CERT\n"}
        for rel, text in self.files.items():
            with open(os.path.join(self.mc, rel), "w") as f:
                f.write(text)
        self.cs = os.path.join(self.root, "crowdsec")
        os.makedirs(self.cs)
        with open(os.path.join(self.cs, "config.yaml"), "w") as f:
            f.write("api: {}\n")
        self.patch = mock.patch.multiple(se, SNAPSHOT_DIR=os.path.join(self.root, "backups"),
                                         SNAPSHOT_POINTER=os.path.join(self.root, "pointer"), CS_DIR=self.cs)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_snapshot_then_restore(self):
        with mock.patch.object(se, "run", return_value=(0, "*filter\n-A INPUT -j ACCEPT\nCOMMIT")):
            se.step_snapshot({}, FakeRunner(), {"mailcow": {"dir": self.mc}})
        path = read(se.SNAPSHOT_POINTER).strip()
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600", "the snapshot holds secrets: root-only")
        names = tarfile.open(path).getnames()
        for want in ("mailcow/mailcow.conf", "mailcow/data/conf/postfix/extra.cf", "mailcow/data/assets/ssl/cert.pem",
                     "crowdsec" + self.cs + "/config.yaml", "firewall/iptables.rules", "MANIFEST"):
            self.assertIn(want, names)
        # what CowSec's install would do: move mailcow behind the edge, replace the certificate
        with open(os.path.join(self.mc, "mailcow.conf"), "w") as f:
            f.write("HTTP_PORT=8081\nHTTPS_PORT=8443\nHTTP_BIND=127.0.0.1\n")
        with open(os.path.join(self.mc, "data/assets/ssl/cert.pem"), "w") as f:
            f.write("COWSEC CERT\n")
        r = FakeRunner()
        with mock.patch.object(se, "find_mailcow", return_value=self.mc), mock.patch.object(se, "compose", return_value=(0, "")) as comp:
            se.restore_mailcow(r, path)
        for rel, text in self.files.items():
            self.assertEqual(read(os.path.join(self.mc, rel)), text, rel + " not restored")
        self.assertTrue(any(f.startswith("mailcow.conf.before-restore-") for f in os.listdir(self.mc)), "today's mailcow.conf must be kept")
        self.assertIn(["systemctl", "disable", "--now", "openresty"], r.cmds, "the edge must give 80/443 back")
        comp.assert_called_once()
        self.assertEqual(comp.call_args[0][1], ["up", "-d"])

    def test_restore_ignores_paths_outside_mailcow(self):
        path = os.path.join(self.root, "evil.tar.gz")
        with tarfile.open(path, "w:gz") as tar:
            for name, data in (("mailcow/mailcow.conf", b"HTTP_PORT=80\n"), ("mailcow/../../escaped", b"x"), ("etc/passwd", b"x")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        with mock.patch.object(se, "find_mailcow", return_value=self.mc), mock.patch.object(se, "compose", return_value=(0, "")):
            se.restore_mailcow(FakeRunner(), path)
        self.assertFalse(os.path.exists(os.path.join(self.root, "escaped")))
        self.assertFalse(os.path.exists(os.path.join(self.mc, "etc", "passwd")))

    def test_restore_needs_a_snapshot(self):
        with self.assertRaises(se.StepError):
            se.restore_mailcow(FakeRunner(), None)


class Validation(unittest.TestCase):
    def test_database_reads_check_the_domain_first(self):
        for bad in ("example.org'; DROP TABLE mailbox; --", "../etc", "EXAMPLE ORG"):
            with mock.patch.object(se, "compose") as comp:
                for fn in (se.mailcow_footer, se.mailcow_mta_sts):
                    with self.assertRaises(se.StepError):
                        fn(bad)
                comp.assert_not_called()

    def test_appsec_mode_input(self):
        for name, mode in (("crowdsecurity/x; rm -rf /", "block"), ("crowdsecurity/vpatch-a", "maybe"), ("other/rule", "watch")):
            with self.assertRaises(se.StepError):
                se.appsec_set_mode(name, mode, FakeRunner())


if __name__ == "__main__":
    unittest.main()


class MailcowPortFix(unittest.TestCase):
    """Up to 0.3.9 the edge put mailcow on HTTP_PORT=8081, which mailcow uses internally."""
    def setUp(self):
        self.root = mkdtemp(dir=SCRATCH)
        self.mc = os.path.join(self.root, "mailcow")
        self.ngx = os.path.join(self.root, "ngx")
        os.makedirs(self.mc)
        os.makedirs(os.path.join(self.ngx, "sites"))
        self.conf = os.path.join(self.mc, "mailcow.conf")
        self.site = os.path.join(self.ngx, "sites", "cowsec-mailcow.conf")
        with open(self.conf, "w") as f:
            f.write("# mailcow\nHTTP_PORT=8081\nHTTP_BIND=127.0.0.1\nHTTPS_PORT=8443\nHTTPS_BIND=127.0.0.1\n")
        with open(self.site, "w") as f:
            f.write("location ^~ /.well-known/acme-challenge/ { proxy_pass http://127.0.0.1:8081; }\n")
        self.patches = [mock.patch.object(se, "NGX", self.ngx), mock.patch.object(se, "find_mailcow", return_value=self.mc)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_moves_port_and_edge_together(self):
        answers = iter([None, 301])  # port free before the move, mailcow answering after it
        with mock.patch.object(se, "http_status", side_effect=lambda *a, **k: next(answers)), \
                mock.patch.object(se, "compose", return_value=(0, "200 PERMIT")) as comp:
            res = se.fix_mailcow_http_port(FakeRunner())
        self.assertEqual(res, {"changed": True, "lookup_ok": True})
        self.assertIn("HTTP_PORT=8180", read(self.conf))
        self.assertIn("HTTPS_PORT=8443", read(self.conf), "only the HTTP port moves")
        self.assertIn("127.0.0.1:8180", read(self.site))
        self.assertEqual(comp.call_args_list[0][0][1], ["up", "-d", "--no-deps", "nginx-mailcow"], "only nginx is recreated")

    def test_puts_everything_back_if_mailcow_does_not_return(self):
        before_conf, before_site = read(self.conf), read(self.site)
        with mock.patch.object(se, "http_status", return_value=None), mock.patch.object(se, "compose", return_value=(0, "")), \
                mock.patch.object(se.time, "sleep"):
            with self.assertRaises(se.StepError):
                se.fix_mailcow_http_port(FakeRunner())
        self.assertEqual(read(self.conf), before_conf)
        self.assertEqual(read(self.site), before_site)

    def test_leaves_other_setups_alone(self):
        with open(self.conf, "w") as f:
            f.write("HTTP_PORT=80\nHTTP_BIND=\n")
        with mock.patch.object(se, "compose") as comp:
            self.assertFalse(se.fix_mailcow_http_port(FakeRunner())["changed"])
        comp.assert_not_called()


class Uninstall(unittest.TestCase):
    """Uninstalling leaves mailcow on its own settings, keeping the admin's later changes."""
    BEFORE = "# mailcow\nMAILCOW_HOSTNAME=mail.example.org\nHTTP_PORT=80\nHTTP_BIND=\nHTTPS_PORT=443\nHTTPS_BIND=\nSKIP_LETS_ENCRYPT=n\nSKIP_CLAMD=n\n"
    NOW = ("# mailcow\nMAILCOW_HOSTNAME=mail.example.org\nHTTP_PORT=8180\nHTTP_BIND=127.0.0.1\nHTTPS_PORT=8443\nHTTPS_BIND=127.0.0.1\n"
           "SKIP_LETS_ENCRYPT=y\nSKIP_CLAMD=y\nAPI_KEY=abcdefabcdefabcdefabcdefabcdef\nAPI_ALLOW_FROM=127.0.0.1,::1,172.22.1.1\nADDITIONAL_SAN=cowsec.example.org\n")

    def setUp(self):
        self.root = mkdtemp(dir=SCRATCH)
        self.mc = os.path.join(self.root, "mailcow")
        self.ngx = os.path.join(self.root, "ngx")
        self.cs = os.path.join(self.root, "crowdsec")
        for d in (self.mc + "/data/conf/postfix", self.mc + "/data/assets/ssl/example.org", self.ngx + "/sites", self.cs + "/acquis.d", self.cs + "/scenarios", self.cs + "/appsec-configs"):
            os.makedirs(d)
        self.conf = os.path.join(self.mc, "mailcow.conf")
        with open(self.conf, "w") as f:
            f.write(self.NOW)  # SKIP_CLAMD=y is the admin's own later change
        with open(self.conf + ".cowsec-bak-20260101000000", "w") as f:
            f.write(self.BEFORE)
        with open(self.mc + "/data/conf/postfix/extra.cf", "w") as f:
            f.write("smtpd_banner = moo\n# BEGIN cowsec-sni (managed by CowSec)\ntls_server_sni_maps = hash:/opt/postfix/conf/cowsec_sni.map\n# END cowsec-sni\n")
        with open(self.mc + "/data/conf/postfix/cowsec_sni.map", "w") as f:
            f.write("example.org /etc/ssl/mail/example.org/key.pem /etc/ssl/mail/example.org/cert.pem\n")
        with open(self.mc + "/data/assets/ssl/example.org/cert.pem", "w") as f:
            f.write("CERT\n")
        with open(self.ngx + "/sites/cowsec-mailcow.conf", "w") as f:
            f.write("proxy_pass https://127.0.0.1:8443;\n")
        self.patches = [mock.patch.object(se, "NGX", self.ngx), mock.patch.object(se, "CS_DIR", self.cs),
                        mock.patch.object(se, "SNAPSHOT_POINTER", os.path.join(self.root, "no-snapshot")),
                        mock.patch.object(se, "ADOPTED_PREFIX", os.path.join(self.root, "adopted-")),
                        mock.patch.object(se, "ROOT", os.path.join(self.root, "sys")),
                        mock.patch.object(se, "APPSEC_ACQUIS", self.cs + "/acquis.d/cowsec-appsec.yaml"),
                        mock.patch.object(se, "APPSEC_CONFIG_FILE", self.cs + "/appsec-configs/cowsec-mail-waf.yaml"),
                        mock.patch.object(se, "APPSEC_WATCH_SCENARIO", self.cs + "/scenarios/cowsec-appsec-watch.yaml"),
                        mock.patch.object(se, "UNINSTALLED", os.path.join(self.root, "uninstalled")),
                        mock.patch.object(se, "COWSEC_FILES", ()), mock.patch.object(se, "COWSEC_UNITS", ()),
                        mock.patch.object(se, "find_mailcow", return_value=self.mc),
                        mock.patch.object(se, "run", return_value=(0, "")),
                        mock.patch.object(se, "mailcow_answers", return_value=True)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def test_detach_reverts_only_cowsec_keys(self):
        se.detach_mailcow(FakeRunner(), self.mc)
        kv = se.read_kv(self.conf)
        for k, v in {"HTTP_PORT": "80", "HTTP_BIND": "", "HTTPS_PORT": "443", "HTTPS_BIND": "", "SKIP_LETS_ENCRYPT": "n",
                     "API_KEY": "", "API_ALLOW_FROM": "", "ADDITIONAL_SAN": ""}.items():
            self.assertEqual(kv.get(k), v, k)
        self.assertEqual(kv["SKIP_CLAMD"], "y", "the admin's own later change must survive")
        self.assertEqual(read(self.mc + "/data/conf/postfix/extra.cf"), "smtpd_banner = moo\n")
        self.assertFalse(os.path.exists(self.mc + "/data/conf/postfix/cowsec_sni.map"))
        self.assertFalse(os.path.exists(self.mc + "/data/assets/ssl/example.org"), "CowSec's per-domain certs would expire unrenewed")

    def test_never_touched_means_left_alone(self):
        os.remove(self.conf + ".cowsec-bak-20260101000000")
        se.detach_mailcow(FakeRunner(), self.mc)
        self.assertEqual(read(self.conf), self.NOW)

    def test_8081_is_not_brought_back(self):
        with open(self.conf + ".cowsec-bak-20260101000000", "w") as f:
            f.write(self.BEFORE.replace("HTTP_PORT=80", "HTTP_PORT=8081").replace("HTTP_BIND=\n", "HTTP_BIND=127.0.0.1\n"))
        se.detach_mailcow(FakeRunner(), self.mc)
        self.assertEqual(se.read_kv(self.conf)["HTTP_PORT"], "8180")

    def test_uninstall_standard_mailcow(self):
        with open(se.APPSEC_CONFIG_FILE, "w") as f:
            f.write("name: cowsec/mail-waf\n")
        r = FakeRunner()
        with mock.patch.object(se, "compose", return_value=(0, "")) as comp:
            res = se.uninstall(r)
        self.assertFalse(res["kept_edge"])
        self.assertEqual(se.read_kv(self.conf)["HTTPS_PORT"], "443")
        self.assertFalse(os.path.exists(self.ngx + "/sites/cowsec-mailcow.conf"))
        self.assertIn(["systemctl", "disable", "--now", "openresty"], r.cmds, "the edge must give 80/443 back")
        self.assertFalse(os.path.exists(se.APPSEC_CONFIG_FILE))
        self.assertTrue(os.path.exists(se.UNINSTALLED))
        comp.assert_called_with(self.mc, ["up", "-d"], r, check=False)

    def test_uninstall_puts_back_a_hand_built_edge(self):
        # before CowSec: mailcow behind the admin's own OpenResty, on the forbidden 8081
        with open(self.conf + ".cowsec-bak-20260101000000", "w") as f:
            f.write(self.BEFORE.replace("HTTP_PORT=80", "HTTP_PORT=8081").replace("HTTP_BIND=\n", "HTTP_BIND=127.0.0.1\n")
                    .replace("HTTPS_PORT=443", "HTTPS_PORT=8443").replace("HTTPS_BIND=\n", "HTTPS_BIND=127.0.0.1\n"))
        adopted = os.path.join(self.root, "adopted-20260101000000")
        os.makedirs(adopted)
        site = os.path.join(self.root, "sys", self.ngx.strip("/"), "sites", "mail.conf")
        with open(os.path.join(adopted, site[len(os.path.join(self.root, "sys")) + 1:].replace("/", "__")), "w") as f:
            f.write("location /.well-known/ { proxy_pass http://127.0.0.1:8081; }\n")
        r = FakeRunner()
        with mock.patch.object(se, "ROOT", "/"), mock.patch.object(se, "compose", return_value=(0, "")):
            res = se.uninstall(r)
        self.assertTrue(res["kept_edge"], "the admin's own edge should serve mailcow again")
        self.assertIn("127.0.0.1:8180", read(self.ngx + "/sites/mail.conf"))
        kv = se.read_kv(self.conf)
        self.assertEqual((kv["HTTP_PORT"], kv["HTTPS_PORT"], kv["HTTPS_BIND"]), ("8180", "8443", "127.0.0.1"))
        self.assertNotIn(["systemctl", "disable", "--now", "openresty"], r.cmds)

    def test_hand_back_fails_loudly(self):
        with mock.patch.object(se, "compose", return_value=(0, "")), mock.patch.object(se, "mailcow_answers", return_value=False):
            with self.assertRaises(se.StepError):
                se.uninstall(FakeRunner())
        self.assertFalse(os.path.exists(se.UNINSTALLED), "a failed hand-back must not be marked done")


class MailcowUpdateHealth(unittest.TestCase):
    """During mailcow updates, slow or crash-looping containers surface their log reason and malformed ClamAV DBs self-heal."""
    def test_surfaces_container_reason_and_heals_malformed_clamd_db(self):
        clam_log = (
            "ClamAV 1.4.6 is starting... please wait a moment.\n"
            "LibClamAV Error: Can't load /var/lib/clamav/phish.ndb: Malformed database\n"
            "ERROR: Malformed database\n"
        )
        states = [
            {"containers": {"clamd-mailcow": {"name": "mc-clamd-1", "status": "Up 5 seconds (health: starting)"},
                            "nginx-mailcow": {"name": "mc-nginx-1", "status": "Up 1 minute"}}},
            {"containers": {"clamd-mailcow": {"name": "mc-clamd-1", "status": "Up 14 seconds (health: starting)"},
                            "nginx-mailcow": {"name": "mc-nginx-1", "status": "Up 1 minute"}}},
            {"containers": {"clamd-mailcow": {"name": "mc-clamd-1", "status": "Up 20 seconds (healthy)"},
                            "nginx-mailcow": {"name": "mc-nginx-1", "status": "Up 1 minute"}}},
        ]
        r = FakeRunner()
        events = []
        with mock.patch.object(se, "find_mailcow", return_value="/opt/mailcow-dockerized"), \
                mock.patch.object(se, "mailcow_info", side_effect=states), \
                mock.patch.object(se, "run", return_value=(0, clam_log)), \
                mock.patch.object(se, "_heal_clamd_db") as heal, \
                mock.patch.object(se, "mailcow_post_checks", return_value=[{"name": "ok", "ok": True, "detail": ""}]), \
                mock.patch.object(se, "write"), \
                mock.patch.object(se.time, "sleep"):
            se.mailcow_update(r, lambda *a, **kw: events.append((a, kw)), {"backup": False})
        heal.assert_called_once_with("mc-clamd-1", "/var/lib/clamav/phish.ndb")
        logged = "\n".join(r.lines)
        self.assertIn("malformed ClamAV signature file (phish.ndb)", logged)
        self.assertIn("waiting on clamd-mailcow", logged)
        self.assertIn("all 2 containers ready", logged)



class IPv6(unittest.TestCase):
    """The IPv6 check reads /proc's contents: those files always report a size of 0 (issue #2)."""
    def files(self, inet6, disabled="0"):
        d = mkdtemp(dir=SCRATCH)
        a, b = os.path.join(d, "if-inet6"), os.path.join(d, "disable")
        with open(a, "w") as f:
            f.write(inet6)
        with open(b, "w") as f:
            f.write(disabled + "\n")
        return a, b

    # the reporter's server: a global /124 on a USB-named interface, plus loopback and link-local
    HOSTING_DE = ("00000000000000000000000000000001 01 80 10 80       lo\n"
                  "2a0017d8010000000000000000000abc 02 7c 00 80 enx1a0135792d10\n"
                  "fe80000000000000180135fffe792d10 02 40 20 80 enx1a0135792d10\n")

    def test_global_address_found(self):
        self.assertTrue(se.ipv6_enabled(*self.files(self.HOSTING_DE)))

    def test_only_loopback_and_link_local(self):
        self.assertFalse(se.ipv6_enabled(*self.files("00000000000000000000000000000001 01 80 10 80       lo\n"
                                                     "fe80000000000000180135fffe792d10 02 40 20 80     eth0\n")))

    def test_switched_off_in_the_kernel(self):
        self.assertFalse(se.ipv6_enabled(*self.files(self.HOSTING_DE, disabled="1")))

    def test_no_ipv6_at_all(self):
        self.assertFalse(se.ipv6_enabled(os.path.join(SCRATCH, "missing"), os.path.join(SCRATCH, "missing-too")))

    def test_proc_files_report_size_zero(self):
        if os.path.exists("/proc/net/if_inet6") and open("/proc/net/if_inet6").read():
            self.assertEqual(os.path.getsize("/proc/net/if_inet6"), 0, "why the old size check always said no")

    def test_fix_adds_ipv6_listeners_once(self):
        se.use_edge("openresty")
        d = mkdtemp(dir=SCRATCH)
        os.makedirs(os.path.join(d, "sites"))
        site = os.path.join(d, "sites", "cowsec-mailcow.conf")
        with open(site, "w") as f:
            f.write("server {\n    listen 80 default_server;\n    server_name _;\n}\n"
                    "server {\n    listen 443 ssl default_server;\n    server_name _;\n}\n")
        r = FakeRunner()
        with mock.patch.object(se, "NGX", d), mock.patch.object(se, "ipv6_enabled", return_value=True):
            res = se.fix_ipv6_listen(r)
            self.assertTrue(res["changed"])
            text = read(site)
            self.assertIn("    listen 80 default_server;\n    listen [::]:80 default_server;\n", text)
            self.assertIn("    listen 443 ssl default_server;\n    listen [::]:443 ssl default_server;\n", text)
            self.assertIn([se.EDGE_BIN, "-t", "-q"], r.cmds, "the config is tested before reloading")
            self.assertFalse(se.fix_ipv6_listen(FakeRunner())["changed"], "running it again changes nothing")

    def test_fix_puts_files_back_when_the_test_fails(self):
        se.use_edge("openresty")
        d = mkdtemp(dir=SCRATCH)
        os.makedirs(os.path.join(d, "sites"))
        site = os.path.join(d, "sites", "cowsec-console.conf")
        original = "server {\n    listen 443 ssl;\n}\n"
        with open(site, "w") as f:
            f.write(original)
        r = FakeRunner()
        r.sh = lambda cmd, **kw: (1, "") if cmd[-1] == "-q" else (0, "")
        with mock.patch.object(se, "NGX", d), mock.patch.object(se, "ipv6_enabled", return_value=True):
            with self.assertRaises(se.StepError):
                se.fix_ipv6_listen(r)
        self.assertEqual(read(site), original)

    def test_fix_does_nothing_without_ipv6(self):
        with mock.patch.object(se, "ipv6_enabled", return_value=False):
            self.assertFalse(se.fix_ipv6_listen(FakeRunner())["changed"])


class FakeAllowlist:
    """cscli's allowlist commands against an in-memory list; every other command succeeds."""
    def __init__(self, items=None):
        self.items = {i["value"]: i for i in (items or [])}
        self.cmds = []

    def __call__(self, cmd, timeout=60):
        self.cmds.append(cmd)
        if cmd[:3] == ["cscli", "allowlists", "inspect"]:
            return 0, json.dumps({"items": list(self.items.values())})
        if cmd[:3] == ["cscli", "allowlists", "add"]:
            exp = cmd[cmd.index("-e") + 1]
            self.items[cmd[4]] = {"value": cmd[4], "description": cmd[cmd.index("-d") + 1],
                                  "expiration": self.later(int(exp.rstrip("s")))}
            return 0, "added"
        if cmd[:3] == ["cscli", "allowlists", "remove"]:
            self.items.pop(cmd[4], None)
            return 0, "removed"
        return 0, ""

    @staticmethod
    def later(seconds):
        import time
        return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + seconds))


def addrinfo(*ips):
    import socket
    return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]


class DynDNS(unittest.TestCase):
    def setUp(self):
        self.dir = mkdtemp()
        os.makedirs(os.path.join(self.dir, "etc"))
        open(os.path.join(self.dir, "etc", "mailcow.env"), "w").close()
        self.unbans = []
        self.patches = [mock.patch.multiple(se, DYNDNS_STATE=os.path.join(self.dir, "dyndns.json"), ETC_DIR=os.path.join(self.dir, "etc"),
                                            NETFILTER_STATE=os.path.join(self.dir, "netfilter.json")),
                        mock.patch.object(se, "dyndns_timer"),
                        mock.patch.object(se, "mailcow_api", side_effect=lambda m, p, b=None: self.unbans.append(b["items"][0]))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def sync(self, cscli, *ips):
        with mock.patch.object(se, "run", cscli), mock.patch.object(se.socket, "getaddrinfo", return_value=addrinfo(*ips)):
            return se.dyndns_sync()

    def add(self, cscli, name, *ips, v6prefix=64):
        with mock.patch.object(se, "run", cscli), mock.patch.object(se.socket, "getaddrinfo", return_value=addrinfo(*ips)):
            return se.dyndns_add(name, v6prefix)

    def test_resolve_keeps_public_addresses_and_widens_ipv6(self):
        with mock.patch.object(se.socket, "getaddrinfo", return_value=addrinfo("203.0.113.9", "2a01:4f8:1:2::7", "192.168.1.5", "8.8.8.8")):
            nets = se.dyndns_resolve("home.example.org", 64)
        self.assertEqual(nets, ["8.8.8.8", "2a01:4f8:1:2::/64"])  # 203.0.113.9 is documentation space: not public

    def test_resolve_refuses_odd_answers(self):
        with mock.patch.object(se.socket, "getaddrinfo", return_value=addrinfo("10.0.0.1", "127.0.0.1")):
            self.assertRaises(se.StepError, se.dyndns_resolve, "home.example.org", 64)
        many = ["8.8.8.%d" % i for i in range(1, 6)]
        with mock.patch.object(se.socket, "getaddrinfo", return_value=addrinfo(*many)):
            self.assertRaises(se.StepError, se.dyndns_resolve, "home.example.org", 64)

    def test_add_validates_the_name(self):
        for bad in ("", "localhost", "-x.example.org", "a b.example.org", "1.2.3.4"):
            self.assertRaises(se.StepError, self.add, FakeAllowlist(), bad, "8.8.8.8")

    def test_new_address_is_allowlisted_with_expiry_and_unbanned_in_netfilter(self):
        cs = FakeAllowlist()
        out = self.add(cs, "Home.Example.org.", "8.8.4.4", "2a01:4f8:1:2::7")
        self.assertEqual(out["hosts"][0]["name"], "home.example.org")
        self.assertEqual(set(cs.items), {"8.8.4.4", "2a01:4f8:1:2::/64"})
        self.assertTrue(all(i["description"] == "dyndns:home.example.org" for i in cs.items.values()))
        self.assertTrue(all(55 * 60 < se.seconds_left(i["expiration"]) <= 3600 for i in cs.items.values()))
        self.assertEqual(sorted(self.unbans), ["2a01:4f8:1:2::/64", "8.8.4.4/32"])

    def test_address_change_swaps_entries_and_records_history(self):
        cs = FakeAllowlist()
        self.add(cs, "home.example.org", "8.8.4.4")
        out = self.sync(cs, "9.9.9.9")
        self.assertEqual(set(cs.items), {"9.9.9.9"})
        self.assertEqual(out["history"][0]["added"], ["9.9.9.9"])
        self.assertEqual(out["history"][0]["removed"], ["8.8.4.4"])

    def test_renews_only_entries_close_to_expiry(self):
        cs = FakeAllowlist([{"value": "8.8.4.4", "description": "dyndns:home.example.org", "expiration": FakeAllowlist.later(600)}])
        self.add(cs, "home.example.org", "8.8.4.4")
        self.assertGreater(se.seconds_left(cs.items["8.8.4.4"]["expiration"]), 3000)
        before = len(cs.cmds)
        self.sync(cs, "8.8.4.4")  # fresh now: nothing to do
        self.assertFalse([c for c in cs.cmds[before:] if c[2] in ("add", "remove")])

    def test_resolution_failure_leaves_entries_to_lapse(self):
        cs = FakeAllowlist()
        self.add(cs, "home.example.org", "8.8.4.4")
        import socket
        with mock.patch.object(se, "run", cs), mock.patch.object(se.socket, "getaddrinfo", side_effect=socket.gaierror(-2, "Name or service not known")):
            out = se.dyndns_sync()
        self.assertIn("8.8.4.4", cs.items)  # not removed, not renewed: it expires on its own
        self.assertIn("doesn't resolve", out["hosts"][0]["error"])

    def test_leaves_manual_entries_alone(self):
        cs = FakeAllowlist([{"value": "8.8.4.4", "description": "office", "expiration": "0001-01-01T00:00:00Z"}])
        self.add(cs, "home.example.org", "8.8.4.4")
        self.assertEqual(cs.items["8.8.4.4"]["description"], "office")
        self.add(cs, "other.example.org", "9.9.9.9")
        self.sync(cs, "1.1.1.1")
        self.assertIn("8.8.4.4", cs.items)

    def test_removing_a_hostname_removes_its_entries(self):
        cs = FakeAllowlist()
        self.add(cs, "home.example.org", "8.8.4.4")
        with mock.patch.object(se, "run", cs):
            out = se.dyndns_remove("home.example.org")
        self.assertEqual(cs.items, {})
        self.assertEqual(out["hosts"], [])


class NetfilterWhitelist(unittest.TestCase):
    def test_takes_back_what_cowsec_added_but_keeps_admin_lines(self):
        d = mkdtemp()
        state = os.path.join(d, "netfilter.json")
        with open(state, "w") as f:
            json.dump({"mode": "side-by-side", "syncTrusted": True, "whitelisted": ["8.8.4.4/32", "10.0.0.0/8"]}, f)
        posted = []
        cur = {"whitelist": "8.8.4.4/32\n10.0.0.0/8\n198.51.100.0/24", "manage_external": 0}
        api = lambda m, p, b=None: cur if m == "GET" else posted.append(b["attr"]["whitelist"])
        with mock.patch.object(se, "NETFILTER_STATE", state), mock.patch.object(se, "mailcow_api", side_effect=api), \
                mock.patch.object(se, "trusted_networks", return_value=["10.0.0.0/8", "9.9.9.9/32"]):
            st = se.netfilter_sync()
        self.assertEqual(posted, ["10.0.0.0/8\n198.51.100.0/24\n9.9.9.9/32"])  # 8.8.4.4 gone, the admin's /24 kept
        self.assertEqual(st["whitelisted"], ["10.0.0.0/8", "9.9.9.9/32"])
        shutil.rmtree(d, ignore_errors=True)


class GitHubToken(unittest.TestCase):
    def setUp(self):
        se.TOKEN_NEEDED = False

    def github(self, public, token_ok=True):
        """A fake GitHub: answers anonymously for a public repository; a private one needs a valid token."""
        import urllib.error
        seen = []
        def urlopen(req, context=None, timeout=None):
            auth = req.get_header("Authorization")
            seen.append(auth)
            if public and not auth:
                return io.BytesIO(b'{"tag_name": "v9.9.9"}')
            if auth and not token_ok:
                raise urllib.error.HTTPError(req.full_url, 401, "Bad credentials", {}, None)
            if auth and not public:
                return io.BytesIO(b'{"tag_name": "v1.0.0"}')
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        return seen, urlopen

    def call(self, repo, token, urlopen):
        with mock.patch.object(se, "update_source", return_value=(repo, token)), mock.patch.object(se.urllib.request, "urlopen", side_effect=urlopen):
            return se._gh("https://api.github.com/repos/%s/releases/latest" % repo)

    def test_public_repo_never_sends_the_token(self):
        seen, urlopen = self.github(public=True, token_ok=False)
        self.assertEqual(self.call("OryxAstro/cowsec", "github_pat_expired", urlopen)["tag_name"], "v9.9.9")
        self.assertEqual(seen, [None])
        self.assertFalse(se.TOKEN_NEEDED)

    def test_private_repo_uses_the_token(self):
        seen, urlopen = self.github(public=False)
        self.assertEqual(self.call("me/private", "github_pat_good", urlopen)["tag_name"], "v1.0.0")
        self.assertEqual(seen, [None, "Bearer github_pat_good"])
        self.assertTrue(se.TOKEN_NEEDED)

    def test_private_repo_with_an_expired_token_says_so(self):
        seen, urlopen = self.github(public=False, token_ok=False)
        with self.assertRaises(se.StepError) as cm:
            self.call("me/private", "github_pat_expired", urlopen)
        self.assertIn("expired or been revoked", str(cm.exception))

    def test_private_repo_without_a_token_asks_for_one(self):
        seen, urlopen = self.github(public=False)
        with self.assertRaises(se.StepError) as cm:
            self.call("me/private", "", urlopen)
        self.assertIn("needs a read-only token", str(cm.exception))
