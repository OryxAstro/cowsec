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
SCRATCH = tempfile.mkdtemp(prefix="cowsec-test-")
atexit.register(shutil.rmtree, SCRATCH, ignore_errors=True)
os.environ["COWSEC_STATE_DIR"] = os.path.join(SCRATCH, "state")
os.makedirs(os.environ["COWSEC_STATE_DIR"], exist_ok=True)
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


class SafetyNet(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(dir=SCRATCH)
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
        self.root = tempfile.mkdtemp(dir=SCRATCH)
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
