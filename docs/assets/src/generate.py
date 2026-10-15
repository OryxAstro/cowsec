#!/usr/bin/env python3
"""Generates the CowSec documentation artwork (SVG) in the console's visual style.

    python3 docs/assets/src/generate.py

Writes docs/assets/{banner,architecture,setup-flow,ban-ladder}.svg. The SVGs carry their own
dark background, so they look the same in GitHub's light and dark themes.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)
FONT = "'Plus Jakarta Sans','Segoe UI',Inter,system-ui,-apple-system,sans-serif"
MONO = "'JetBrains Mono','SFMono-Regular',Consolas,monospace"

ACCENT = {
    "rose": ("#fb7185", "#e11d48"),
    "indigo": ("#a5b4fc", "#6366f1"),
    "sky": ("#7dd3fc", "#0ea5e9"),
    "emerald": ("#6ee7b7", "#10b981"),
    "amber": ("#fcd34d", "#f59e0b"),
    "violet": ("#c4b5fd", "#8b5cf6"),
}


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def cow_logo(prefix, x, y, size):
    """The CowSec mark, from web/public/favicon.svg, with ids namespaced."""
    svg = open(os.path.join(OUT, "..", "..", "web", "public", "favicon.svg")).read()
    inner = svg[svg.index(">", svg.index("<svg")) + 1:svg.rindex("</svg>")]
    inner = re.sub(r'id="(\w+)"', lambda m: 'id="%s%s"' % (prefix, m.group(1)), inner)
    inner = re.sub(r"url\(#(\w+)\)", lambda m: "url(#%s%s)" % (prefix, m.group(1)), inner)
    return '<g transform="translate(%g %g) scale(%g)">%s</g>' % (x, y, size / 64.0, inner)


def defs(extra=""):
    grads = "".join(
        '<linearGradient id="g-%s" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient>'
        '<marker id="m-%s" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 10 5 0 10z" fill="%s"/></marker>'
        % (k, a, b, k, a) for k, (a, b) in ACCENT.items())
    return ('<defs>'
            '<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#050a18"/><stop offset="1" stop-color="#0b1530"/></linearGradient>'
            '<linearGradient id="title" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#ffffff"/><stop offset=".55" stop-color="#e0f2fe"/><stop offset="1" stop-color="#a5b4fc"/></linearGradient>'
            '<linearGradient id="rim" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#34d399" stop-opacity=".8"/><stop offset=".5" stop-color="#38bdf8" stop-opacity=".45"/><stop offset="1" stop-color="#818cf8" stop-opacity=".8"/></linearGradient>'
            '<filter id="blur" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="60"/></filter>'
            '<filter id="shadow" x="-10%" y="-10%" width="120%" height="130%"><feDropShadow dx="0" dy="10" stdDeviation="14" flood-color="#000" flood-opacity=".55"/></filter>'
            '<pattern id="grid" width="44" height="44" patternUnits="userSpaceOnUse"><path d="M44 0H0V44" fill="none" stroke="#94a3b8" stroke-opacity=".06"/></pattern>'
            + grads + extra + '</defs>')


def canvas(w, h, body, glow=True):
    blobs = ('<circle cx="%d" cy="%d" r="%d" fill="#6366f1" opacity=".35" filter="url(#blur)"/>'
             '<circle cx="%d" cy="%d" r="%d" fill="#0ea5e9" opacity=".22" filter="url(#blur)"/>'
             '<circle cx="%d" cy="%d" r="%d" fill="#10b981" opacity=".18" filter="url(#blur)"/>'
             % (w * .12, h * .1, h * .45, w * .92, h * .45, h * .42, w * .4, h * 1.02, h * .4)) if glow else ""
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="%s">%s'
            '<clipPath id="clip"><rect width="%d" height="%d" rx="26"/></clipPath><rect width="%d" height="%d" rx="26" fill="url(#bg)"/><g clip-path="url(#clip)">%s'
            '<rect width="%d" height="%d" fill="url(#grid)"/></g>'
            '<rect x=".75" y=".75" width="%g" height="%g" rx="25.5" fill="none" stroke="url(#rim)" stroke-width="1.5"/>%s</svg>\n'
            % (w, h, w, h, FONT, defs(), w, h, w, h, blobs, w, h, w - 1.5, h - 1.5, body))


def card(x, y, w, h, title, sub, accent, rows=(), chips=(), icon=""):
    a, b = ACCENT[accent]
    out = ['<g filter="url(#shadow)"><rect x="%g" y="%g" width="%g" height="%g" rx="18" fill="#0d152a" fill-opacity=".92" stroke="%s" stroke-opacity=".45"/></g>' % (x, y, w, h, a),
           '<rect x="%g" y="%g" width="%g" height="4" rx="2" fill="url(#g-%s)"/>' % (x + 18, y, w - 36, accent),
           '<text x="%g" y="%g" font-size="17" font-weight="800" fill="#fff">%s%s</text>' % (x + 20, y + 34, icon, esc(title))]
    if sub:
        out.append('<text x="%g" y="%g" font-size="11.5" fill="%s" font-family="%s" letter-spacing=".4">%s</text>' % (x + 20, y + 53, a, MONO, esc(sub)))
    ry = y + (76 if sub else 60)
    for label, detail in rows:
        out.append('<circle cx="%g" cy="%g" r="3.2" fill="%s"/>' % (x + 24, ry - 4, a))
        out.append('<text x="%g" y="%g" font-size="13" fill="#e2e8f0" font-weight="600">%s</text>' % (x + 36, ry, esc(label)))
        if detail:
            out.append('<text x="%g" y="%g" font-size="11" fill="#94a3b8">%s</text>' % (x + 36, ry + 16, esc(detail)))
            ry += 38
        else:
            ry += 24
    cx = x + 20
    for c in chips:
        cw = 16 + len(c) * 7.4
        if cx + cw > x + w - 16:
            cx, ry = x + 20, ry + 28
        out.append('<rect x="%g" y="%g" width="%g" height="22" rx="7" fill="%s" fill-opacity=".12" stroke="%s" stroke-opacity=".35"/>'
                   '<text x="%g" y="%g" font-size="11" fill="%s" font-family="%s">%s</text>' % (cx, ry - 14, cw, a, a, cx + 7, ry + 1, a, MONO, esc(c)))
        cx += cw + 8
    return "".join(out)


def arrow(d, accent, label=None, lx=0, ly=0, dashed=False, both=False):
    a, _ = ACCENT[accent]
    s = '<path d="%s" fill="none" stroke="%s" stroke-width="2.2" stroke-opacity=".85"%s marker-end="url(#m-%s)"%s/>' % (
        d, a, ' stroke-dasharray="7 6"' if dashed else "", accent, ' marker-start="url(#m-%s)"' % accent if both else "")
    if label:
        w = len(label) * 6.7 + 16
        s += ('<rect x="%g" y="%g" width="%g" height="22" rx="11" fill="#050a18" stroke="%s" stroke-opacity=".5"/>'
              '<text x="%g" y="%g" font-size="11" text-anchor="middle" fill="%s" font-family="%s">%s</text>' % (lx - w / 2, ly - 15, w, a, lx, ly, a, MONO, esc(label)))
    return s


# ------------------------------------------------------------------ banner
def banner():
    w, h = 1280, 340
    body = cow_logo("b", 86, 78, 184)
    body += '<text x="320" y="168" font-size="86" font-weight="800" fill="url(#title)" letter-spacing="-2">CowSec</text>'
    body += ('<rect x="326" y="52" width="196" height="30" rx="15" fill="#6366f1" fill-opacity=".16" stroke="#818cf8" stroke-opacity=".45"/>'
             '<text x="424" y="72" font-size="13" font-weight="700" text-anchor="middle" fill="#a5b4fc" font-family="%s" letter-spacing="2.5">HERD PROTECTION</text>' % MONO)
    body += '<text x="324" y="212" font-size="22" fill="#cbd5e1" font-weight="500">The browser installer and security console for CrowdSec on mailcow</text>'
    x = 324
    for txt, acc in (("CrowdSec engine", "emerald"), ("AppSec WAF", "indigo"), ("Firewall + DOCKER-USER", "rose"), ("DNS-01 · 190+ providers", "sky"), ("2FA console", "amber")):
        a, _ = ACCENT[acc]
        cw = len(txt) * 8.9 + 34
        body += ('<rect x="%g" y="246" width="%g" height="34" rx="11" fill="%s" fill-opacity=".1" stroke="%s" stroke-opacity=".45"/>'
                 '<circle cx="%g" cy="263" r="4" fill="%s"/><text x="%g" y="268.5" font-size="14" fill="#e2e8f0" font-weight="600">%s</text>' % (x, cw, a, a, x + 15, a, x + 25, esc(txt)))
        x += cw + 10
    return canvas(w, h, body)


# ------------------------------------------------------------------ architecture
def architecture():
    w, h = 1440, 1080
    b = '<text x="48" y="70" font-size="30" font-weight="800" fill="url(#title)">How CowSec protects a mailcow server</text>'
    b += '<text x="48" y="100" font-size="15" fill="#94a3b8">Layered defence: every connection meets the firewall bouncer, web traffic also meets the edge and the WAF, and every log line feeds CrowdSec.</text>'
    b += cow_logo("a", 1336, 34, 64)
    # clients
    b += card(48, 150, 250, 300, "Internet", "untrusted", "rose",
              [("Mail servers", "deliver on port 25"), ("Mail clients", "IMAP · SMTP AUTH"), ("Webmail users", "SOGo · ActiveSync"), ("Bots & scanners", "spray, probe, exploit")])
    b += card(48, 490, 250, 180, "Your LAN / tunnel", "trusted ranges", "emerald",
              [("Admins", "console · mailcow admin"), ("Never banned", "private-range whitelist")])
    # firewall
    b += card(352, 150, 290, 520, "Firewall bouncer", "iptables · ipset · CROWDSEC chain", "rose",
              [("INPUT", "host services: SSH, edge 80/443"), ("DOCKER-USER", "mailcow mail ports (Docker NAT)"), ("Community blocklist", "tens of thousands of IPs"), ("Local decisions", "from your own logs"), ("Your allowlist", "checked by the LAPI")],
              chips=("25", "465", "587", "993", "995", "143", "110", "4190", "80", "443"))
    # edge
    b += card(700, 150, 330, 300, "OpenResty edge", "ports 80 / 443", "indigo",
              [("Lua bouncer", "ban · captcha on every request"), ("AppSec WAF", "CVE virtual patches · generic rules"), ("Admin pages LAN-only", "/admin · /domainadmin"), ("Per-domain TLS", "lego DNS-01 certificates")])
    # mailcow
    b += card(700, 490, 330, 180, "mailcow-dockerized", "unchanged · update.sh safe", "sky", [],
              chips=("postfix", "dovecot", "nginx :8443", "SOGo", "rspamd", "mysql", "redis", "netfilter"))
    b += '<text x="720" y="652" font-size="11" fill="#94a3b8">web UI on 127.0.0.1 · mail ports via Docker</text>'
    # crowdsec
    b += card(1088, 150, 304, 360, "CrowdSec engine", "127.0.0.1:8080 LAPI · :7422 AppSec", "emerald",
              [("Log processor", "postfix · dovecot · edge · SSH"), ("Scenarios", "brute force, probing, CVEs"), ("cowsec/auth-abroad", "slow password sprays"), ("Profiles", "escalating ban ladder"), ("CAPI", "community blocklist in, signals out")])
    # cowsec
    b += card(1088, 550, 304, 320, "CowSec", "127.0.0.1:8090 · 2FA sign-in", "amber",
              [("Console", "bans · WAF · hub · policy · updates"), ("cowsec-hostctl", "the only privileged path, allowlisted"), ("Setup engine", "idempotent steps · backups · rollback")],
              chips=("LAN", "Cloudflare Tunnel", "Internet", "SSH only"))
    # flows
    b += arrow("M298 300 H352", "rose")
    b += arrow("M298 580 H352", "emerald")
    b += arrow("M642 290 H700", "indigo", "80/443", 671, 272)
    b += arrow("M642 590 H700", "sky", "mail", 671, 572)
    b += arrow("M865 450 V490", "indigo", "proxy", 905, 474)
    b += arrow("M1030 600 C1060 600 1060 330 1088 330", "emerald", "logs", 1060, 560, dashed=True)
    b += arrow("M1030 260 H1088", "violet", "AppSec", 1059, 242, dashed=True, both=True)
    b += arrow("M1240 510 V550", "amber", "cscli", 1278, 535, both=True)
    b += arrow("M1110 150 C1110 112 500 112 500 150", "emerald", "decisions → bouncers", 805, 118, dashed=True)
    b += arrow("M1160 150 C1160 126 890 126 890 150", "emerald", None, 0, 0, dashed=True)
    # legend
    lx, ly = 48, 900
    b += '<rect x="%d" y="%d" width="1344" height="150" rx="18" fill="#0d152a" fill-opacity=".7" stroke="#334155" stroke-opacity=".6"/>' % (lx, ly)
    b += '<text x="%d" y="%d" font-size="15" font-weight="800" fill="#fff">What happens to a password-spraying bot</text>' % (lx + 24, ly + 34)
    steps = [("1", "rose", "Tries one password on SMTP AUTH"), ("2", "emerald", "postfix logs it; CrowdSec reads it"),
             ("3", "amber", "2nd failure from abroad → auth-abroad"), ("4", "emerald", "Ban length from history: 4h … 7 days"),
             ("5", "rose", "Firewall drops it on every port"), ("6", "indigo", "Edge refuses it on 80/443 too")]
    for i, (n, acc, txt) in enumerate(steps):
        cx = lx + 24 + (i % 3) * 440
        cy = ly + 76 + (i // 3) * 40
        a, _ = ACCENT[acc]
        b += ('<circle cx="%d" cy="%d" r="11" fill="%s" fill-opacity=".18" stroke="%s"/><text x="%d" y="%d" font-size="12" font-weight="800" text-anchor="middle" fill="%s">%s</text>'
              '<text x="%d" y="%d" font-size="13" fill="#cbd5e1">%s</text>' % (cx + 11, cy - 4, a, a, cx + 11, cy, a, n, cx + 32, cy, esc(txt)))
    b += '<text x="48" y="1062" font-size="11" fill="#475569" font-family="%s">CowSec · github.com/OryxAstro/cowsec</text>' % MONO
    return canvas(w, h, b)


# ------------------------------------------------------------------ setup flow
def setup_flow():
    w, h = 1440, 410
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">From <tspan fill="#6ee7b7">apt install</tspan> to a protected server</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">The wizard runs once on https://&lt;server&gt;:9443, unlocked with a one-time token, and closes for good when you finish.</text>'
    steps = [("Checks", "OS · Docker · mailcow · ports · clock", "sky"), ("Protection", "edge + WAF · LAN-only admin · ban policy", "indigo"),
             ("Certificates", "DNS-01 · per-domain · wildcard", "emerald"), ("Access", "LAN · Tunnel · Internet · SSH", "amber"),
             ("Account", "local admin · 2FA at first sign-in", "violet"), ("Install", "live steps · backups · auto-rollback", "rose")]
    x0, y0, cw, gap = 48, 140, 206, 20
    for i, (t, d, acc) in enumerate(steps):
        x = x0 + i * (cw + gap)
        a, _ = ACCENT[acc]
        b += card(x, y0, cw, 200, t, None, acc)
        b += '<circle cx="%d" cy="%d" r="17" fill="%s" fill-opacity=".15" stroke="%s"/><text x="%d" y="%d" font-size="15" font-weight="800" text-anchor="middle" fill="%s">%d</text>' % (x + cw - 36, y0 + 30, a, a, x + cw - 36, y0 + 35, a, i + 1)
        words, line, ly = d.split(" · "), "", y0 + 84
        for wd in words:
            b += '<text x="%d" y="%d" font-size="12.5" fill="#cbd5e1">• %s</text>' % (x + 20, ly, esc(wd))
            ly += 22
        if i < len(steps) - 1:
            b += arrow("M%d %d H%d" % (x + cw + 2, y0 + 85, x + cw + gap - 2), acc)
    b += '<text x="48" y="380" font-size="12.5" fill="#64748b">Prefer the terminal? <tspan font-family="%s" fill="#a5b4fc">sudo cowsec-setup install --config cowsec.json</tspan> runs the same steps.</text>' % MONO
    return canvas(w, h, b)


# ------------------------------------------------------------------ ban ladder
def ban_ladder():
    w, h = 1280, 420
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">Escalating bans</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">Each ban looks back 7 days. Repeat offenders from abroad climb the ladder; home-country IPs stay on the first rung.</text>'
    rungs = [("1st", "4h"), ("2nd", "8h"), ("3rd", "16h"), ("4th", "32h"), ("5th", "64h"), ("6th", "128h"), ("7th+", "7 days")]
    base, x0, bw, gap = 330, 60, 150, 22
    for i, (n, d) in enumerate(rungs):
        hgt = 40 + i * 30
        x = x0 + i * (bw + gap)
        t = i / (len(rungs) - 1)
        col = "#%02x%02x%02x" % (int(16 + t * (244 - 16)), int(185 - t * (185 - 63)), int(129 - t * (129 - 94)))
        b += '<rect x="%d" y="%d" width="%d" height="%d" rx="12" fill="%s" fill-opacity=".22" stroke="%s"/>' % (x, base - hgt, bw, hgt, col, col)
        b += '<text x="%d" y="%d" font-size="20" font-weight="800" text-anchor="middle" fill="#fff">%s</text>' % (x + bw / 2, base - hgt + 30, d)
        b += '<text x="%d" y="%d" font-size="12" text-anchor="middle" fill="#94a3b8" font-family="%s">%s ban</text>' % (x + bw / 2, base + 24, MONO, n)
    b += '<text x="48" y="396" font-size="12.5" fill="#64748b">Double or linear steps, first ban and cap are configurable in Herd Rules. Burst alerts from one attack count once.</text>'
    return canvas(w, h, b)


# ------------------------------------------------------------------ page headers
PAGES = {
    "install": ("Requirements & headless install", "What CowSec needs, what it changes, and installing from a config file", "sky", ["Debian · Ubuntu", "amd64", "mailcow-dockerized", "idempotent"]),
    "access": ("Console access", "LAN, Cloudflare Tunnel, internet or SSH only: you choose who can reach the sign-in page", "emerald", ["LAN", "Cloudflare Tunnel", "Internet", "SSH only"]),
    "certificates": ("Certificates", "DNS-01 through 190+ DNS providers, one certificate per domain, renewed automatically", "sky", ["lego", "DNS-01", "wildcards", "per-domain SNI"]),
    "ban-policy": ("Ban policy", "Home countries, the abroad login rule, escalating bans and your trusted herd", "amber", ["home countries", "auth-abroad", "4h → 7 days", "allowlists"]),
    "security": ("Security model", "How CowSec protects itself: privileges, sign-in, the setup token and what leaves the server", "violet", ["root + allowlist", "2FA", "CSRF", "no telemetry"]),
    "maintenance": ("Maintenance", "Updating CowSec, CrowdSec and the hub, changing your choices, reverting and uninstalling", "indigo", ["signed packages", "backups", "revert-edge", "apt remove"]),
    "troubleshooting": ("Troubleshooting", "Where to look first, and fixes for the problems people actually hit", "rose", ["lock-outs", "clocks", "certificates", "OpenResty"]),
    "architecture": ("Architecture", "How the console, the helper, CrowdSec, the edge and mailcow fit together", "emerald", ["Go", "Python", "React", "CrowdSec"]),
    "mailcow": ("Managing mailcow", "Domains, mailboxes, aliases, DKIM, quarantine, the mail queue and logs, from CowSec", "sky", ["mailcow API", "validated", "audited", "localhost only"]),
}


def page_header(key):
    title, sub, acc, chips = PAGES[key]
    w, h = 1280, 200
    a, _ = ACCENT[acc]
    b = cow_logo("h" + key.replace("-", ""), 52, 44, 112)
    b += '<rect x="200" y="50" width="56" height="5" rx="2.5" fill="url(#g-%s)"/>' % acc
    b += '<text x="200" y="98" font-size="38" font-weight="800" fill="url(#title)" letter-spacing="-.5">%s</text>' % esc(title)
    b += '<text x="200" y="128" font-size="15.5" fill="#94a3b8">%s</text>' % esc(sub)
    x = 200
    for c in chips:
        cw = len(c) * 7.6 + 26
        b += ('<rect x="%g" y="146" width="%g" height="26" rx="9" fill="%s" fill-opacity=".1" stroke="%s" stroke-opacity=".4"/>'
              '<text x="%g" y="163.5" font-size="12" fill="%s" font-family="%s">%s</text>' % (x, cw, a, a, x + 13, a, MONO, esc(c)))
        x += cw + 8
    return canvas(w, h, b)


# ------------------------------------------------------------------ access modes
def access_modes():
    w, h = 1440, 560
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">Four ways to reach the console</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">The console always listens on 127.0.0.1:8090. The access mode decides what, if anything, publishes it.</text>'
    modes = [("Local network", "emerald", "LAN only", ["your browser on the LAN", "OpenResty :443 · allow LAN ranges", "everyone else: 403"], "Most homes and offices"),
             ("Cloudflare Tunnel", "amber", "no open ports", ["your browser anywhere", "Cloudflare Access login", "cloudflared dials out"], "Remote access, safest"),
             ("Internet", "rose", "public sign-in page", ["anyone", "CrowdSec + WAF + rate limits", "password + 2FA"], "When a tunnel isn't possible"),
             ("This server only", "sky", "nothing exposed", ["ssh -L 8090:127.0.0.1:8090", "your laptop: localhost:8090", "zero network exposure"], "Maximum lock-down")]
    cw, gap, y0 = 318, 22, 130
    for i, (t, acc, tag, steps, best) in enumerate(modes):
        x = 48 + i * (cw + gap)
        a, _ = ACCENT[acc]
        b += card(x, y0, cw, 380, t, tag, acc)
        yy = y0 + 100
        for j, st in enumerate(steps):
            b += '<rect x="%d" y="%d" width="%d" height="46" rx="12" fill="%s" fill-opacity=".08" stroke="%s" stroke-opacity=".35"/>' % (x + 20, yy, cw - 40, a, a)
            b += '<text x="%d" y="%d" font-size="13" fill="#e2e8f0" text-anchor="middle">%s</text>' % (x + cw / 2, yy + 28, esc(st))
            if j < len(steps) - 1:
                b += arrow("M%d %d V%d" % (x + cw / 2, yy + 47, yy + 66), acc)
            yy += 70
        b += '<text x="%d" y="%d" font-size="12.5" fill="%s" font-weight="700" text-anchor="middle">%s</text>' % (x + cw / 2, y0 + 360, a, esc(best))
    b += '<text x="48" y="540" font-size="12.5" fill="#64748b">Switch any time: <tspan font-family="%s" fill="#a5b4fc">sudo cowsec-setup access lan|tunnel|wan|local</tspan></text>' % MONO
    return canvas(w, h, b)


# ------------------------------------------------------------------ certificates
def cert_flow():
    w, h = 1440, 600
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">DNS-01 certificates, end to end</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">No port 80: Let&apos;s Encrypt checks a TXT record in your DNS. The daily timer renews and only redeploys when something changed.</text>'
    b += card(48, 130, 250, 200, "lego", "on your server", "emerald", [("Requests a certificate", "per domain, with wildcards"), ("Writes a TXT record", "via your provider's API")])
    b += card(360, 130, 250, 200, "Your DNS provider", "190+ supported", "sky", [("_acme-challenge TXT", "created, then removed"), ("Credentials root-only", "/etc/cowsec/dns.env")])
    b += card(672, 130, 250, 200, "Let's Encrypt", "ACME", "indigo", [("Checks the TXT record", "at authoritative servers"), ("Issues the certificate", "90 days, renewed early")])
    b += card(984, 130, 408, 200, "Deployed to", "per-hostname SNI", "amber", [("Web: OpenResty edge", "one server block per domain"), ("IMAP: dovecot SNI folders", "data/assets/ssl/<domain>/"), ("SMTP: postfix SNI map", "extra.cf · cowsec_sni.map")])
    b += arrow("M298 230 H360", "emerald", "TXT", 329, 212)
    b += arrow("M610 230 H672", "sky", "verify", 641, 212)
    b += arrow("M922 230 H984", "indigo", "cert", 953, 212)
    # per-domain vs shared
    b += '<text x="48" y="392" font-size="18" font-weight="800" fill="#fff">Why one certificate per domain</text>'
    b += card(48, 412, 650, 150, "Shared certificate", "what a visitor to mail.example.org sees", "rose", [], chips=("example.com", "example.org", "client-one.co.uk", "client-two.com", "family.net", "…every domain"))
    b += card(742, 412, 650, 150, "One per domain (default)", "what a visitor to mail.example.org sees", "emerald", [], chips=("example.org", "*.example.org"))
    b += '<text x="1066" y="530" font-size="12.5" fill="#94a3b8" text-anchor="middle">Your other domains stay private.</text>'
    b += '<text x="374" y="550" font-size="12.5" fill="#94a3b8" text-anchor="middle">Anyone can list everyone you host.</text>'
    return canvas(w, h, b)


# ------------------------------------------------------------------ security model
def security_layers():
    w, h = 1440, 620
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">Layers between a browser and your server</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">Each layer has to be passed in order. Secrets stay in root-only files and never reach the browser or the logs.</text>'
    layers = [("Network", "rose", "access mode · firewall bouncer · edge bouncer · AppSec WAF"),
              ("TLS", "sky", "HTTPS for every connection that leaves the server · modern TLS only"),
              ("Sign-in", "indigo", "local account or LDAP · rate limits per IP and per user · audit log"),
              ("Second factor", "violet", "TOTP with replay protection, or Duo Push · always required"),
              ("Session", "amber", "HttpOnly + SameSite=Strict cookie · idle and absolute timeouts · CSRF header"),
              ("Privileged work", "emerald", "cowsec-hostctl: a fixed allowlist of verbs · jobs in transient systemd units")]
    y = 128
    for i, (t, acc, d) in enumerate(layers):
        a, _ = ACCENT[acc]
        inset = i * 26
        b += '<g filter="url(#shadow)"><rect x="%d" y="%d" width="%d" height="62" rx="16" fill="#0d152a" fill-opacity=".92" stroke="%s" stroke-opacity=".5"/></g>' % (48 + inset, y, 860 - 2 * inset, a)
        b += '<rect x="%d" y="%d" width="5" height="38" rx="2.5" fill="url(#g-%s)"/>' % (66 + inset, y + 12, acc)
        b += '<text x="%d" y="%d" font-size="16" font-weight="800" fill="#fff">%s</text>' % (86 + inset, y + 28, esc(t))
        b += '<text x="%d" y="%d" font-size="12.5" fill="#94a3b8">%s</text>' % (86 + inset, y + 48, esc(d))
        y += 76
    b += card(960, 128, 432, 280, "Secrets vault", "root-only, mode 0600", "amber",
              [("/etc/cowsec/cowsec.env", "LDAP bind, Duo keys"), ("/etc/cowsec/dns.env", "DNS provider credentials"), ("/etc/cowsec/mailcow.env", "mailcow API key"), ("/var/lib/cowsec/", "accounts, TOTP, sessions, certificates")])
    b += card(960, 430, 432, 160, "Nothing phones home", "no telemetry", "emerald", [("GeoIP and fonts are local", ""), ("Downloads: signed repos, pinned hashes", "")])
    return canvas(w, h, b)


# ------------------------------------------------------------------ maintenance
def upgrade_flow():
    w, h = 1440, 330
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">Safe upgrades from Fresh Hay</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">Every upgrade runs as a background job with a live log; your configuration files are kept.</text>'
    steps = [("Check", "apt-get update", "sky"), ("Back up", "/etc/crowdsec → tgz", "amber"), ("Upgrade", "keep your configs", "indigo"),
             ("Test", "crowdsec -t · openresty -t", "violet"), ("Restart", "engine · bouncer · edge", "emerald"), ("Verify", "services · LAPI status", "emerald")]
    cw, gap = 206, 20
    for i, (t, d, acc) in enumerate(steps):
        x = 48 + i * (cw + gap)
        b += card(x, 130, cw, 130, t, None, acc)
        b += '<text x="%d" y="%d" font-size="12.5" fill="#cbd5e1">%s</text>' % (x + 20, 214, esc(d))
        if i < len(steps) - 1:
            b += arrow("M%d 195 H%d" % (x + cw + 2, x + cw + gap - 2), acc)
    b += '<text x="48" y="300" font-size="12.5" fill="#64748b">If the configuration test fails, nothing is restarted. Your previous configuration is in the backup tarball.</text>'
    return canvas(w, h, b)


# ------------------------------------------------------------------ troubleshooting
def where_to_look():
    w, h = 1440, 420
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">Where to look first</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">Most problems show up in one of these places within a minute.</text>'
    items = [("Locked out?", "rose", ["cscli decisions delete --ip <ip>", "cscli allowlists add cowsec <ip>"]),
             ("2FA codes rejected?", "amber", ["timedatectl", "cowsec auth totp reset <user>"]),
             ("Setup or upgrade failed?", "indigo", ["/var/lib/cowsec/jobs/*.log", "journalctl -t cowsec-hostctl"]),
             ("Console won't load?", "sky", ["systemctl status cowsec", "journalctl -u cowsec -n 100"]),
             ("Web or WAF problem?", "violet", ["journalctl -u openresty", "openresty -t"]),
             ("Bans not biting?", "emerald", ["iptables -S DOCKER-USER", "cscli metrics"])]
    cw, ch = 432, 120
    for i, (t, acc, cmds) in enumerate(items):
        x = 48 + (i % 3) * (cw + 24)
        y = 130 + (i // 3) * (ch + 22)
        b += card(x, y, cw, ch, t, None, acc)
        for j, c in enumerate(cmds):
            b += '<text x="%d" y="%d" font-size="12.5" fill="#cbd5e1" font-family="%s">$ %s</text>' % (x + 20, y + 72 + j * 22, MONO, esc(c))
    return canvas(w, h, b)


# ------------------------------------------------------------------ mailcow management
def mailcow_flow():
    w, h = 1440, 470
    b = '<text x="48" y="64" font-size="28" font-weight="800" fill="url(#title)">Managing mailcow without its admin UI</text>'
    b += '<text x="48" y="94" font-size="14.5" fill="#94a3b8">CowSec calls mailcow&apos;s own API on localhost. Only validated operations are exposed, and every change lands in CowSec&apos;s audit log.</text>'
    b += card(48, 130, 330, 290, "You, in CowSec", "2FA sign-in", "amber", [("Farmhouse", "containers · versions · storage"), ("Paddocks · Stalls · Ear Tags", "domains · mailboxes · aliases"), ("Brand Irons", "DKIM keys + DNS records"), ("Quarantine · Milk Queue · Farm Log", "release · retry · read")])
    b += card(470, 160, 330, 230, "CowSec server", "127.0.0.1:8090", "emerald", [("Validates every field", "domains, addresses, quotas"), ("Fixed set of operations", "no raw API pass-through"), ("Audit log", "who changed what, when")])
    b += card(892, 130, 500, 290, "mailcow API", "https://127.0.0.1 · X-API-Key", "sky", [("Key stays root-only", "/etc/cowsec/mailcow.env"), ("API_ALLOW_FROM", "localhost + mailcow's Docker gateway"), ("Existing key reused", "your other tools keep working")],
              chips=("domains", "mailboxes", "aliases", "dkim", "quarantine", "mailq", "logs", "status"))
    b += arrow("M378 275 H470", "amber", "HTTPS", 424, 257)
    b += arrow("M800 275 H892", "emerald", "API", 846, 257)
    b += '<text x="48" y="450" font-size="12.5" fill="#64748b">Enable it in the setup wizard, or on an existing install: <tspan font-family="%s" fill="#a5b4fc">sudo cowsec-setup mailcow-api</tspan></text>' % MONO
    return canvas(w, h, b)


if __name__ == "__main__":
    jobs = [("banner", banner), ("architecture", architecture), ("setup-flow", setup_flow), ("ban-ladder", ban_ladder),
            ("access-modes", access_modes), ("cert-flow", cert_flow), ("security-layers", security_layers), ("upgrade-flow", upgrade_flow),
            ("where-to-look", where_to_look), ("mailcow-flow", mailcow_flow)]
    jobs += [("header-" + k, (lambda k: lambda: page_header(k))(k)) for k in PAGES]
    for name, fn in jobs:
        with open(os.path.join(OUT, name + ".svg"), "w") as f:
            f.write(fn())
        print("wrote docs/assets/%s.svg" % name)
