// Shared helpers for CowSec's end-to-end tests: config, browser, sign-in (with 2FA enrolment),
// screenshots with real names and addresses replaced, API calls and pass/fail reporting.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { chromium } = require('playwright');

// Config: a JSON file named by COWSEC_E2E_CONFIG, or the first argument. See config.example.json.
//   COWSEC_E2E_CONFIG=config.json node <test>.js [outdir]
//   node <test>.js config.json [outdir]
function loadConfig() {
  const args = process.argv.slice(2);
  const file = process.env.COWSEC_E2E_CONFIG || args.shift();
  if (!file) {
    console.error('Usage: COWSEC_E2E_CONFIG=config.json node <test>.js [outdir]');
    process.exit(64);
  }
  const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
  cfg.out = process.env.COWSEC_E2E_OUT || args[0] || path.join(process.cwd(), 'out');
  fs.mkdirSync(cfg.out, { recursive: true });
  return cfg;
}

function totp(secret, at = Date.now()) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.toUpperCase().replace(/=+$/, '')) bits += a.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const d = crypto.createHmac('sha1', key).update(msg).digest();
  const o = d[d.length - 1] & 15;
  return String((d.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

async function browser(cfg) {
  const args = [];
  // reach the console by its name at a given address, without touching DNS
  if (cfg.console && cfg.console.ip) args.push(`--host-resolver-rules=MAP ${new URL(cfg.console.url).hostname} ${cfg.console.ip}`);
  const b = await chromium.launch({ args });
  const ctx = await b.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true, locale: 'en-GB', colorScheme: cfg.colorScheme || 'dark' });
  const p = await ctx.newPage();
  const errors = [];
  p.on('pageerror', (e) => errors.push('JS: ' + e.message));
  p.on('console', (m) => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
  p.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) errors.push(`${r.status()} ${r.url()}`); });
  return { b, ctx, p, errors };
}

// Sign in to the console. After `sudo cowsec auth totp reset <user>` this also enrols 2FA;
// otherwise give the account's TOTP secret as console.totpSecret.
async function signIn(p, cfg) {
  let secret = cfg.console.totpSecret || null;
  p.on('response', async (r) => {
    if (r.url().endsWith('/api/auth/login') && r.status() === 200) {
      try { secret = (await r.json()).secret || secret; } catch { /* not JSON */ }
    }
  });
  await p.goto(cfg.console.url + '/');
  await p.waitForSelector('text=Open the barn door', { timeout: 60000 });
  await p.fill('input[autocomplete=username], input[type=text], input[type=email]', cfg.console.user);
  await p.fill('input[type=password]', cfg.console.password);
  await p.click('button[type=submit]');
  for (let i = 0; i < 40 && !secret; i++) await p.waitForTimeout(250);
  if (!secret) throw new Error('no TOTP secret: reset 2FA first (sudo cowsec auth totp reset ' + cfg.console.user + ') or set console.totpSecret');
  const code = p.locator('input[inputmode="numeric"], input[autocomplete="one-time-code"]').first();
  await code.waitFor({ timeout: 30000 });
  await code.click();
  await p.keyboard.type(totp(secret), { delay: 40 });
  await p.keyboard.press('Enter');
  await p.waitForSelector('text=Barn Status', { timeout: 30000 });
  return secret;
}

async function go(p, cfg, hash, wait) {
  await p.goto(`${cfg.console.url}/#/${hash}`);
  await p.waitForSelector(`text=${wait}`, { timeout: 90000 });
  await p.waitForTimeout(1500);
}

// Before each screenshot, swap real names and LAN addresses for documentation values.
async function sanitize(p, cfg) {
  const s = cfg.sanitize || {};
  const subs = [...(s.domains || []).map((d) => [d, 'example.com']), ...(s.ips || []).map((ip) => [ip, '192.0.2.10'])];
  await p.evaluate((pairs) => {
    const res = pairs.map(([from, to]) => [new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), to]);
    res.push([/192\.168\.\d+\.\d+/g, '192.0.2.1'], [/\b10\.\d+\.\d+\.\d+\b/g, '192.0.2.2']);
    const fix = (t) => res.reduce((acc, [re, to]) => acc.replace(re, to), t);
    const undo = (window.__undo = []);
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      if (n.nodeValue) { const o = n.nodeValue, f = fix(o); if (f !== o) { undo.push(() => { n.nodeValue = o; }); n.nodeValue = f; } }
    }
    document.querySelectorAll('input').forEach((i) => {
      if (i.type !== 'password' && i.value) { const o = i.value; i.value = fix(o); undo.push(() => { i.value = o; }); }
    });
  }, subs);
}

let shot = 0;
async function snap(p, cfg, name, full = true) {
  await p.waitForTimeout(400);
  await sanitize(p, cfg);
  const file = path.join(cfg.out, `${String(++shot).padStart(2, '0')}-${name}.png`);
  await p.screenshot({ path: file, fullPage: full });
  await p.evaluate(() => (window.__undo || []).forEach((f) => f()));
  console.log('shot', file);
}

// fetch from inside the signed-in page, so cookies and CSRF behave as in real use
function api(p) {
  return (method, url, body) => p.evaluate(async ([m, u, b]) => {
    const r = await fetch(u, { method: m, headers: b ? { 'Content-Type': 'application/json' } : {}, body: b ? JSON.stringify(b) : undefined });
    const t = await r.text();
    let j;
    try { j = JSON.parse(t); } catch { j = t; }
    return { status: r.status, body: j };
  }, [method, url, body]);
}

function reporter() {
  const results = { pass: 0, fail: 0, failures: [] };
  const check = (name, cond, extra) => {
    if (cond) results.pass++;
    else { results.fail++; results.failures.push(name); }
    console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${!cond && extra !== undefined ? ' :: ' + JSON.stringify(extra).slice(0, 400) : ''}`);
    return cond;
  };
  const done = () => {
    console.log(`\n${results.pass} passed, ${results.fail} failed`);
    if (results.fail) console.log('failed: ' + results.failures.join(', '));
    return results.fail ? 1 : 0;
  };
  return { check, done, results };
}

module.exports = { loadConfig, totp, browser, signIn, go, snap, sanitize, api, reporter };
