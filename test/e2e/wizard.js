// Drives the setup wizard from unlock to "The barn is built", taking screenshots on the way.
// Works for both paths: protecting an existing mailcow, and installing mailcow on a bare server
// (setup.mode = "existing" | "bare"). Copes with Debian 13, where the edge isn't offered yet.
// Exit codes: 0 installed, 1 the script broke, 2 the installer reported a failure.
//   COWSEC_E2E_CONFIG=config.json node wizard.js [outdir]
const fs = require('fs');
const path = require('path');
const { loadConfig, browser, snap } = require('./lib');

(async () => {
  const cfg = loadConfig();
  const s = cfg.setup || {};
  const { b, p, errors } = await browser(cfg);
  const next = async () => { await p.click('button:has-text("Next")'); await p.waitForTimeout(500); };
  try {
    await p.goto(s.url);
    await p.waitForSelector('text=Open the gate');
    await snap(p, cfg, 'unlock', false);
    await p.fill('input', s.token);
    await p.click('button:has-text("Unlock setup")');
    await p.waitForSelector('text=Run the checks again', { timeout: 180000 });
    await snap(p, cfg, 'checks');

    await next();
    if (s.mode === 'bare') {
      await p.waitForSelector('text=Install mailcow, then protect it');
      await p.fill('input[placeholder="mail.example.com"]', s.mailHost);
    } else {
      await p.waitForSelector('text=Protect my existing mailcow');
    }
    await snap(p, cfg, 'mailserver');

    await next();
    await p.waitForSelector('text=Home countries');
    const noEdge = (await p.locator('text=not available on Debian 13 yet').count()) > 0;
    console.log('edge available:', !noEdge);
    await snap(p, cfg, 'protection');

    await next();
    if (noEdge) {
      await p.waitForSelector("text=mailcow's own Let's Encrypt");
    } else {
      // DNS-01: pick the provider, then fill its credentials by variable name
      const dns = s.dns || {};
      await p.waitForSelector('input[placeholder^="Search, e.g. cloudflare"]', { timeout: 180000 });
      await p.fill('input[placeholder^="Search, e.g. cloudflare"]', dns.provider);
      await p.click(`button.font-mono:text-is("${dns.provider}")`);
      for (const [name, value] of Object.entries(dns.env || {})) {
        await p.waitForSelector(`text=${name}`, { timeout: 60000 });
        await p.locator(`label:has-text("${name}") input, xpath=//*[text()="${name}"]/following::input[1]`).first().fill(value);
      }
      await p.fill('input[type=email]', s.email);
      if (s.staging) await p.click('label:has-text("Test run") button[role=switch]');
    }
    await snap(p, cfg, 'certificates');

    await next();
    await p.waitForSelector('text=How you reach the console');
    if (!noEdge && s.consoleHost) await p.fill('input[placeholder="cowsec.example.com"]', s.consoleHost);
    await snap(p, cfg, 'access');

    await next();
    await p.waitForSelector('text=Your admin account');
    await p.fill('input[autocomplete=username]', cfg.console.user);
    const pw = p.locator('input[type=password]');
    await pw.nth(0).fill(cfg.console.password);
    await pw.nth(1).fill(cfg.console.password);
    await p.click('button:has-text("Create account")');
    await p.waitForSelector('text=Account created');

    await next();
    await p.waitForSelector('text=Ready to install');
    const backup = p.locator('label:has-text("I have a recent backup") input[type=checkbox]');
    if (await backup.count()) await backup.check();
    await snap(p, cfg, 'review');

    await p.click('button:has-text("Install")');
    await p.waitForSelector('text=Raising the barn', { timeout: 60000 });
    await p.waitForTimeout(25000);
    await snap(p, cfg, 'installing');
    const minutes = s.mode === 'bare' ? 75 : 30;
    await p.waitForFunction(() => /All done|Installation stopped/.test(document.body.innerText), null, { timeout: minutes * 60000, polling: 3000 });
    const failed = (await p.locator('text=Installation stopped').count()) > 0;
    fs.writeFileSync(path.join(cfg.out, 'install-log.txt'), await p.evaluate(() => (document.querySelector('pre') || {}).innerText || ''));
    // never put a real generated password in a screenshot
    await p.evaluate(() => document.querySelectorAll('code.select-all').forEach((e) => { e.textContent = 'Xq7-·····-example'; }));
    await snap(p, cfg, failed ? 'install-FAILED' : 'installed');
    if (failed) {
      console.log('INSTALL FAILED (see install-log.txt)');
      process.exitCode = 2;
      return;
    }
    await p.click('button:has-text("Finish and close setup")');
    await p.waitForSelector('text=The barn is built');
    await snap(p, cfg, 'finished', false);
    console.log('INSTALL OK');
  } catch (e) {
    console.error('FAILED:', e.message);
    await snap(p, cfg, 'script-error').catch(() => {});
    process.exitCode = 1;
  } finally {
    console.log('page errors:', errors.length ? '\n' + errors.join('\n') : 'none');
    await b.close();
  }
})();
