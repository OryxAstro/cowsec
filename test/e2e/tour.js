// Read-only tour of every console page: opens each one, screenshots it and fails if a page throws
// a JavaScript error or an API call answers 5xx. Changes nothing, so it is safe on any server.
//   COWSEC_E2E_CONFIG=config.json node tour.js [outdir]
// Set COWSEC_E2E_THEME=light for the light theme.
const { loadConfig, browser, signIn, snap, reporter } = require('./lib');

const PAGES = [
  'host', 'updates', 'decisions', 'policy', 'appsec', 'whitelists', 'netfilter',
  'farm', 'health', 'trail', 'domains', 'mailboxes', 'aliases', 'quarantine', 'queue', 'lookout', 'ribbons', 'maillogs',
  'farmhands', 'ratelimits', 'tls', 'routes',
  'alerts', 'hub', 'topology', 'help', 'about',
];

(async () => {
  const cfg = loadConfig();
  if (process.env.COWSEC_E2E_THEME === 'light') cfg.colorScheme = 'light';
  const { b, p, errors } = await browser(cfg);
  const { check, done } = reporter();
  try {
    await signIn(p, cfg);
    if (cfg.colorScheme === 'light') {
      await p.evaluate(() => localStorage.setItem('cowsec_theme', 'mint'));
      await p.reload();
      await p.waitForSelector('text=Barn Status', { timeout: 30000 });
    }
    await snap(p, cfg, 'barn-status');
    for (const page of PAGES) {
      const before = errors.length;
      await p.goto(`${cfg.console.url}/#/${page}`);
      await p.waitForSelector('main', { timeout: 60000 });
      await p.waitForTimeout(4000); // let the page's first API calls land
      await snap(p, cfg, page);
      const fresh = errors.slice(before).filter((e) => e.startsWith('JS:') || /^5\d\d /.test(e));
      check(`page ${page}`, fresh.length === 0, fresh);
    }
    await p.click('button[title^="Signed in as"]');
    await p.waitForTimeout(1500);
    await snap(p, cfg, 'settings', false);
  } catch (e) {
    check('tour completed', false, e.message);
  } finally {
    await b.close();
    process.exit(done());
  }
})();
