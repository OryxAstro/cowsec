// API regression checks against a running CowSec console. Creates its own throwaway domain
// (e2e-<random>.test) and mailbox, exercises the mail features, mailbox security, the mail WAF
// and deliverability, then deletes everything it made. Exit code 1 if any check fails.
//   COWSEC_E2E_CONFIG=config.json node checks.js [outdir]
const { loadConfig, browser, signIn, api: apiOf, reporter } = require('./lib');

(async () => {
  const cfg = loadConfig();
  const { b, p, errors } = await browser(cfg);
  const { check, done } = reporter();
  const tag = Math.random().toString(36).slice(2, 8);
  const D = `e2e-${tag}.test`;
  const U = `postmaster@${D}`;
  const E = encodeURIComponent(U);
  let api;
  try {
    await signIn(p, cfg);
    api = apiOf(p);
    const mc = (m, path, body) => api(m, '/api/mailcow' + path, body);

    // ---- a throwaway domain and mailbox
    let r = await mc('POST', '/domains', { domain: D, description: 'CowSec e2e test (safe to delete)', mailboxes: 5, aliases: 10, quota: 2048, defquota: 256, maxquota: 512 });
    if (!check('create test domain', r.status === 200, r.body)) throw new Error('cannot continue without a test domain');
    r = await mc('POST', '/mailboxes', { local_part: 'postmaster', domain: D, name: 'E2E', password: 'E2e-' + tag + '-Passw0rd', quota: 256 });
    if (!check('create test mailbox', r.status === 200, r.body)) throw new Error('cannot continue without a test mailbox');

    // ---- Phase 3a: mailboxes and domains
    r = await mc('PATCH', `/mailboxes/${E}`, { force_tfa: true, sender_acl: [`@${D}`] });
    r = await mc('GET', `/mailboxes/${E}`);
    check('2FA required and send-as stored', r.body.attributes?.force_tfa === '1' && (r.body.sender_acl || []).includes(`@${D}`), r.body);
    await mc('PATCH', `/mailboxes/${E}`, { tags: ['moo', 'barn'] });
    await mc('PATCH', `/mailboxes/${E}`, { tags: ['moo'] });
    r = await mc('GET', `/mailboxes/${E}`);
    check('removed tag is removed in mailcow', JSON.stringify(r.body.tags) === '["moo"]', r.body.tags);
    r = await mc('PUT', `/mailboxes/${E}/spam-score`, { junk: 6, reject: 12 });
    r = await mc('GET', `/mailboxes/${E}/spam-score`);
    check('spam score', r.body.score === '6,12', r.body);
    r = await mc('POST', `/mailboxes/${E}/app-passwords`, { name: 'e2e phone', protocols: ['imap', 'smtp'] });
    check('app password generated', /^[A-Za-z0-9]{6}(-[A-Za-z0-9]{6}){3}$/.test(r.body.password || ''), r.body);
    r = await mc('GET', `/mailboxes/${E}/app-passwords`);
    const ap = (r.body || [])[0];
    check('app password listed without its hash', ap && !('password' in ap), r.body);
    if (ap) check('app password paused', (await mc('PATCH', `/mailboxes/${E}/app-passwords/${ap.id}`, { active: false })).status === 200);
    r = await mc('POST', `/mailboxes/${E}/spam-aliases`, { domain: D, description: 'e2e shop', hours: 24 });
    r = await mc('GET', `/mailboxes/${E}/spam-aliases`);
    const sa = (r.body || []).find((a) => a.description === 'e2e shop');
    check('disposable address', !!sa, r.body);
    if (sa) check('disposable address made permanent', (await mc('PATCH', `/spam-aliases/${encodeURIComponent(sa.address)}`, { permanent: true })).status === 200);
    r = await mc('PUT', `/domains/${D}/footer`, { html: '<p>Moo Ltd</p>', plain: 'Moo Ltd', skip_replies: true, exclude: [] });
    r = await mc('GET', `/domains/${D}/footer`);
    check('footer saved and read back', r.body.plain === 'Moo Ltd' && r.body.skip_replies === true, r.body);
    r = await mc('POST', '/alias-domains', { alias_domain: `alias-${tag}.test`, target_domain: D, active: true });
    check('alias domain', r.status === 200, r.body);
    r = await mc('POST', '/policies', { scope: 'mailbox', target: U, from: 'friend@example.net', list: 'wl' });
    r = await mc('GET', `/policies?scope=mailbox&target=${E}`);
    check('sender allow list', (r.body.wl || []).some((x) => x.value === 'friend@example.net'), r.body);
    r = await mc('GET', `/dkim/${D}`);
    const sel = r.body.dkim_selector || 'dkim';
    r = await mc('POST', `/dkim/${D}/rotation`, { selector: sel, key_size: 2048 });
    check('DKIM rotation refuses the current selector', r.status === 400, r.body);
    r = await mc('POST', `/dkim/${D}/rotation`, { selector: 'e2e' + tag, key_size: 2048 });
    check('DKIM rotation prepares a key', r.status === 200 && /p=MII/.test(r.body.rotation?.value || ''), r.body);
    r = await mc('POST', `/dkim/${D}/rotation/finish`, {});
    check('DKIM rotation waits for DNS', r.status === 409, r.body);
    await mc('DELETE', `/dkim/${D}/rotation`);

    // ---- quarantine preview (only if something is held)
    r = await mc('GET', '/quarantine');
    const q = (r.body || [])[0];
    if (q) {
      r = await mc('GET', `/quarantine/${q.id}`);
      check('quarantine preview hides the raw message', r.status === 200 && r.body.preview && !('msg' in r.body), Object.keys(r.body || {}));
    } else console.log('SKIP quarantine preview (nothing held)');

    // ---- Phase 3b: mailbox security, lock-down and undo
    r = await mc('GET', `/mailboxes/${E}/security`);
    check('security view', r.status === 200 && Array.isArray(r.body.logins) && Array.isArray(r.body.failures), r.body);
    r = await mc('POST', `/mailboxes/${E}/lockdown`, { disable_login: true, force_password: true, pause_app_passwords: true, clear_devices: true, throttle: true, ban_ips: ['203.0.113.77'], ban_duration: '24h' });
    check('lock-down ran every step', r.status === 200 && (r.body.steps || []).every((s) => s.ok), r.body.steps || r.body);
    r = await mc('GET', `/mailboxes/${E}`);
    check('sign-in disabled, mail still accepted', String(r.body.active) === '2', r.body.active);
    r = await mc('GET', '/lookout');
    check('Lookout lists the lock-down', (r.body.lockdowns || []).some((l) => l.user === U), r.body.lockdowns);
    r = await mc('POST', `/mailboxes/${E}/lockdown/undo`, { restore_login: true, resume_app_passwords: true, remove_throttle: true, unban: true });
    check('undo ran every step', r.status === 200 && (r.body.steps || []).every((s) => s.ok) && !r.body.remaining, r.body);
    r = await mc('GET', `/mailboxes/${E}`);
    check('sign-in restored', String(r.body.active) === '1', r.body.active);

    // ---- Phase 3c: MTA-STS, DNS, deliverability, domain admin sign-in
    r = await mc('PUT', `/domains/${D}/mta-sts`, { active: true, mode: 'testing', max_age: 604800, mx: [] });
    r = await mc('GET', `/domains/${D}/mta-sts`);
    check('MTA-STS saved', r.body.policy?.active && r.body.policy?.mode === 'testing' && r.body.policy?.id, r.body);
    r = await mc('GET', `/dns/${D}`);
    check('DNS checklist includes MTA-STS', (r.body.records || []).some((x) => x.type === 'TXT (MTA-STS)'), (r.body.records || []).map((x) => x.type));
    r = await mc('GET', '/deliverability?refresh=1');
    const card = (r.body.domains || []).find((x) => x.domain === D);
    check('deliverability scorecard', card && /^[A-F]$/.test(card.grade) && card.checks.length >= 8, card || r.body);
    const fake = (r.body.server?.blocklists || []).filter((l) => l.state === 'listed');
    check('no blocklist claims a listing the self-test can\'t back up', fake.every((l) => /^127\./.test(l.answer || '')), fake);
    r = await mc('POST', '/domain-admins', { username: 'e2e' + tag, password: 'E2e-' + tag + '-Passw0rd', domains: [D], active: true });
    r = await mc('POST', `/domain-admins/e2e${tag}/sso`);
    check('domain admin sign-in link', /\/domainadmin\/\?sso_token=/.test(r.body.url || ''), r.body);

    // ---- mail WAF
    r = await api('GET', '/api/crowdsec/appsec/plan');
    if (r.status === 200) {
      check('mail WAF active', r.body.active === 'cowsec/mail-waf' && r.body.counts.block > 0 && r.body.counts.watch > 0, { active: r.body.active, counts: r.body.counts });
    } else console.log('SKIP mail WAF (no AppSec engine on this server)');
  } catch (e) {
    check('run completed', false, e.message);
  } finally {
    if (api) {
      const mc = (m, path, body) => api(m, '/api/mailcow' + path, body);
      await mc('DELETE', `/domain-admins/e2e${tag}`).catch(() => {});
      await mc('DELETE', `/alias-domains/alias-${tag}.test`).catch(() => {});
      await mc('DELETE', `/mailboxes/${E}`).catch(() => {});
      const gone = await mc('DELETE', `/domains/${D}`).catch(() => ({}));
      console.log(gone.status === 200 ? `cleaned up ${D}` : `could not remove ${D}; delete it by hand`);
    }
    // 4xx answers are expected here: some checks make sure a bad request is refused
    const real = errors.filter((e) => e.startsWith('JS:') || /^5\d\d /.test(e));
    if (real.length) console.log('page errors:', real.slice(0, 10));
    await b.close();
    process.exit(done());
  }
})();
