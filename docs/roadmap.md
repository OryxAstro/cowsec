# Roadmap

What's planned for CowSec, roughly in order. Nothing here is a promise of a date; items move as they're built and tested on real servers.

## Phase 3: deeper mailcow control

Built on mailcow's API ([review of the API](mailcow.md)), with CrowdSec tying it together.

### 3a. Finish what's half-built (done)

- **Mailboxes:** force 2FA, "may send as" picker, per-mailbox spam score, app passwords, disposable (time-limited) aliases.
- **DKIM:** choose selector and key size, rotation with a grace period for the old key, copy a key to another domain.
- **Domains:** footer/disclaimer editor with live preview, alias domains.
- **Quarantine:** release and train as not spam, message preview with rspamd symbols, "always allow / block this sender" from an item.

### 3b. Security with CrowdSec (done)

- **Mailbox security view:** recent sign-ins with country flags, failed sign-ins CrowdSec saw for the address, "new country" warnings.
- **Lock down a mailbox:** one playbook that disables sign-in, forces a password reset, revokes app passwords, clears ActiveSync devices, throttles sending and bans the source IPs. Comes with an undo checklist.
- **Outbound spam watch:** spikes in the rate-limit log and the queue, linked to the lock-down playbook.
- **Sender policy:** allow and block lists per domain, plus forwarding hosts.
- **Password policy**, and an overview of the mailcow admins and their 2FA.

### Mail insight

CowSec keeps a small history of its own, so it can show trends and follow a message from start to finish:
- **Mail trail:** search by sender, recipient or subject and follow one message as an animated journey: arrived, rspamd's verdict, delivered, deferred or bounced, with the reason at each step.
- **Herd health dashboard:** messages, spam, bounces and failed sign-ins over 24 hours, 7 days and 30 days, with live sparklines; per-mailbox sent, received and failure rates.
- **DMARC and TLS reports:** import aggregate reports (upload or a mailbox CowSec reads), then show who sends as your domains on an animated map, and what passes or fails.
- **Pen rules:** release or delete quarantined mail automatically by sender, domain, recipient or subject, with a dry run first.
- **Do-not-send list:** stop retrying addresses that hard-bounce, and keep the queue clean.
- **Live logs:** streamed as they happen, not on refresh.
- **DNS watch:** re-check every domain's records on a schedule, with an SPF lookup counter and DMARC policy advice, and alert when something changes.
- **rspamd maps editor** with a pattern helper and validation.

### 3c. Deliverability and onboarding (done)

- MTA-STS per domain.
- **Deliverability scorecard:** DNS status for every domain, blocklist checks on the server IP, PTR.
- **New-domain wizard:** domain, DKIM, live DNS check until everything is green, first mailboxes.
- Open mailcow as a domain admin with one click (SSO token).

### 3d. Larger features

- **IMAP migration wizard:** connection test, folder mapping, live progress per mailbox (sync jobs).
- **Sieve rule builder** with out-of-office.
- BCC and recipient maps, resources (rooms and equipment), external identity provider, mailcow branding.

## Phase 4: a modern webmail client

A webmail client to replace SOGo's interface: built for 2026 and beyond, secure by design, and up to the standard of the CowSec console.

Plenty of mail clients have one good idea. Very few have all of them, and the open-source self-hosted ones (SOGo, Roundcube, SquirrelMail) feel dated. The goal is to bring the best ideas together on the mail server you already run, and add things only a client that sits next to CrowdSec and mailcow can do.

### Security you can see

- **Trust panel on every message.** It shows SPF, DKIM, DMARC and ARC results in plain language, when you first heard from this sender, lookalike-domain warnings (`paypa1.com`), and a risk summary for attachments based on rspamd's verdict.
- **Link unmasking.** Hover a link to see where it really goes, including through redirectors, before you click.
- **Remote content off by default.** Images load through a proxy that strips tracking pixels, and the client shows which trackers it blocked.
- **"This is phishing" button** that does three things: trains the spam filter, reports the sending server to CrowdSec, and removes copies from other mailboxes on the server (with an admin's approval).
- **Your own security page:** recent sign-ins with locations, active sessions and devices, app passwords, 2FA, and a one-click "sign me out everywhere".
- **End-to-end encryption built in:** OpenPGP with automatic key discovery (WKD, Autocrypt) and S/MIME, without plugins.

### Privacy and aliases

- **Disposable aliases from the compose window and the address bar.** Create a "hide my email" alias for each sign-up, see which alias started receiving spam, and turn it off with one click.
- **Screener for first-time senders.** New senders wait in a queue until you allow them once.

### A fast, modern inbox

- Keyboard-first, with a command palette; works offline as an installable app with push notifications.
- **Server-side features that work on every device:** snooze, send later, undo send, follow-up reminders.
- Smart bundles (newsletters, receipts, notifications) sorted on the server. Nothing goes to an outside AI service.
- **Optional assistant:** thread summaries, reply drafts and natural-language search. It's off by default and uses a model the admin picks, local or a provider of their choice.
- **Visual rule builder** that writes Sieve under the hood, including out-of-office.
- Quarantine inside the inbox: see what was held and release it yourself.
- Calendar and contacts over CalDAV and CardDAV, using the server you already have.

### White label

For anyone using mailcow to offer mail as a service, every visible part can carry the customer's identity instead of CowSec's:

- **Brand per tenant.** Set brands per mailcow domain or group of domains: name, logo, favicon, colours (theme tokens), login page text, support links and legal footer.
- **Custom hostnames** (`mail.customer.com`), with certificates issued automatically through CowSec's existing DNS-01 setup.
- **Bessie and the cow wording become the default skin** rather than fixed parts; a brand hides them entirely.
- **Notification mail** (quarantine digests, quota warnings, password resets) uses the same brand.
- **Brand packs** that can be exported and imported, and an optional branded view of the console for domain admins.

### How it would fit

- A separate component from the console, packaged the same way and served through the same OpenResty edge with CrowdSec AppSec in front.
- **Talks to Dovecot and Postfix** over IMAP and SMTP. A Go backend turns IMAP IDLE into live updates for the browser. Search uses Dovecot's full-text index.
- **Sign-in** uses mailcow's own accounts (with OAuth2 for single sign-on), and 2FA is enforced where mailcow requires it.
