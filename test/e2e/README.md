# End-to-end tests

Browser tests that drive a real CowSec install with [Playwright](https://playwright.dev). The Go and Python unit tests (`make test`) run on every build. These tests need a server, so you run them yourself against a test machine.

| Script | What it does | Changes the server? |
| --- | --- | --- |
| `wizard.js` | Runs the setup wizard from "Open the gate" to "The barn is built". Handles both paths (protect an existing mailcow, or install one on a bare server) and Debian 13, where the edge isn't offered yet. | Yes: it installs CowSec |
| `tour.js` | Signs in, opens every console page, screenshots it and fails on a JavaScript error or a 5xx answer from the API. | No |
| `checks.js` | API regression checks for the mail features, mailbox lock-down and undo, MTA-STS, deliverability, the mail WAF and Mail insight. It creates a throwaway `e2e-<random>.test` domain and mailbox, sends one message to itself through SMTP submission and follows it in the mail trail, then removes the domain and mailbox. | Only its own test domain |

**Use a test server, not one people rely on.** `checks.js` cleans up after itself, but it does lock down and restore a mailbox, ban and unban a documentation address (`203.0.113.77`), and prepare a DKIM key.

## Setup

```sh
cd test/e2e
npm install
npx playwright install chromium
cp config.example.json config.json   # git ignores config.json
```

Fill in `config.json`:

- `console`: the console's address and your admin login. If the console name doesn't resolve from where you run the tests, set `ip` and the browser maps the name to that address (DNS isn't touched).
- 2FA: either put the account's TOTP secret in `console.totpSecret`, or run `sudo cowsec auth totp reset <user>` on the server before each run. The test then enrols a fresh secret as part of signing in.
- `setup` is only needed for `wizard.js`. `mode` is `existing` or `bare`. `dns.env` holds your DNS provider's variables, by the names the wizard shows. Leave `staging` on so test runs use Let's Encrypt's staging service.
- `mail` (optional): `smtpHost` and `smtpPort` for the Mail insight check's test message. The default is the console's address on port 587. If it can't connect, those checks are skipped.
- `sanitize` lists real domain names and addresses to replace with `example.com` and `192.0.2.10` in screenshots. LAN addresses are always replaced.

## Run

```sh
COWSEC_E2E_CONFIG=config.json node checks.js out/checks
COWSEC_E2E_CONFIG=config.json node tour.js out/tour
COWSEC_E2E_THEME=light COWSEC_E2E_CONFIG=config.json node tour.js out/tour-light
COWSEC_E2E_CONFIG=config.json node wizard.js out/wizard
```

From the repo root, `make e2e COWSEC_E2E_CONFIG=test/e2e/config.json` installs the pinned Playwright and runs the checks and the tour.

Each script prints `PASS`/`FAIL` lines and exits non-zero on a failure, so they fit in a script or CI job. Screenshots go into the output folder (the last argument, `COWSEC_E2E_OUT`, or `./out`), and `wizard.js` also saves the installer log there.

## Adding a check

Put shared helpers in `lib.js`. In `checks.js`, make anything a check creates use the run's random tag, and add its removal to the `finally` block, so a failed run still leaves the server clean.
