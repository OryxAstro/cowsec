# Security policy

CowSec sits in front of mail servers, so security reports get priority.

## Reporting a vulnerability

**Please don't open a public issue for a security problem.** Report it privately instead, through GitHub's private vulnerability reporting: go to the repository's **Security** tab and choose **Report a vulnerability**.

Include what you can:
- the CowSec version (`dpkg -l cowsec`) and your OS;
- what an attacker could do, and what they'd need first (network access, a console account, and so on);
- steps to reproduce, or a proof of concept.

## What to expect

- An acknowledgement within 3 days.
- An assessment and a plan within 10 days.
- A fixed release as soon as one is ready, with credit in the release notes if you'd like it.

Please give us a reasonable time to release a fix before you disclose the issue publicly.

## Scope

In scope: the CowSec console, the setup wizard, `cowsec-hostctl`, `cowsec-setup`, the package scripts, and the configuration CowSec writes for CrowdSec, OpenResty and mailcow.

Out of scope: vulnerabilities in mailcow, CrowdSec, OpenResty or other projects CowSec installs. Report those to their own projects; we're happy to help coordinate if CowSec's configuration makes one worse.

## Supported versions

Only the latest release gets security fixes. The console's **Fresh Hay → CowSec** card updates it in one click.
