# Contributing to CowSec

Thanks for helping Bessie guard the pasture.

## Reporting bugs and ideas

Open an issue using the bug or feature template. For bugs, the most useful things to include are:
- the output of `sudo cowsec-setup check` (it changes nothing);
- your OS (`cat /etc/os-release`), mailcow version and CrowdSec version;
- what you expected, and what happened instead.

Security problems go through private reporting instead; see [SECURITY.md](SECURITY.md).

## Pull requests

1. Open an issue first for anything larger than a small fix, so we can agree the approach.
2. Keep each pull request to one change, and describe how you tested it.
3. Build and check locally:
   ```bash
   make test     # Go vet/tests and Python checks
   make deb      # builds build/cowsec_<version>_amd64.deb
   ```
4. Anything that changes a server (CrowdSec, the firewall, OpenResty, mailcow) needs testing on a real install, or on a VM you don't mind breaking. The browser tests in [`test/e2e`](test/e2e/README.md) drive the setup wizard, tour every console page and run API regression checks against such a VM.

## Contributor licence agreement

CowSec is licensed under the [GNU AGPL-3.0](LICENSE). To keep the project's licensing options open (for example offering CowSec under other terms alongside the AGPL), contributions are accepted under this agreement:

> By submitting a contribution to this repository, you confirm that:
> 1. the contribution is your own original work, or you have the right to submit it;
> 2. you grant OryxAstro a perpetual, worldwide, non-exclusive, royalty-free, irrevocable licence to use, reproduce, modify, distribute and sublicense your contribution, including under licences other than the AGPL-3.0;
> 3. you keep the copyright in your contribution, and it will also be available under the AGPL-3.0 as part of CowSec.

The pull request template asks you to tick a box agreeing to this. Pull requests without it can't be merged.

## Style

- Match the surrounding code; keep comments as sparse as the code around them.
- User-facing text: plain, specific and friendly. The farm wording is welcome in names and light touches, never at the cost of clarity.
