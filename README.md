# AdGuard Home games blocklist

Blocks gaming sites and the filter-bypass ecosystem used to reach them.
Built because no existing list covers both.

Two outputs, added to AdGuard Home as **two separate blocklists** so the
aggressive half can be toggled independently:

| File | Rules | What it is |
|---|---|---|
| `dist/games.txt` | ~35,600 | Four upstream lists normalised + 10 hand-maintained layers |
| `dist/games-aggressive.txt` | 7 | Whole-TLD rules for game-dominated TLDs |

## Why this exists

Measured on 110 DNS-verified, currently-live game domains:

| Configuration | Blocked |
|---|---|
| UT1 games list alone (33,741 rules) | 33 / 110 |
| Five best upstream lists stacked (36,673 rules) | 58 / 110 |
| This list, main only | 60 / 110 |
| This list + aggressive TLD layer | 110 / 110 |

**50 of the 52 domains that every upstream list missed were `.io`.** Seven TLD
rules close that gap. Read the last row honestly though: the test set is
`.io`-heavy and the TLD rule catches all `.io` by construction, so that number
is partly circular. The real claim is the third row versus the second.

Two findings that shaped the design:

1. **A bare domain in AdGuard Home blocks only the exact hostname, not
   subdomains.** Per the [DNS filtering syntax docs](https://adguard-dns.io/kb/general/dns-filtering-syntax/):
   *"`example.org`: blocks the `example.org` domain but **not** its subdomains."*
   Subscribing to UT1 raw therefore silently under-blocks. Everything here is
   compiled to `||domain^` via the `Compress` transformation.
2. **The proxy ecosystem cannot be covered by a static list.** 971 new proxy
   hostnames appeared in Aug–Sep 2026, mostly subdomains of compromised
   small-business sites. The durable leverage is `src/embed-cdns.txt` —
   blocking `gamedistribution.com` and `gamemonetize.com` kills the games
   regardless of which front domain serves the page.

## Install

```bash
npm ci
npm run build
npm test
```

Then in AdGuard Home → **Filters → DNS blocklists → Add blocklist → Add a custom
list**. AdGuard Home accepts an absolute local file path as well as a URL, so
you can point it straight at `dist/games.txt` without hosting anything.

Also switch on **Filters → Blocked services → Gaming** (22 services, 242 rules:
Steam, Roblox, Epic, Nintendo, PlayStation, Xbox Live, Battle.net…). It is free,
needs no maintenance, and covers the launcher axis no blocklist does.

## Verify the TLD rule before relying on it

`src/aggressive-tlds.txt` uses `||io^$denyallow=…`. This is documented for DNS
filtering but AdGuard's *ad blocker* docs state a `$denyallow` pattern "cannot
start with `||`" — two engines, two docs that disagree. Confirm on your own
instance: **Settings → Check the filtering**, enter `bloxd.io` (expect blocked)
and `docker.io` (expect not blocked).

If it does not work, the fallback is a bare `||io^` plus `@@||docker.io^`
exception rules, compiled with `ValidateAllowPublicSuffix` instead of
`Validate`. Note that a plain `@@` can be overridden by an upstream
`$important` rule, which is why `$denyallow` is preferred.

## Layout

```
configuration.json             main list: 4 upstream + 10 local sources
configuration.aggressive.json  TLD layer
src/allowlist-io.txt           SINGLE SOURCE OF TRUTH for exemptions
src/aggressive-tlds.txt        generated - do not edit
src/exclusions.txt             generated - do not edit
src/overlay.txt                games no upstream list has
src/single-game-domains.txt    one-game-one-domain sites
src/portals-international.txt  non-English portals (UT1 is French-leaning)
src/emulators.txt              browser ROM/emulator sites
src/embed-cdns.txt             iframe providers - highest leverage layer
src/platforms-social-games.txt Discord / Telegram / Scratch-style hosts
src/bypass-portals.txt         "unblocked games" portals
src/bypass-proxies.txt         Ultraviolet/Rammerhead-family frontends
src/nowgg-mirrors.txt          now.gg cloud-Android cluster
src/cloud-gaming.txt           GeForce NOW, Luna, Boosteroid…
scripts/gen_tld_rules.py       generates the two generated files
scripts/coverage_test.py       rule matcher + 14-case selftest
scripts/verify.py              the gate run by `npm test`
tests/known-game-domains.txt   110 DNS-verified live game domains
tests/must-not-block.txt       infrastructure that must stay reachable
```

Edit `src/allowlist-io.txt` and re-run `npm run build`; it feeds both the
`$denyallow` exemptions and the upstream exclusions.

## False positives found in upstream lists

Stripped via `src/exclusions.txt`. Worth knowing if you use these lists directly:

| Domain | Source | Impact |
|---|---|---|
| `cloudfront.net` | JosuhaSanhueza | **All of Amazon CloudFront.** Breaks a large slice of the web. |
| `nvidia.com` | UT1 | Driver downloads. `gfn.nvidia.com` stays blocked. |
| `playstation.net` | UT1 | PSN sign-in. `remoteplay.dl.*` stays blocked. |
| `sentry.io` | JosuhaSanhueza | Error monitoring. |
| `huggingface.co` | IREK-szef, NemesisHubris | ML model hub. |
| `khanacademy.org` | NemesisHubris | Education. |

**Do not use `NemesisHubris/parental-control-blocklists`.** It is
`UT1 ∪ IREK-szef` plus 1,284 additions, so it re-imports `huggingface.co` and
adds `khanacademy.org` and `abcmouse.com`. Its recent date makes it look fresh.

Kept blocked on purpose: `xbox.com`, `xboxlive.com`, `playstation.com`,
`steampowered.com`, `roblox.com`, `epicgames.com`, `minecraft.net`,
`chess.com`, `itch.io`, `scratch.mit.edu`. Use Blocked Services instead if you
want these individually toggleable.

## Maintenance

Quarterly, because these rot at different rates:

- `src/bypass-portals.txt`, `src/bypass-proxies.txt` — fastest rot, rotate deliberately
- `src/nowgg-mirrors.txt` — re-run a CertSpotter query on `now.gg`
- `npm test` after any change

Known gaps, stated plainly:

- Xbox Cloud Gaming's web client is at the **path** `xbox.com/play`. DNS cannot
  block a path. Use Blocked Services → xboxlive.
- PS Plus Premium cloud streaming publishes no endpoint.
- `storage.googleapis.com` is now the largest proxy-hosting vector (41,750
  links) and is not blockable without breaking Google Cloud Storage.
- Rotating proxy subdomains on compromised legitimate sites are structurally
  outside what DNS blocking can reach.
- DNS filtering is bypassed by DoH/DoT in the browser and by any VPN. Enable
  AdGuard Home's "Block access to DNS-over-HTTPS/TLS" or this is a front-door
  lock only.
