#!/usr/bin/env python3
"""Verification gate. Fails non-zero if the built lists regress."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from coverage_test import load, verdict, selftest  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# Blocking any of these means the list has become dangerous.
MUST_NOT_BLOCK = [
    'cloudfront.net', 'nvidia.com', 'www.nvidia.com', 'playstation.net',
    'sentry.io', 'huggingface.co', 'khanacademy.org', 'github.io',
    'docker.io', 'k8s.io', 'hub.docker.io', 'kubernetes.io',
]
# Losing any of these means a high-leverage layer has silently dropped out.
MUST_BLOCK = [
    'gamedistribution.com', 'gamemonetize.com',   # embed CDNs - the durable layer
    'nowgg.me', 'mathsspot.com',                  # now.gg cluster
    'invisiproxy.com', 'titaniumnetwork.org',     # proxy frontends
    'gfn.nvidia.com',                             # narrow rule under an excluded apex
    'remoteplay.dl.playstation.net',              # ditto
    'emulatorgames.net', 'turbowarp.org',
    'oyunkolu.com', 'sprunki.com', 'bloxd.io',
]


def main():
    if selftest() != 0:
        return 1

    main_list = ROOT / 'dist' / 'games.txt'
    aggr = ROOT / 'dist' / 'games-aggressive.txt'
    if not main_list.exists() or not aggr.exists():
        print('FAIL: run `npm run build` first')
        return 1

    rules, _ = load(main_list)
    rules += load(aggr)[0]
    failures = []

    for d in MUST_NOT_BLOCK:
        v, r = verdict(rules, d)
        if v == 'BLOCK':
            failures.append(f'  must NOT block {d} - blocked by {r}')
    for d in MUST_BLOCK:
        v, _ = verdict(rules, d)
        if v != 'BLOCK':
            failures.append(f'  must block {d} - got {v}')

    domains = [l.strip() for l in (ROOT / 'tests' / 'known-game-domains.txt')
               .read_text(encoding='utf-8').splitlines() if l.strip()]
    missed = [d for d in domains if verdict(rules, d)[0] != 'BLOCK']

    print(f'rules loaded: {len(rules)}')
    print(f'must-not-block: {len(MUST_NOT_BLOCK) - len([f for f in failures if "must NOT" in f])}'
          f'/{len(MUST_NOT_BLOCK)} ok')
    print(f'must-block:     {len(MUST_BLOCK) - len([f for f in failures if f.strip().startswith("must block")])}'
          f'/{len(MUST_BLOCK)} ok')
    print(f'known games:    {len(domains) - len(missed)}/{len(domains)} blocked')

    if failures:
        print('\nFAILURES:')
        print('\n'.join(failures))
        return 1
    print('\nall checks passed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
