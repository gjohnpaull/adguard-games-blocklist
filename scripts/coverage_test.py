#!/usr/bin/env python3
"""Test whether domains are blocked by a blocklist, using AdGuard Home semantics.

Key semantics (https://adguard-dns.io/kb/general/dns-filtering-syntax/):
  example.com          -> blocks EXACTLY example.com, NOT subdomains
  0.0.0.0 example.com  -> same: exact only
  ||example.com^       -> blocks example.com AND all subdomains
  @@||example.com^     -> allowlist (exception)
"""
import re
import sys
from pathlib import Path

DOMAIN_RE = re.compile(r'^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$')


class Rule:
    __slots__ = ('host', 'subdomains', 'allow', 'raw', 'denyallow')

    def __init__(self, host, subdomains, allow, raw, denyallow=()):
        self.host = host
        self.subdomains = subdomains
        self.allow = allow
        self.raw = raw
        self.denyallow = tuple(denyallow)

    def matches(self, domain):
        if domain == self.host:
            hit = True
        elif self.subdomains and domain.endswith('.' + self.host):
            hit = True
        else:
            return False
        # $denyallow=a|b exempts those domains and their subdomains
        for ex in self.denyallow:
            if domain == ex or domain.endswith('.' + ex):
                return False
        return hit


def parse_line(line):
    """Return a Rule, or None if the line is not a plain host-blocking rule."""
    line = line.strip()
    if not line or line[0] in '!#':
        return None

    allow = line.startswith('@@')
    if allow:
        line = line[2:]

    # Adblock-style: ||host^  /  ||host^$modifiers  /  ||host
    if line.startswith('||'):
        body, _, mods = line[2:].partition('$')
        body = body.rstrip('^').rstrip('|')
        if not body or '*' in body or '/' in body:
            return None  # wildcard/regex/path rules: out of scope for this check
        deny = ()
        for m in mods.split(','):
            if m.startswith('denyallow='):
                deny = tuple(d.lower() for d in m[len('denyallow='):].split('|') if d)
        return Rule(body.lower(), True, allow, line, deny)

    # /etc/hosts style: "IP host [aliases...]"
    parts = line.split()
    if len(parts) >= 2 and re.match(r'^(\d{1,3}\.){3}\d{1,3}$|^::|^[0-9a-f:]+$', parts[0], re.I):
        for host in parts[1:]:
            if host.startswith('#'):
                break
            if DOMAIN_RE.match(host.lower()):
                return Rule(host.lower(), False, allow, line)
        return None

    # Domains-only syntax: a bare domain, exact match only
    if DOMAIN_RE.match(line.lower()):
        return Rule(line.lower(), False, allow, line)

    return None


def load(path_or_text, is_text=False):
    text = path_or_text if is_text else Path(path_or_text).read_text(encoding='utf-8', errors='replace')
    rules, skipped = [], 0
    for line in text.splitlines():
        r = parse_line(line)
        if r is None:
            if line.strip() and line.strip()[0] not in '!#':
                skipped += 1
        else:
            rules.append(r)
    return rules, skipped


def verdict(rules, domain):
    domain = domain.lower().rstrip('.')
    blocked = [r for r in rules if not r.allow and r.matches(domain)]
    allowed = [r for r in rules if r.allow and r.matches(domain)]
    if allowed:
        return 'ALLOW', allowed[0].raw
    if blocked:
        return 'BLOCK', blocked[0].raw
    return 'MISS', ''


def selftest():
    rules, _ = load("\n".join([
        "! comment",
        "example.com",
        "||sub.test.org^",
        "0.0.0.0 hosts.example",
        "||games.net^$important",
        "||allowed.org^",
        "@@||allowed.org^",
        "||*.io^",
        "||io^$denyallow=docker.io|k8s.io",
    ]), is_text=True)
    cases = [
        ("example.com", "BLOCK"),      # bare domain, exact
        ("www.example.com", "MISS"),   # bare domain does NOT cover subdomains
        ("sub.test.org", "BLOCK"),     # || exact
        ("a.sub.test.org", "BLOCK"),   # || covers subdomains
        ("test.org", "MISS"),          # || on child does not cover parent
        ("hosts.example", "BLOCK"),    # hosts syntax, exact
        ("x.hosts.example", "MISS"),   # hosts syntax does NOT cover subdomains
        ("games.net", "BLOCK"),        # modifiers stripped
        ("allowed.org", "ALLOW"),      # @@ wins over plain block
        ("notexample.com", "MISS"),    # no substring matching
        ("bloxd.io", "BLOCK"),         # TLD rule catches arbitrary .io
        ("docker.io", "MISS"),         # $denyallow exempts it
        ("hub.docker.io", "MISS"),     # $denyallow covers subdomains too
        ("nacker.io", "BLOCK"),        # near-miss of an exempt domain still blocked
    ]
    fails = []
    for domain, want in cases:
        got, _ = verdict(rules, domain)
        if got != want:
            fails.append(f"  {domain}: want {want}, got {got}")
    if fails:
        print("SELFTEST FAILED:")
        print("\n".join(fails))
        return 1
    print(f"selftest: {len(cases)}/{len(cases)} passed")
    return 0


def main():
    args = sys.argv[1:]
    if not args or args[0] == '--selftest':
        return selftest()

    listfile, domainfile = args[0], args[1]
    rules, skipped = load(listfile)
    domains = [d.strip() for d in Path(domainfile).read_text().splitlines()
               if d.strip() and not d.startswith('#')]

    counts = {'BLOCK': 0, 'ALLOW': 0, 'MISS': 0}
    misses = []
    for d in domains:
        v, rule = verdict(rules, d)
        counts[v] += 1
        if v != 'BLOCK':
            misses.append((d, v))

    print(f"list: {listfile}  ({len(rules)} host rules parsed, {skipped} non-host lines skipped)")
    print(f"tested {len(domains)} domains -> {counts['BLOCK']} blocked, "
          f"{counts['ALLOW']} allowlisted, {counts['MISS']} missed")
    if misses:
        print("\nNOT BLOCKED:")
        for d, v in misses:
            print(f"  {v:6} {d}")
    return 1 if counts['MISS'] else 0


if __name__ == '__main__':
    sys.exit(main())
