#!/usr/bin/env python3
"""Static audit of every integration script across the qualities we care about.

  python3 scripts/audit_scripts.py            # everything, grouped by dimension
  python3 scripts/audit_scripts.py glpi       # one integration
  python3 scripts/audit_scripts.py --secrets  # one dimension
  python3 scripts/audit_scripts.py --summary  # counts only

Dimensions, in descending order of how much a hit actually matters:

  secrets   a credential value or a whole response body reaching the log
  hangs     a loop with no ceiling, so a broken cursor spins forever
  logging   shouty prefixes, banners, and unbounded per-record chatter
  coverage  no fixtures and no container, so nothing exercises the script
  config    declared parameters that the code never reads, and vice versa

This is a STATIC audit: it reads source, it does not run anything. Every finding
is a lead to confirm, not a verdict -- the checks are deliberately tuned to stay
quiet rather than to catch everything, because an audit that cries wolf is one
people stop running. Where a check cannot distinguish a real problem from a
legitimate pattern it stays silent and says so in its docstring.
"""

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# print("slug: ...") is the house format. These are the shapes that are not.
SHOUTY_RE = re.compile(r'print\(\s*["\'](\[[A-Z][A-Z0-9._ -]{2,}\]|[A-Z]{4,}:)')
BANNER_RE = re.compile(r'print\(\s*["\']\s*(?:[-=*#]{3,}|.{0,40}?[-=]{3,})')

# A response body or a whole record reaching a log. .get()/len()/type() calls on
# the same line mean a field was extracted, which is the correct pattern.
RAW_LOG_RE = re.compile(
    r'print\([^)]*\b(?:resp|response|download_response|del_resp)\.body\b'
    r'|print\([^)]*,\s*(?:item|record|device|host|row|entry)\s*\)')
RAW_OK_RE = re.compile(r'\.get\(|len\(|type\(|status_code|_api_error')


def integrations():
    """Yield (slug, path) for every integration script in the repo."""
    for name in sorted(os.listdir(REPO_ROOT)):
        d = os.path.join(REPO_ROOT, name)
        if not os.path.isdir(d) or name.startswith('.') or name in (
                'docs', 'scripts', 'tests'):
            continue
        for f in sorted(os.listdir(d)):
            if f.endswith('.star'):
                yield name, os.path.join(d, f)


def secret_keys(src):
    """Parameter keys the CONFIG marks as secret, in either field order."""
    keys = set(re.findall(r'"key":\s*"([a-z0-9_]+)"[^}]*?"type":\s*"secret"', src))
    keys |= set(re.findall(r'"type":\s*"secret"[^}]*?"key":\s*"([a-z0-9_]+)"', src))
    return keys


def check_secrets(slug, src):
    """A credential VALUE, or an entire response body, reaching the log.

    Naming a secret parameter in prose ("check the username and password") is
    correct and common, so only interpolation counts: concatenation, .format(),
    str(), or passing it as a print argument. That distinction is the whole
    check -- matching on the name alone reports ~32 lines in this repo and every
    one of them is fine.
    """
    out = []
    keys = secret_keys(src)
    for ln, line in enumerate(src.splitlines(), 1):
        if 'print(' not in line:
            continue
        # Blank out string literals first. Naming a secret inside the message
        # ("check the username, password, and organization") is prose, not a
        # leak; only an identifier in code position can carry the value. Without
        # this the check reports every helpful error message in the repo.
        code = re.sub(r'"[^"]*"|\'[^\']*\'', '""', line)
        for key in keys:
            if re.search(r'(\+\s*%s\b|\.format\([^)]*\b%s\b|,\s*%s\s*[),]|str\(\s*%s\s*\))'
                         % ((re.escape(key),) * 4), code):
                out.append((ln, "secret %r interpolated into a log" % key, line.strip()))
    for ln, line in enumerate(src.splitlines(), 1):
        if RAW_LOG_RE.search(line) and not RAW_OK_RE.search(line):
            out.append((ln, "whole body/record logged; may carry tokens or PII",
                        line.strip()))
    return out


def check_hangs(slug, src):
    """Loops that can spin forever when the far end misbehaves.

    A `while True` or cursor-driven walk is fine when something bounds it. What
    is not fine is a cursor loop whose only exit is the server returning a
    terminator: a server that keeps echoing the same next-page link spins until
    the task times out, which is how these fail in production rather than in
    tests. A page ceiling turns that into a clean, reportable stop.
    """
    out = []
    # pager() is the house bound: p.next() raises at CONFIG["maxPages"], so a
    # `while p.next():` loop is already ceilinged and reporting it buries the
    # handful of loops that genuinely are not.
    bounded = re.search(r'MAX_PAGES|max_pages|MAX_ITER|page_limit|MAX_VULNS'
                        r'|max_environments|MAX_DEVICES|\bpager\(', src)
    pages = re.search(r'next_page|nextLink|links\.get\(\s*["\']next|cursor'
                      r'|continuation|hasNextPage|has_more', src)
    for ln, line in enumerate(src.splitlines(), 1):
        m = re.match(r'\s*while\s+(.+?):\s*$', line)
        if not m:
            continue
        cond = m.group(1).strip()
        if bounded:
            continue
        if cond == 'True' or pages:
            out.append((ln, "loop has no page/iteration ceiling", line.strip()))
    return out


def check_logging(slug, src):
    """Log lines that are shouty, decorative, or emitted once per record."""
    out = []
    lines = src.splitlines()
    for ln, line in enumerate(lines, 1):
        if SHOUTY_RE.search(line):
            out.append((ln, "shouty prefix; house format is 'slug: message'",
                        line.strip()))
        elif BANNER_RE.search(line):
            out.append((ln, "banner/decoration in a log line", line.strip()))

    # A skip-log inside the per-record loop is the right *format* but the wrong
    # *volume*: on an estate where thousands of records lack an id it emits
    # thousands of lines. Flag only when nothing counts or caps them, since the
    # established fix is to tally and print one summary line.
    aggregated = re.search(r'skipped\s*\+?=|skipped_\w+\s*\+?=|_skipped\b'
                           r'|reported\s*\+=', src)
    if not aggregated:
        for ln, line in enumerate(lines, 1):
            if re.search(r'print\("[a-z0-9-]+: skipping\b', line):
                out.append((ln, "per-record skip log with no tally; "
                                "one line per record on a large estate",
                            line.strip()))
                break
    return out


def check_coverage(slug, src):
    """Nothing exercises this script at all."""
    d = os.path.join(REPO_ROOT, slug)
    has_fix = os.path.isdir(os.path.join(d, 'tests', 'fixtures')) and \
        any(f.endswith('.json') for f in
            os.listdir(os.path.join(d, 'tests', 'fixtures'))) \
        if os.path.isdir(os.path.join(d, 'tests', 'fixtures')) else False
    has_doc = os.path.isdir(os.path.join(d, 'tests', 'docker'))
    if not has_fix and not has_doc:
        return [(0, "no fixtures and no container: nothing exercises this", "")]
    return []


def check_config(slug, src):
    """Declared parameters the code never reads, and reads never declared.

    Both directions are real defects seen in this repo: a declared-but-unread
    parameter is a promise the console makes and the script ignores, and a
    read-but-undeclared one is unreachable except through legacy JSON.
    """
    out = []
    declared = set(re.findall(r'"key":\s*"([a-z0-9_]+)"', src))
    # includes expand into prefixed families; treat those prefixes as declared
    prefixes = re.findall(r'"([a-z0-9_]+_)":\s*OPTIONS_', src)

    # Everything after the CONFIG literal. A parameter counts as read if its
    # name appears here AT ALL, not merely in a literal kwargs access: several
    # integrations drive their toggles from a table (ubiquiti-unifi-protect
    # keeps the toggle name in a COLLECTIONS tuple and looks it up dynamically),
    # and a stricter match reports every one of those as dead.
    body = src
    m = re.search(r'^\s*\)?\s*\}\s*$', src, re.M)
    end = src.find('\nload(')
    if end > 0:
        body = src[end:]
    read = set(k for k in declared if re.search(r'\b%s\b' % re.escape(k), body))
    read |= set(re.findall(r'kwargs(?:\.get\(|\[)\s*["\']([a-z0-9_]+)["\']', src))
    read |= set(re.findall(r'get_\w+\(\s*kwargs\s*,\s*["\']([a-z0-9_]+)["\']', src))
    for key in sorted(declared - read):
        if any(key.startswith(p) for p in prefixes) or key in ('url', 'legacy_credentials'):
            continue
        out.append((0, "parameter %r is declared but never read" % key, ""))
    for key in sorted(read - declared):
        if any(key.startswith(p) for p in prefixes) or key in (
                'legacy_credentials', 'url'):
            continue
        out.append((0, "parameter %r is read but never declared" % key, ""))
    return out


CHECKS = [
    ("secrets", check_secrets),
    ("hangs", check_hangs),
    ("logging", check_logging),
    ("coverage", check_coverage),
    ("config", check_config),
]


def main(argv):
    only = [a for a in argv if not a.startswith('-')]
    dims = [d for d in (a.lstrip('-') for a in argv if a.startswith('--'))
            if d in dict(CHECKS)]
    summary_only = '--summary' in argv

    findings = {name: [] for name, _ in CHECKS}
    scanned = 0
    for slug, path in integrations():
        if only and slug not in only:
            continue
        scanned += 1
        src = open(path, encoding='utf-8', errors='replace').read()
        rel = os.path.relpath(path, REPO_ROOT)
        for name, fn in CHECKS:
            if dims and name not in dims:
                continue
            for ln, msg, ctx in fn(slug, src):
                findings[name].append((rel, ln, msg, ctx))

    total = sum(len(v) for v in findings.values())
    print("audited %d integration script(s), %d finding(s)\n" % (scanned, total))
    for name, _ in CHECKS:
        hits = findings[name]
        if dims and name not in dims:
            continue
        print("%-9s %d" % (name, len(hits)))
        if summary_only:
            continue
        for rel, ln, msg, ctx in hits:
            where = "%s:%d" % (rel, ln) if ln else rel
            print("    %-58s %s" % (where, msg))
            if ctx:
                print("    %-58s   %s" % ("", ctx[:96]))
        if hits:
            print()
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
