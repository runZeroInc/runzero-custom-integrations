"""Drive a real scanner run against a fixture scenario and check the result.

This exercises what `--validate` cannot: the actual call sequence, real response
parsing, and the assets that come out the other end. The scanner is the real
binary, so anything the runtime rejects -- a future timestamp, a bad CVE, an
unexpected keyword -- fails here exactly as it would in production.
"""

import glob
import gzip
import json
import os
import shutil
import subprocess
import tempfile

from . import invariants
from .gmp_server import GMPServer
from .server import FixtureServer

# Any valid UUID works; the scanner only requires the flag to parse.
INTEGRATION_ID = "11111111-2222-3333-4444-555555555555"


def scanner_path():
    """Locate the dev scanner. /usr/local/bin/runzero is a zero-byte stub."""
    env = os.environ.get("RUNZERO_SCANNER")
    if env and os.path.exists(env):
        return env
    for candidate in glob.glob("/private/tmp/claude-*/**/rumble-scanner", recursive=True):
        if os.access(candidate, os.X_OK):
            return candidate
    raise SystemExit(
        "set RUNZERO_SCANNER to a rumble-scanner binary. Build one with:\n"
        "  cd /Users/dev/go/platform/product/rumble-scanner && "
        "go build -tags recogNocloud,development -o /tmp/rumble-scanner ."
    )


def read_assets(output_dir):
    """Parse the scan export into a list of the per-asset `info` dicts."""
    path = os.path.join(output_dir, "scan.runzero.gz")
    if not os.path.exists(path):
        return []
    assets = []
    with gzip.open(path) as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if isinstance(record, dict) and isinstance(record.get("info"), dict):
                assets.append(record["info"])
    return assets


def substitute(value, base, gmp=None):
    """Expand the fixture-server tokens inside a scenario string.

    The server binds an ephemeral port, so an integration that scopes its ids on
    the base URL produces a different id on every run. Expanding the same tokens
    inside `expect` lets those ids still be asserted exactly, instead of the
    scenario having to give up and assert nothing.

    A scenario carrying a `gmp` block also gets $GMP_HOST and $GMP_PORT, which
    is how a socket-protocol integration is pointed at its fixture listener.
    """
    host_port = base.split("://", 1)[-1]
    out = (str(value)
           .replace("$BASE_HOST", host_port)
           .replace("$HOST", host_port.split(":")[0])
           .replace("$BASE", base))
    if gmp:
        out = out.replace("$GMP_HOST", gmp[0]).replace("$GMP_PORT", str(gmp[1]))
    return out


def run_once(scenario, script, scanner, basedir="."):
    """Start a fixture server, run the scanner against it, return assets+requests."""
    server = FixtureServer(scenario)
    base = server.start()
    # A `gmp` block adds a raw TLS listener speaking the Greenbone Management
    # Protocol. It is started only when a scenario asks for one, so every
    # existing HTTP scenario behaves exactly as before.
    gmp_server = None
    gmp = None
    if scenario.get("gmp"):
        gmp_server = GMPServer(scenario["gmp"], basedir)
        gmp = gmp_server.start()
    # The scanner refuses an output directory that already exists unless
    # --overwrite is passed, so hand it a path inside a temp dir rather than the
    # temp dir itself.
    workdir = tempfile.mkdtemp(prefix="rz-fixture-")
    output = os.path.join(workdir, "scan")
    try:
        # Expand the tokens inside the routes too, so a response body can carry an
        # absolute next-page URL pointing back at this server. Cursor APIs that
        # return a full URL (DRF, HAL, trend-vision-one's nextLink) are
        # otherwise impossible to page in a fixture.
        server.routes = FixtureServer(
            json.loads(substitute(json.dumps(scenario), base, gmp))).routes
        kwargs = {k: substitute(v, base, gmp) for k, v in scenario.get("kwargs", {}).items()}
        # One --kwargs flag per pair. Joining them with commas makes any value
        # that itself contains a comma unparseable, which silently blocked every
        # list-valued parameter (property lists, site ids, extra facts) and
        # surfaced only as the scanner printing its usage text.
        argv = [scanner, "script", "--filename", script]
        for key, value in kwargs.items():
            argv += ["--kwargs", "%s=%s" % (key, value)]
        argv += ["--custom-integration-id", INTEGRATION_ID, "--output", output]
        proc = subprocess.run(
            argv,
            capture_output=True, text=True, timeout=scenario.get("timeout", 180),
        )
        requests = server.snapshot()
        if gmp_server:
            requests = requests + gmp_server.snapshot()
        return read_assets(output), requests, proc.stdout + proc.stderr, base, gmp
    finally:
        server.stop()
        if gmp_server:
            gmp_server.stop()
        shutil.rmtree(workdir, ignore_errors=True)


# Every key check_expectations understands. An unknown key is a hard error: a
# silently ignored expectation is one the harness never evaluates, so the
# scenario reports PASS while asserting nothing.
EXPECT_KEYS = frozenset([
    "assets", "asset_count", "min_assets", "ids", "ids_absent",
    "request_count", "min_requests", "requests_include", "requests_absent",
    "log_contains", "min_services_total", "min_software_total",
    "min_vulnerabilities_total",
])


def check_expectations(scenario, assets, requests, log, base, gmp=None):
    """Compare the run against the scenario's `expect` block."""
    expect = json.loads(substitute(json.dumps(scenario.get("expect", {})), base, gmp))
    unknown = sorted(set(expect) - EXPECT_KEYS)
    if unknown:
        raise ValueError(
            "unsupported expect key(s) %s; supported: %s"
            % (", ".join(unknown), ", ".join(sorted(EXPECT_KEYS))))
    failures = []

    # Assert individual asset fields. Identity and merge behaviour live here:
    # _match.behavior is the only place a no-id-match decision is observable.
    by_id = {a.get("id", ""): a for a in assets}
    for want in expect.get("assets", []):
        asset = by_id.get(want.get("id", ""))
        if asset is None:
            failures.append("no asset with id %s (have %s)" % (
                want.get("id"), sorted(by_id)[:5]))
            continue
        for field, expected in (want.get("fields") or {}).items():
            actual = asset.get(field)
            if actual is None and expected is not None:
                failures.append("%s: field %s missing" % (want.get("id"), field))
            elif str(actual) != str(expected):
                failures.append("%s: field %s is %r, expected %r" % (
                    want.get("id"), field, actual, expected))
        for field in want.get("fields_absent", []):
            if asset.get(field):
                failures.append("%s: field %s should be empty, is %r" % (
                    want.get("id"), field, asset.get(field)))

    if "asset_count" in expect and len(assets) != expect["asset_count"]:
        failures.append("expected %d assets, got %d" % (expect["asset_count"], len(assets)))
    if "min_assets" in expect and len(assets) < expect["min_assets"]:
        failures.append("expected at least %d assets, got %d" % (expect["min_assets"], len(assets)))

    ids = [a.get("id", "") for a in assets]
    for wanted in expect.get("ids", []):
        if wanted not in ids:
            failures.append("expected an asset with id %s" % wanted)
    for absent in expect.get("ids_absent", []):
        if absent in ids:
            failures.append("asset %s should have been skipped" % absent)

    # Assert on the call sequence itself -- the thing the built-in dummy server
    # cannot express, and where pagination and re-auth bugs actually live.
    if "request_count" in expect and len(requests) != expect["request_count"]:
        failures.append("expected %d requests, got %d (%s)" % (
            expect["request_count"], len(requests),
            [r["method"] + " " + r["path"] for r in requests][:8]))
    if "min_requests" in expect and len(requests) < expect["min_requests"]:
        failures.append("expected at least %d requests, got %d" % (expect["min_requests"], len(requests)))
    try:
        for want in expect.get("requests_include", []):
            if not any(_request_matches(r, want) for r in requests):
                failures.append("no request matched %s" % json.dumps(want))
        for want in expect.get("requests_absent", []):
            if any(_request_matches(r, want) for r in requests):
                failures.append("a request matched %s but should not have" % json.dumps(want))
    except ValueError as exc:
        failures.append(str(exc))

    for needle in expect.get("log_contains", []):
        if needle not in log:
            failures.append("expected %r in the run log" % needle)

    total_services = sum(len(invariants._children(a, "_services")) for a in assets)
    if "min_services_total" in expect and total_services < expect["min_services_total"]:
        failures.append("expected at least %d services, got %d" % (expect["min_services_total"], total_services))
    total_software = sum(len(invariants._children(a, "_software")) for a in assets)
    if "min_software_total" in expect and total_software < expect["min_software_total"]:
        failures.append("expected at least %d software rows, got %d" % (expect["min_software_total"], total_software))
    total_vulns = sum(len(invariants._children(a, "_vulnerabilities")) for a in assets)
    if "min_vulnerabilities_total" in expect and total_vulns < expect["min_vulnerabilities_total"]:
        failures.append("expected at least %d vulnerabilities, got %d" % (
            expect["min_vulnerabilities_total"], total_vulns))

    return failures


# Every key _request_matches understands. An expectation carrying anything else
# used to be ignored silently, which meant a matcher with no recognised key
# matched EVERY request vacuously -- so `requests_absent` always fired and
# `requests_include` always passed. Two open-audit scenarios were failing for
# exactly this reason (they used the route-match key `path_prefix`, which is not
# an expectation key). Unknown keys are now a hard error.
REQUEST_MATCH_KEYS = frozenset([
    "method", "path", "path_contains", "query_contains",
    "body_contains", "header_contains", "header",
])


def _request_matches(request, want):
    unknown = sorted(set(want) - REQUEST_MATCH_KEYS)
    if unknown:
        raise ValueError(
            "unsupported request matcher key(s) %s; supported: %s"
            % (", ".join(unknown), ", ".join(sorted(REQUEST_MATCH_KEYS))))
    if "method" in want and request["method"] != want["method"].upper():
        return False
    if "path" in want and request["path"] != want["path"]:
        return False
    if "path_contains" in want and want["path_contains"] not in request["path"]:
        return False
    if "query_contains" in want and want["query_contains"] not in request["query"]:
        return False
    if "body_contains" in want and want["body_contains"] not in request["body"]:
        return False
    if "header_contains" in want:
        blob = " ".join(request.get("headers", {}).values())
        if want["header_contains"] not in blob:
            return False
    for name, value in (want.get("header") or {}).items():
        got = request.get("headers", {}).get(name.lower())
        if got is None or (value and value not in got):
            return False
    return True


def run_scenario(path, scanner, repo_root):
    """Run one scenario file. Returns (ok, name, [failure, ...])."""
    with open(path) as handle:
        scenario = json.load(handle)

    # Scenarios live at <repo>/<slug>/tests/fixtures/<name>.json, so the slug is
    # three directories up from the file.
    slug = scenario.get("integration") or os.path.basename(
        os.path.dirname(os.path.dirname(os.path.dirname(path))))
    # Every integration is <slug>/<slug>.star, with one exception:
    # akamai-guardicore-centra ships two API-version scripts in one directory
    # (centra-v3-api.star, centra-v4-api.star), so neither can be named after
    # the directory. A scenario may therefore point at its script explicitly.
    script = os.path.join(repo_root, scenario.get("script") or os.path.join(slug, slug + ".star"))
    name = "%s/%s" % (slug, scenario.get("name") or os.path.basename(path))
    if not os.path.exists(script):
        return False, name, ["no such integration script: %s" % script]

    # The CLI's --kwargs is a cobra stringToString flag. When the whole
    # `key=value` argument contains exactly ONE `=`, the value is taken verbatim
    # and a comma in it is harmless. A SECOND `=` switches it into CSV parsing,
    # and only then does a comma split the value into a fabricated extra
    # parameter (`filter=a=b,c=d` -> filter="a=b" PLUS c="d"). Verified against
    # the scanner both ways. So the unsafe shape is a value containing BOTH.
    bad_kwargs = [k for k, v in (scenario.get("kwargs") or {}).items()
                  if "=" in str(v) and "," in str(v)]
    if bad_kwargs:
        return False, name, [
            "kwarg %r contains both '=' and ','; the runZero CLI parses that as "
            "CSV and fabricates an extra parameter, so this scenario cannot test "
            "what it declares" % k
            for k in sorted(bad_kwargs)]

    basedir = os.path.dirname(os.path.abspath(path))
    assets, requests, log, base, gmp = run_once(scenario, script, scanner, basedir)
    failures = check_expectations(scenario, assets, requests, log, base, gmp)

    skip = set(scenario.get("invariants", {}).get("skip", []))
    for inv_name, message in invariants.run(assets, skip, {"slug": slug}):
        failures.append("invariant %s: %s" % (inv_name, message))

    # A second identical run must produce identical ids. This is what catches an
    # id built from new_uuid(), a timestamp, or anything else non-deterministic;
    # such a script reconciles against nothing and duplicates its estate on
    # every poll.
    if scenario.get("check_determinism", True):
        again, _, _, _, _ = run_once(scenario, script, scanner, basedir)
        first = sorted(a.get("id", "") for a in assets)
        second = sorted(a.get("id", "") for a in again)
        if first != second:
            failures.append("ids are not deterministic across two identical runs")

    return (not failures), name, failures
