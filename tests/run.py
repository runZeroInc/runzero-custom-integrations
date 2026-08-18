#!/usr/bin/env python3
"""Run custom integration fixture tests.

  python3 tests/run.py                     # every scenario
  python3 tests/run.py bmc-discovery       # one integration
  python3 tests/run.py bmc-discovery/paged # one scenario
  python3 tests/run.py -j1                 # serial, for debugging
  python3 tests/run.py --failed            # re-run only last run's failures

Set RUNZERO_SCANNER to a rumble-scanner binary, or let the runner find one.

Scenarios are independent -- each stands up its own fixture server on an
ephemeral port and its own temp output directory -- so they run concurrently by
default. The work is almost entirely waiting on a scanner subprocess, so the
pool is sized well above the core count.
"""

import argparse
import glob
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import runner  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Where --failed reads and writes the failing-scenario list.
STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".last-failures.json")


def slug_for(path):
    """Recover the integration slug from <repo>/<slug>/tests/fixtures/<name>.json."""
    return os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(path))))


def name_for(path):
    return "%s/%s" % (slug_for(path), os.path.basename(path)[: -len(".json")])


def default_jobs():
    # Each job is a fixture server plus a scanner subprocess. Oversubscribing the
    # cores looks attractive because both are mostly idle waiting on the other,
    # but the scanner is a large binary with real startup cost, and at cores*2 on
    # this repo several integrations began failing on asset counts and request
    # counts purely from contention -- passing again the moment they were re-run
    # alone. Spurious failures are far more expensive than a slower suite, so the
    # default stays at or below the core count. Raise it with -j if your machine
    # can take it.
    return max(1, min(8, os.cpu_count() or 4))


def run_one(path, scanner):
    """Run a scenario, converting any harness-level exception into a failure.

    A scenario that times out or crashes the harness must not take the whole run
    down with it: before this, one hung script aborted the suite mid-way and
    every remaining scenario went unreported.
    """
    started = time.monotonic()
    try:
        ok, name, failures = runner.run_scenario(path, scanner, REPO_ROOT)
    except Exception as exc:  # noqa: BLE001 - any harness failure is a test failure
        ok, name, failures = False, name_for(path), ["harness error: %s: %s" % (type(exc).__name__, exc)]
    return ok, name, failures, time.monotonic() - started


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("selector", nargs="?", default="")
    ap.add_argument("-j", "--jobs", type=int, default=int(os.environ.get("RUNZERO_TEST_JOBS", 0)) or default_jobs())
    ap.add_argument("--failed", action="store_true", help="re-run only the scenarios that failed last time")
    ap.add_argument("--slow", type=float, default=0.0, help="report scenarios slower than N seconds")
    args = ap.parse_args(argv)

    paths = sorted(glob.glob(os.path.join(REPO_ROOT, "*", "tests", "fixtures", "*.json")))

    if args.failed:
        try:
            with open(STATE_FILE) as fh:
                wanted = set(json.load(fh))
        except (OSError, ValueError):
            print("no recorded failures; run the suite first")
            return 1
        paths = [p for p in paths if name_for(p) in wanted]
    elif args.selector:
        wanted = args.selector.rstrip("/")
        paths = [p for p in paths if wanted == slug_for(p) or name_for(p) == wanted]

    if not paths:
        print("no scenarios matched %r" % args.selector)
        return 1

    scanner = runner.scanner_path()
    jobs = max(1, min(args.jobs, len(paths)))
    started = time.monotonic()

    passed, failed, slow = 0, [], []
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(run_one, p, scanner): p for p in paths}
        # as_completed, not submission order: a single wedged scenario would
        # otherwise block the report of every scenario submitted after it, which
        # looks exactly like the whole suite hanging. The per-scenario subprocess
        # timeout is inside run_one; this only controls reporting order.
        for future in as_completed(futures):
            ok, name, failures, elapsed = future.result()
            if args.slow and elapsed >= args.slow:
                slow.append((elapsed, name))
            if ok:
                passed += 1
                print("PASS  %s" % name, flush=True)
            else:
                failed.append((name, failures))
                print("FAIL  %s" % name, flush=True)
                for failure in failures:
                    print("        %s" % failure, flush=True)

    with open(STATE_FILE, "w") as fh:
        json.dump([name for name, _ in failed], fh)

    if slow:
        print("\nslowest scenarios:")
        for elapsed, name in sorted(slow, reverse=True)[:10]:
            print("  %6.1fs  %s" % (elapsed, name))

    print("\n%d passed, %d failed in %.1fs (-j%d)"
          % (passed, len(failed), time.monotonic() - started, jobs))
    if failed:
        print("re-run just these with: python3 tests/run.py --failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
