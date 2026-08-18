#!/usr/bin/env python3
"""Run each integration against the real software in a container.

  python3 tests/run_containers.py                # every light integration
  python3 tests/run_containers.py kubernetes     # one integration, heavy or not
  python3 tests/run_containers.py --heavy        # include the heavy stacks too
  python3 tests/run_containers.py --list         # what is available
  python3 tests/run_containers.py --sweep-all    # also clear other runs' strays

These are deliberately NOT part of `tests/run.py`. They need Docker, they pull
multi-gigabyte images, and a single case can take minutes -- none of which
belongs in the fast fixture suite. What they buy is the one thing a fixture
cannot give: the response really came from the vendor's software, so a renamed
field or a changed envelope fails here instead of in production.

Exactly one integration's stack is up at a time, and teardown is verified with
`docker ps` rather than assumed -- but only over the stacks this run started.
The `rzci-` project prefix is shared with every other instance of the suite on
the host, so a stack this run did not start is reported and left alone rather
than swept: it is as likely to be a live second run as an earlier run's litter.
Pass --sweep-all to clear those too, once you know no other run is active.

A manifest may set `"heavy": true` to opt out of the default run; those stacks
need emulation or several gigabytes of RAM, and quietly starting one on a shared
machine is how this suite stops being run at all. They still run when named
explicitly or under --heavy.

Exits 0 when everything passed, 1 on failure, and 0 with a SKIP notice when
Docker is unavailable -- an absent Docker is not a broken integration.

Set RUNZERO_SCANNER to a rumble-scanner binary, or let the runner find one.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import containers, runner  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(argv):
    args = [a for a in argv if not a.startswith("-")]
    want_list = "--list" in argv
    want_heavy = "--heavy" in argv
    want_sweep_all = "--sweep-all" in argv
    selector = args[0].rstrip("/") if args else ""

    paths = containers.find_manifests(REPO_ROOT)
    if selector:
        paths = [p for p in paths
                 if containers.load_manifest(p)["_slug"] == selector
                 or containers.load_manifest(p)["_label"] == selector]
    if not paths:
        print("no containerized integrations matched %r" % selector)
        return 1

    if want_list:
        for path in paths:
            manifest = containers.load_manifest(path)
            print("%-28s %-7s %s" % (manifest["_label"],
                                     "HEAVY" if manifest.get("heavy") else "",
                                     manifest.get("description", "")))
        return 0

    # Naming an integration is an explicit choice to pay its cost, so a selector
    # overrides the heavy filter. An unqualified run does not.
    if not selector and not want_heavy:
        loaded = [(p, containers.load_manifest(p)) for p in paths]
        skipped = [m for _, m in loaded if m.get("heavy")]
        paths = [p for p, m in loaded if not m.get("heavy")]
        for manifest in skipped:
            print("SKIP  %s (heavy: %s)" % (
                manifest["_label"],
                manifest.get("heavy_reason", "opted out of the default run")))
        if skipped:
            print("      pass --heavy, or name the integration, to run %s.\n"
                  % ("it" if len(skipped) == 1 else "them"))
    if not paths:
        print("nothing to run")
        return 0

    ok, reason = containers.docker_available()
    if not ok:
        print("SKIP  containerized integration tests: %s" % reason)
        print("      %d case(s) were not run. Install/start Docker to run them." % len(paths))
        return 0

    scanner = runner.scanner_path()
    passed, failed = 0, []
    interrupted = False
    # Strictly sequential, and never a `continue` that skips teardown: exactly
    # one integration's stack is up at any moment. Running two in parallel would
    # halve the wall clock and reliably saturate a laptop, which is how this
    # suite becomes the thing nobody runs.
    try:
        for path in paths:
            manifest = containers.load_manifest(path)
            print("RUN   %s" % manifest["_label"], flush=True)
            ok, label, failures = containers.run_manifest(path, scanner, REPO_ROOT)
            if ok:
                passed += 1
                print("PASS  %s" % label, flush=True)
            else:
                failed.append((label, failures))
                print("FAIL  %s" % label, flush=True)
                for failure in failures:
                    print("        %s" % failure, flush=True)
    except KeyboardInterrupt:
        # run_manifest tore its own stack down on the way out; this only stops
        # the loop from starting the next one.
        interrupted = True
        print("\ninterrupted -- stopped before the next integration", flush=True)

    print("\n%d passed, %d failed" % (passed, len(failed)))
    ours = final_sweep(sweep_all=want_sweep_all)
    if ours:
        print("FAIL  this run leaked %d project(s): %s" % (len(ours), ", ".join(ours)))
        return 1
    return 1 if (failed or interrupted) else 0


def final_sweep(sweep_all=False):
    """Print `docker ps` once at the end and force-remove anything of ours left.

    The per-case check already ran; this is the belt-and-braces pass that makes
    the guarantee auditable -- the run prints the actual `docker ps` it ended
    with, rather than asking the reader to trust that teardown happened.

    Only containers this harness created are ever touched. The prefix filter is
    load-bearing: a developer's own containers, and other work sharing the
    machine, must survive a run of this suite untouched.

    Returns only the projects *this* run started and failed to clean up. A
    project this run did not start is reported and LEFT RUNNING: on a shared
    machine it is most likely a concurrent instance of this suite, and removing
    it would destroy that run.
    """
    # Only sweep projects THIS run started. An `rzci-` project we did not start
    # is far more likely to be a concurrently running instance of this suite
    # than a stray -- the machine is routinely shared -- and tearing it down
    # mid-case destroys someone else's run. Report it and leave it alone; the
    # run that owns it will clean it up in its own final sweep. When that run is
    # gone rather than busy, nothing left behind can say so, so clearing it is a
    # decision for the person at the keyboard: --sweep-all.
    strays = containers.stray_projects()
    ours = [p for p in strays if containers.started_here(p)]
    theirs = [p for p in strays if not containers.started_here(p)]
    for project in ours:
        print("      force-removing leaked project %s (from this run)" % project, flush=True)
        containers.force_remove_project(project)
    for project in theirs:
        if sweep_all:
            print("      force-removing %s (--sweep-all; started by another run)" % project,
                  flush=True)
            containers.force_remove_project(project)
        else:
            print("      leaving %s alone: not started by this run, so it is either a "
                  "concurrent run or someone else's stray. Pass --sweep-all to clear it "
                  "once no other run is active." % project, flush=True)
    running = containers._docker(["ps", "--format",
                                 "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}"]).strip()
    print("\n$ docker ps\n%s" % (running or "(empty)"), flush=True)
    return ours


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
