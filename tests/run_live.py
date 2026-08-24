#!/usr/bin/env python3
"""Run integrations against REAL vendor endpoints.

  python3 tests/run_live.py                    # every configured integration
  python3 tests/run_live.py ubiquiti-unifi-network   # one, by slug or env prefix
  python3 tests/run_live.py --list             # what is configured, and what is not
  python3 tests/run_live.py --env-template     # print .env.example
  python3 tests/run_live.py --env ~/creds.env  # a different credential file

Credentials come from a git-ignored `.env` at the repo root, or from the real
environment, which wins. Nothing is hardcoded here and nothing is written back.

This is deliberately NOT reachable from tests/run.py. These runs call live
vendor endpoints -- someone else's production controller -- so they must never
happen because a developer typed the wrong command.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness import invariants, live  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A live estate is not a fixture: printing the whole run log spills real
# hostnames and addresses into a terminal or a CI record. Print enough to debug
# by default, everything only when asked.
LOG_TAIL_LINES = 20

HEADER = """\
# Credentials for the live endpoint tests (python3 tests/run_live.py).
#
#   cp .env.example .env      # .env is git-ignored; .env.example is not
#
# Then uncomment and fill in the block for each integration you can actually
# reach. An integration runs only when its variables are set, so a developer
# with two credentials configured sees two runs and one skip count, not a
# failure for every other integration in the repo. NEVER commit .env, and never
# put a real credential in this file.
#
# Regenerate this file after a CONFIG change:
#
#   python3 tests/run_live.py --env-template > .env.example
#
# ===========================================================================
# Globals
# ===========================================================================

# The runzero CLI that runs each script. Defaults to `runzero` on PATH.
#RUNZERO_CLI=/opt/runzero/bin/runzero

# ===========================================================================
# Naming
# ===========================================================================
#
# Every variable is <PREFIX>_<PARAMETER>, where PARAMETER is the CONFIG
# parameter key upper-cased -- so the integration's own CONFIG block is the
# only declaration of what it accepts, and there is no second list to drift.
# PREFIX defaults to the directory name upper-cased
# (ubiquiti-unifi-network -> UBIQUITI_UNIFI_NETWORK) and an integration may
# claim a shorter one in <slug>/tests/live.json:
#
#   {"env_prefix": "UNIFI", "aliases": {"TLS_INSECURE": "tls_disable_validation"}}
#
# A <PREFIX>_ variable that matches no parameter is an error, not a shrug:
# a typo'd credential that is silently ignored still reports a green run.
#
# Three suffixes belong to the harness rather than to an integration:
#
#   <PREFIX>_EXPECT        what a valid result looks like (required)
#   <PREFIX>_EXPECT_FILE   the same terms, one per line, from a file outside git
#   <PREFIX>_LIVE_TIMEOUT  seconds before the run is failed (default 600)
#
# ===========================================================================
# Expectations
# ===========================================================================
#
# EXPECT is a space-separated list of terms, shell-quoted. Every term must
# parse: an unrecognised one fails the run rather than being ignored, because
# an expectation with a typo that silently passes is worse than none at all.
#
#   asset_count>=5              how many assets came back (also > = < <= ==)
#   services>=1                 services across every asset (also software,
#                               vulnerabilities)
#   any:hostnames=JOHNS-IPHONE  some asset has this value in this field
#   any:os~Windows              some asset's field contains this substring
#   asset[unifi:site:aa-bb]     this exact foreign id was emitted
#   asset[unifi:site:aa-bb]:deviceType=Switch      ... with this field value
#
# Field names are the ones on the EMITTED asset -- id, hostnames, ipAddresses,
# macAddresses, deviceType, os, and each <prefix>_ custom attribute -- not the
# vendor's field names. `=` matches one whole value case-insensitively, `~`
# matches a substring. Quote values containing spaces: any:os="Windows Server".
#
# Expectations are printed in failure messages, so put no secrets in them.
#
# ===========================================================================
# Integrations
# ===========================================================================
"""


def placeholder_for(param):
    """A fake value for .env.example that shows the shape without being usable."""
    kind = param.get("type", "string")
    if param.get("placeholder"):
        return param["placeholder"]
    if kind == "secret" or param.get("secret"):
        return "replace-me"
    if kind == "url":
        return "https://vendor.example.com"
    if kind == "bool":
        return str(param.get("default", False)).lower()
    if kind in ("int", "float"):
        return str(param.get("default", 100))
    if kind == "enum":
        options = param.get("options") or ["value"]
        first = options[0]
        return str(first.get("value", first) if isinstance(first, dict) else first)
    default = param.get("default")
    return str(default) if default not in (None, "") else "replace-me"


def stanza(integration):
    """One integration's block of .env.example, generated from its CONFIG."""
    name = integration.config.get("name") or integration.slug
    heading = "# --- %s (%s) " % (name, integration.slug)
    out = [heading + "-" * max(3, 78 - len(heading))]
    if integration.script is None:
        out.append("# This directory ships several scripts. Name the one to test "
                   "with \"script\" in %s/tests/live.json." % integration.slug)
    params = [p for p in (integration.config.get("params") or [])
              if isinstance(p, dict) and p.get("key")] + integration.include_params
    aliased = {v.lower(): k for k, v in (integration.live.get("aliases") or {}).items()}
    for param in params:
        note = " (required)" if param.get("required") else ""
        out.append("# %s%s" % (param.get("label") or param["key"], note))
        suffix = aliased.get(param["key"].lower(), param["key"]).upper()
        out.append("#%s=%s" % (integration.env_name(suffix), placeholder_for(param)))
    out.append("# What a valid result looks like (required to run; see tests/README.md)")
    out.append("#%s='asset_count>=1'" % integration.env_name("EXPECT"))
    out.append("")
    return out


def env_template(integrations):
    """The per-integration half of .env.example, generated from every CONFIG."""
    out = []
    for integration in integrations:
        out += stanza(integration)
    return out


def describe(plan):
    """One --list row: prefix, slug, and whether the environment configures it."""
    integration = plan.integration
    names = [n for n in sorted(os.environ)
             if n.startswith(integration.prefix + "_") and os.environ[n] != ""]
    if plan.state == live.Plan.SKIP:
        state = "not configured"
    elif plan.state == live.Plan.ERROR:
        state = "INCOMPLETE (%d set)" % len(names)
    else:
        state = "configured (%s)" % ", ".join(names)
    return "%-28s %-32s %s" % (integration.prefix, integration.slug, state)


def report_failure(name, failures):
    print("FAIL  %s" % name)
    for failure in failures:
        print("        %s" % failure)


def main(argv):
    args = list(argv)
    env_path = os.path.join(REPO_ROOT, ".env")
    show_list = template = full_log = explicit_env = False
    selector = ""
    while args:
        arg = args.pop(0)
        if arg == "--env" and args:
            env_path, explicit_env = args.pop(0), True
        elif arg.startswith("--env="):
            env_path, explicit_env = arg.split("=", 1)[1], True
        elif arg == "--list":
            show_list = True
        elif arg == "--env-template":
            template = True
        elif arg == "--log":
            full_log = True
        elif arg in ("-h", "--help"):
            print(__doc__)
            return 0
        elif arg.startswith("-"):
            print("unknown option %r" % arg)
            return 2
        else:
            selector = arg.rstrip("/")

    # A missing default .env just means nothing is configured yet. A missing
    # --env path is a typo, and silently running zero tests would look like
    # success.
    if explicit_env and not os.path.exists(env_path):
        print("ERROR no such credential file: %s" % env_path)
        return 2

    try:
        loaded = live.load_dotenv(env_path)
        integrations = live.discover(REPO_ROOT)
    except live.LiveError as exc:
        print("ERROR %s" % exc)
        return 2

    if template:
        print(HEADER)
        print("\n".join(env_template(integrations)))
        return 0

    if selector:
        wanted = [i for i in integrations
                  if i.slug == selector or i.prefix == selector.upper()]
        if not wanted:
            print("no integration matched %r. Try --list." % selector)
            return 2
        integrations = wanted

    plans = [live.plan_for(i) for i in integrations]

    if show_list:
        print("%-28s %-32s %s" % ("ENV PREFIX", "INTEGRATION", "STATE"))
        for plan in plans:
            print(describe(plan))
        configured = sum(1 for p in plans if p.state != live.Plan.SKIP)
        print("\n%d of %d integrations configured; .env: %s"
              % (configured, len(plans),
                 env_path if os.path.exists(env_path) else "%s (absent)" % env_path))
        return 0

    runnable = [p for p in plans if p.state != live.Plan.SKIP]
    skipped = len(plans) - len(runnable)
    if not runnable:
        # Naming an integration that turns out to be unconfigured is an error,
        # not a skip: the developer asked for that one specifically, and CI that
        # green-lights a run of nothing is worse than CI that fails.
        if selector:
            wanted = plans[0].integration
            print("ERROR %s has no credentials configured. It needs at least:\n"
                  "        %s"
                  % (wanted.slug, "\n        ".join(
                      [wanted.env_name(s) for s in wanted.required]
                      + [wanted.env_name("EXPECT")])))
            return 2
        print("no integrations configured; %d skipped. Set credentials in %s "
              "(see .env.example), then re-run. `--list` shows every prefix."
              % (skipped, env_path))
        return 0

    try:
        cli = live.cli_path()
    except live.LiveError as exc:
        print("ERROR %s" % exc)
        return 2

    print("runzero CLI: %s" % cli)
    print("credentials: %s%s"
          % (env_path if os.path.exists(env_path) else "%s (absent)" % env_path,
             "" if not loaded else " (%d variables)" % len(loaded)))
    print("")

    passed, failed = 0, 0
    for plan in runnable:
        name = plan.integration.slug
        if plan.state == live.Plan.ERROR:
            failed += 1
            report_failure(name, plan.problems)
            continue

        # An outbound integration does not import an estate, it pushes one
        # somewhere. Say so before the push, not after: the expectations below
        # are about emitted assets and have nothing to assert for it.
        kind = str(plan.integration.config.get("type", "inbound")).lower()
        if kind != "inbound":
            print("NOTE  %s is an %s integration; this run writes to its real "
                  "destination" % (name, kind))

        try:
            result = live.run(plan, cli)
        except live.LiveError as exc:
            failed += 1
            report_failure(name, [str(exc)])
            continue

        failures = []
        if result.timed_out:
            failures.append("timed out after %ds; raise %s_LIVE_TIMEOUT if the "
                            "estate is genuinely this large"
                            % (plan.timeout, plan.integration.prefix))
        else:
            failures += live.evaluate(plan.expect, result.assets)
            skip = set(plan.integration.invariant_skips)
            for inv_name, message in invariants.run(result.assets, skip):
                failures.append("invariant %s: %s" % (inv_name, message))

        if failures:
            failed += 1
            # Failure text quotes field values back, and an integration that
            # copies a token into a custom attribute would otherwise print it
            # here. Redact these the same as the log.
            report_failure(name, [result.redact(f) for f in failures])
            print("        command: %s" % live.command_echo(result.argv, result.redact))
            log = result.redact(result.log).rstrip().splitlines()
            shown = log if full_log else log[-LOG_TAIL_LINES:]
            if shown:
                print("        --- run log%s ---"
                      % ("" if full_log else " (last %d lines; --log for all)"
                         % len(shown)))
                for line in shown:
                    print("        %s" % line)
        else:
            passed += 1
            print("PASS  %s (%d assets)" % (name, len(result.assets)))

    print("\n%d passed, %d failed, %d skipped" % (passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
