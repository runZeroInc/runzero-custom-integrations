#!/usr/bin/env python3
"""Create the Host objects this case imports, then freeze them.

The ApiUser objects come from configuration (see api-users.conf) because Icinga
2 has no runtime creation for that type. Everything here goes through the real
API, as a real operator's provisioning tool would: PUT /v1/objects/hosts/<name>
creates a runtime object, and Icinga's own shipped apply rules then decide which
host groups it lands in and which service checks get attached to it. Nothing
below asserts those decisions -- it reports them, so the manifest can assert
what Icinga really did rather than what this script asked for.

Two details are not obvious and both cost a debugging session if missed:

* **Accept: application/json is mandatory on writes.** Without it Icinga
  answers `<h1>Accept header is missing or not set to 'application/json'.</h1>`
  with an HTML body -- not a JSON error, and not a 415 either.

* **Host state has to be frozen before the run.** A host with active checks
  enabled changes state underneath the test: the seeded addresses are
  unreachable, so they start UP and go DOWN a check interval later, and the
  built-in host is DOWN until its first check succeeds. Anything asserted about
  state would then pass or fail on timing. So the seeded hosts are created with
  checks disabled, and the built-in host is left to complete one real check and
  is then frozen by the same means.
"""

import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["RZ_BASE"].rstrip("/")

# Must match api-users.conf.
SEED_USER, SEED_PASSWORD = "runzero-seed", "runzero-seed-pw-2026"
READ_USER, READ_PASSWORD = "runzero", "runzero-test-pw-2026"

# Must match compose.yml's ICINGA_CN: the shipped conf.d/hosts.conf names its
# one Host object after NodeName, which node setup sets from the CN.
BUILTIN_HOST = "rz-icinga-master"

HTTP_TIMEOUT = 30
API_DEADLINE = 300
CHECK_DEADLINE = 300

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# The four hosts this case imports, each chosen for one thing the integration
# has to get right against data an operator really produces.
HOSTS = [
    # A conventional server: routable address, a MAC parked in a custom
    # variable (Icinga models no hardware at all, so that is the only place one
    # can appear), and an OS. The MAC carries the locally-administered bit, so
    # the platform emits it as a8:bb:cc:11:22:33.
    ("rz-web01.lab.example.com", {
        "address": "10.223.4.21",
        "check_command": "hostalive",
        "enable_active_checks": False,
        "vars": {"os": "Linux", "mac": "AA:BB:CC:11:22:33",
                 "location": "DC1 rack 14", "environment": "lab"},
    }),
    # display_name is a human caption with spaces in it -- far more common in
    # the field than a second FQDN -- and must not become a hostname. The MAC
    # lives under `hwaddr` here rather than `mac`, which is the other spelling
    # the integration accepts.
    ("rz-core-switch", {
        "address": "10.223.4.22",
        "display_name": "Core switch 01",
        "check_command": "hostalive",
        "enable_active_checks": False,
        "vars": {"os": "Cisco IOS", "hwaddr": "0c:c4:7a:1b:2c:3d"},
    }),
    # 169.254/16 is what a host reports when DHCP failed. The platform's
    # IsUnicast deliberately KEEPS link-local, so this address reaches the asset
    # unless the integration filters it -- and two unrelated hosts that both
    # failed DHCP would then correlate to each other.
    ("rz-apipa-only", {
        "address": "169.254.10.5",
        "check_command": "hostalive",
        "enable_active_checks": False,
        "vars": {"os": "Linux"},
    }),
    # `address` is a plain string attribute Icinga never validates, and filling
    # it with a DNS name is the norm on installs that let DNS do the resolving.
    # It has to be classified by what it is, not by which attribute it arrived
    # in: a name here, an address in the rows above.
    ("rz-dns-addressed", {
        "address": "ns1.lab.example.com",
        "check_command": "hostalive",
        "enable_active_checks": False,
        "vars": {"os": "Linux"},
    }),
]


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def note(message):
    # Diagnostics go to stderr: the harness parses the LAST STDOUT LINE as JSON.
    print(message, file=sys.stderr)


def call(path, payload=None, method="GET", user=READ_USER, password=READ_PASSWORD,
         override=None):
    """One Icinga API call. Returns (status, parsed-or-text)."""
    headers = {
        "Accept": "application/json",
        "Authorization": "Basic " + base64.b64encode(
            ("%s:%s" % (user, password)).encode()).decode(),
    }
    body = None
    if payload is not None:
        body = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    if override:
        # The same trick the integration uses: the API rejects a body on a GET,
        # so a read that needs one is a POST carrying this header.
        headers["X-HTTP-Method-Override"] = override
    request = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT, context=CTX) as response:
            status, text = response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status, text = exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, str(exc)
    try:
        return status, json.loads(text)
    except ValueError:
        return status, text


def wait_for_api():
    """Wait until the ApiUser from config authenticates.

    A 401 means the listener is up but the configuration has not been loaded
    yet, so this gates on a real 200 rather than on the port opening.
    """
    deadline = time.time() + API_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, body = call("/v1/status/IcingaApplication")
        if status == 200 and isinstance(body, dict):
            app = (((body.get("results") or [{}])[0].get("status") or {})
                   .get("icingaapplication") or {}).get("app") or {}
            version = str(app.get("version") or "")
            note("Icinga API answering, version %s" % version)
            return version
        last = "status %s: %s" % (status, str(body)[:120])
        time.sleep(3)
    die("the Icinga 2 API never accepted the configured ApiUser within %ds (last: %s). "
        "Check that api-users.conf was mounted into conf.d and parsed." % (API_DEADLINE, last))


def query_hosts(attrs):
    status, body = call("/v1/objects/hosts", {"attrs": attrs}, method="POST", override="GET")
    if status != 200 or not isinstance(body, dict):
        return None
    return {r.get("name"): (r.get("attrs") or {})
            for r in (body.get("results") or []) if isinstance(r, dict)}


def freeze(name):
    """Turn active checks off, so the host's state stops moving."""
    status, body = call("/v1/objects/hosts/" + urllib.parse.quote(name),
                        {"attrs": {"enable_active_checks": False}},
                        method="POST", user=SEED_USER, password=SEED_PASSWORD)
    if status != 200:
        die("could not disable active checks on %s: status %s: %s" % (name, status, str(body)[:200]))


def main():
    version = wait_for_api()

    for name, attrs in HOSTS:
        payload = {"templates": ["generic-host"], "attrs": attrs}
        status, body = call("/v1/objects/hosts/" + urllib.parse.quote(name), payload,
                            method="PUT", user=SEED_USER, password=SEED_PASSWORD)
        if status != 200:
            die("creating host %s failed with status %s: %s" % (name, status, str(body)[:300]))
    note("created %d host objects" % len(HOSTS))

    # Let the built-in host complete one real check, then stop it moving. Its
    # state is the one thing here produced by Icinga actually executing a
    # monitoring plugin rather than by this script asserting a value.
    deadline = time.time() + CHECK_DEADLINE
    builtin = {}
    last = "never checked"
    while time.time() < deadline:
        hosts = query_hosts(["name", "state", "last_check", "last_check_result"]) or {}
        builtin = hosts.get(BUILTIN_HOST) or {}
        if float(builtin.get("last_check") or 0) > 0:
            break
        last = "last_check=%s" % builtin.get("last_check")
        time.sleep(3)
    else:
        note("WARNING: the built-in host never completed a check (%s); freezing anyway" % last)

    freeze(BUILTIN_HOST)

    # Read everything back the way the integration will, so the manifest gets
    # the values Icinga settled on rather than the ones this script asked for.
    attrs = ["name", "display_name", "address", "address6", "groups", "vars",
             "state", "last_check", "last_check_result", "templates", "check_command"]
    hosts = query_hosts(attrs)
    if hosts is None:
        die("could not read the host objects back")
    for name, _ in HOSTS:
        if name not in hosts:
            die("host %s was created but does not appear in the object query" % name)

    status, body = call("/v1/objects/services",
                        {"attrs": ["host_name", "name", "display_name", "state", "check_command"]},
                        method="POST", override="GET")
    services = [r for r in ((body or {}).get("results") or []) if isinstance(r, dict)]
    per_host = {}
    for entry in services:
        host = ((entry.get("attrs") or {}).get("host_name") or "")
        per_host[host] = per_host.get(host, 0) + 1
    note("services per host: %s" % json.dumps(per_host, sort_keys=True))

    builtin = hosts.get(BUILTIN_HOST) or {}
    builtin_state = int(float(builtin.get("state") or 0))
    result = {
        "api_version": version,
        "username": READ_USER,
        "password": READ_PASSWORD,
        "builtin_host": BUILTIN_HOST,
        "builtin_state": {0: "UP", 1: "DOWN"}.get(builtin_state, ""),
        "builtin_state_code": builtin_state,
        "builtin_groups": ",".join(sorted(builtin.get("groups") or [])),
        "builtin_check_count": per_host.get(BUILTIN_HOST, 0),
        "web_check_count": per_host.get("rz-web01.lab.example.com", 0),
        "switch_check_count": per_host.get("rz-core-switch", 0),
        "apipa_check_count": per_host.get("rz-apipa-only", 0),
        "dns_check_count": per_host.get("rz-dns-addressed", 0),
        "host_count": len(hosts),
        "service_count": len(services),
        "web_groups": ",".join(sorted((hosts.get("rz-web01.lab.example.com") or {}).get("groups") or [])),
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
