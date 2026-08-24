#!/usr/bin/env python3
"""Seed a fresh AdGuard Home so the integration has something to import.

A freshly started AdGuard Home has no user, no DHCP server, and no clients: it
sits on its first-run wizard and answers 403 to everything else. So the seed
walks the same three steps an operator would:

  1. finish the install wizard      POST /control/install/configure
  2. turn the DHCP server on        POST /control/dhcp/set_config
  3. add two static leases          POST /control/dhcp/add_static_lease

Step 3 is what makes this test worth running. DHCP leases are the only records
in the whole AdGuard API that carry a MAC address, so they are the only ones
that produce an asset with a real layer-2 identity -- everything else is an
address AdGuard happened to see send a query.

The lease values are constants rather than discoveries, because the compose
file pins the container's subnet for exactly that reason; see its comments.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"].rstrip("/")
USERNAME = "admin"
# Guards a container that is destroyed at the end of the test and never listens
# off loopback. Written down rather than generated so a failed run can be
# reproduced by hand.
PASSWORD = "runzero-test-pw-2026"

# Must match the compose file's `networks.lan` block.
INTERFACE = "eth0"
GATEWAY = "10.222.7.1"
NETMASK = "255.255.255.0"
RANGE_START = "10.222.7.100"
RANGE_END = "10.222.7.200"

# Two hosts, deliberately outside the dynamic range above so AdGuard stores them
# as static leases rather than handing the addresses out.
LEASES = [
    {"mac": "00:11:22:33:44:55", "ip": "10.222.7.11", "hostname": "web01"},
    {"mac": "00:11:22:33:44:66", "ip": "10.222.7.12", "hostname": "db01"},
]

API_TIMEOUT = 15
INSTALL_DEADLINE = 120
READY_DEADLINE = 120


def call(method, path, body=None, auth=True):
    """One /control/ call. Returns (status, parsed-or-text)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    if auth:
        import base64
        token = base64.b64encode(("%s:%s" % (USERNAME, PASSWORD)).encode()).decode()
        request.add_header("Authorization", "Basic " + token)
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT) as response:
            payload = response.read().decode("utf-8", "replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
        status = exc.code
    except Exception as exc:
        return 0, str(exc)
    try:
        return status, json.loads(payload)
    except ValueError:
        return status, payload


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def install():
    """Complete the first-run wizard, tolerating an instance already set up."""
    body = {
        "web": {"ip": "0.0.0.0", "port": 3000},
        "dns": {"ip": "0.0.0.0", "port": 53},
        "username": USERNAME,
        "password": PASSWORD,
    }
    deadline = time.time() + INSTALL_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, payload = call("POST", "/control/install/configure", body, auth=False)
        if status == 200:
            return
        # Once configured, the wizard endpoint is gone; 403/404 on a re-run
        # against a surviving container is expected, and the status check below
        # is what actually proves the instance is usable.
        if status in (403, 404):
            return
        last = "status %s: %s" % (status, str(payload)[:200])
        time.sleep(2)
    die("AdGuard Home install did not complete within %ds (last: %s)"
        % (INSTALL_DEADLINE, last))


def wait_running():
    """Wait until /control/status reports the DNS server actually running.

    The install call returns before the server has rebound its listeners, and
    /control/dhcp/set_config is rejected in that window.
    """
    deadline = time.time() + READY_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, payload = call("GET", "/control/status")
        if status == 200 and isinstance(payload, dict) and payload.get("running"):
            return payload
        last = "status %s: %s" % (status, str(payload)[:200])
        time.sleep(2)
    die("AdGuard Home never reported running within %ds (last: %s)" % (READY_DEADLINE, last))


def main():
    install()
    status_payload = wait_running()

    if not status_payload.get("dhcp_available"):
        die("AdGuard Home reports dhcp_available=false, so no lease can be seeded. "
            "The container needs CAP_NET_ADMIN; check the compose file.")

    status, payload = call("POST", "/control/dhcp/set_config", {
        "enabled": True,
        "interface_name": INTERFACE,
        "v4": {
            "gateway_ip": GATEWAY,
            "subnet_mask": NETMASK,
            "range_start": RANGE_START,
            "range_end": RANGE_END,
            "lease_duration": 86400,
        },
        "v6": {},
    })
    if status != 200:
        die("could not enable the AdGuard DHCP server (status %s): %s\n"
            "The DHCP range must lie inside the container's own subnet; if the "
            "compose file's fixed subnet changed, these constants must change too."
            % (status, str(payload)[:300]))

    for lease in LEASES:
        status, payload = call("POST", "/control/dhcp/add_static_lease", lease)
        # A re-run against a surviving container finds the lease already there.
        if status not in (200, 201) and "already exists" not in str(payload):
            die("could not add static lease %s (status %s): %s"
                % (lease["ip"], status, str(payload)[:300]))

    # Read the leases back rather than trusting the writes: this is the exact
    # payload the integration will parse, so if AdGuard stored something other
    # than what was sent, the seed fails here with a clear message instead of
    # the manifest failing later with a confusing field mismatch.
    status, dhcp = call("GET", "/control/dhcp/status")
    if status != 200 or not isinstance(dhcp, dict):
        die("could not read /control/dhcp/status back (status %s)" % status)
    stored = {entry.get("ip"): entry for entry in (dhcp.get("static_leases") or [])}
    for lease in LEASES:
        if lease["ip"] not in stored:
            die("static lease %s is missing after seeding; AdGuard stored %s"
                % (lease["ip"], sorted(stored)))

    print(json.dumps({
        "version": str(status_payload.get("version") or ""),
        "appliance_ip": "10.222.7.2",
        "web01_mac": LEASES[0]["mac"],
        "web01_ip": LEASES[0]["ip"],
        "db01_mac": LEASES[1]["mac"],
        "db01_ip": LEASES[1]["ip"],
        "static_lease_count": len(dhcp.get("static_leases") or []),
    }))


if __name__ == "__main__":
    main()
