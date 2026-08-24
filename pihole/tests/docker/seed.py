#!/usr/bin/env python3
"""Wait for Pi-hole to discover the client container, and report the row ids.

There is nothing to create here. The compose file starts a container that sends
real DNS queries, and FTL discovers it exactly as it discovers a laptop on a
home LAN -- so this script's job is to wait for that discovery to land and then
tell the manifest which rows it produced.

Why the ids have to be discovered: /api/network/devices keys every device on
FTL's own auto-increment row id, and which number a device gets depends on the
order FTL happened to see them in. Hard-coding `1` and `4` would pass on this
machine and fail on a slower one.

Three devices are expected, and the third is the interesting one:

  * the client container   -- a real MAC and a real address
  * the Pi-hole's own NIC  -- a real MAC and a real address
  * the loopback interface -- hwaddr 00:00:00:00:00:00, ip 127.0.0.1

That last row is not contrived; it is what Pi-hole genuinely reports for its own
`lo`. The integration must drop it, and the manifest asserts that by id, which
is why its row id is reported too.

The session is released on the way out. Pi-hole v6 allows a small fixed number
of concurrent API sessions and refuses new logins once they are used up, so a
seed that leaks its session would break the integration's own login on a later
run rather than at the point of the mistake.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"].rstrip("/") + "/api"
PASSWORD = "runzero-test-pw-2026"

# Must match the compose file.
CLIENT_MAC = "00:11:22:33:44:55"
CLIENT_IP = "10.222.8.11"
APPLIANCE_MAC = "02:42:0a:de:08:02"
APPLIANCE_IP = "10.222.8.2"
LOOPBACK_MAC = "00:00:00:00:00:00"

API_TIMEOUT = 15
LOGIN_DEADLINE = 180
# FTL rebuilds its network table on a timer rather than per query; observed at
# roughly 40s on an idle machine, so this allows generous headroom while still
# failing rather than hanging.
DISCOVERY_DEADLINE = 300


def call(method, path, body=None, sid=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data else {}
    if sid:
        headers["sid"] = sid
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
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


def login():
    deadline = time.time() + LOGIN_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, body = call("POST", "/auth", {"password": PASSWORD})
        if status == 200 and isinstance(body, dict):
            sid = (body.get("session") or {}).get("sid")
            if sid:
                return sid
        last = "status %s: %s" % (status, str(body)[:200])
        time.sleep(3)
    die("could not authenticate to Pi-hole within %ds (last: %s). If this says the "
        "session limit is reached, an earlier run leaked its session; restart the "
        "container." % (LOGIN_DEADLINE, last))


def devices(sid):
    status, body = call("GET", "/network/devices?max_devices=100&max_addresses=32", sid=sid)
    if status != 200 or not isinstance(body, dict):
        return []
    return [d for d in (body.get("devices") or []) if isinstance(d, dict)]


def main():
    sid = login()
    try:
        deadline = time.time() + DISCOVERY_DEADLINE
        found = {}
        last = "no devices yet"
        while time.time() < deadline:
            by_mac = {}
            for device in devices(sid):
                mac = str(device.get("hwaddr") or "").lower()
                if mac:
                    by_mac[mac] = device
            if CLIENT_MAC in by_mac and APPLIANCE_MAC in by_mac:
                found = by_mac
                break
            last = "saw %s" % (sorted(by_mac) or "nothing")
            time.sleep(5)
        else:
            die("Pi-hole never discovered both the client (%s) and its own NIC (%s) "
                "within %ds (last: %s). The client container sends a query every 2s; "
                "check that it started and that FTL is listening on all interfaces."
                % (CLIENT_MAC, APPLIANCE_MAC, DISCOVERY_DEADLINE, last))

        client = found[CLIENT_MAC]
        appliance = found[APPLIANCE_MAC]
        loopback = found.get(LOOPBACK_MAC)
        if loopback is None:
            die("Pi-hole did not report its loopback interface. This case exists to "
                "prove the all-zero MAC on `lo` is dropped, so without that row the "
                "assertion would pass for the wrong reason.")

        # Verify the addresses landed where expected before reporting them, so a
        # mis-seeded network fails here rather than as a puzzling field mismatch.
        client_ips = [a.get("ip") for a in (client.get("ips") or [])]
        if CLIENT_IP not in client_ips:
            die("the client device holds %s, expected %s" % (client_ips, CLIENT_IP))

        result = {
            "client_device_id": client.get("id"),
            "client_mac": CLIENT_MAC,
            "client_ip": CLIENT_IP,
            "client_mac_vendor": str(client.get("macVendor") or ""),
            "appliance_device_id": appliance.get("id"),
            "appliance_ip": APPLIANCE_IP,
            "appliance_hwaddr": APPLIANCE_MAC,
            "loopback_device_id": loopback.get("id"),
            "device_count": len(found),
        }
    finally:
        # Always release the seat, including on the failure paths above.
        call("DELETE", "/auth", sid=sid)

    print(json.dumps(result))


if __name__ == "__main__":
    main()
