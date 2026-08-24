#!/usr/bin/env python3
"""Take a first-boot Zabbix to an instance with a real API token and real hosts.

Everything here goes through the same JSON-RPC endpoint the integration uses, so
the records under test were written the way an operator writes them -- no SQL
reaches around the API.

  1. Poll api_jsonrpc.php until the frontend answers. The HTTP port opens while
     the server is still importing several thousand schema statements, so "the
     port is open" is not readiness; "apiinfo.version answers" is.
  2. user.login as the shipped Admin, then token.create + token.generate for a
     real API token. The session id would also work as a Bearer credential, but
     an API token is what an operator would configure and what the CONFIG
     parameter documents.
  3. Create one host group and six hosts, each chosen to exercise a decision the
     integration makes on data no hand-written fixture would invent.

The hosts, and what each one is for:

  rz-core-switch    Fully populated: two interfaces on one address, both
                    inventory MACs, and six inventory fields. Proves interface
                    -> Service, inventory -> Software, and the device-type map.
  rz-dns-by-name    useip=0, so Zabbix stores an EMPTY ip and addresses the host
                    by DNS. A Service needs an address, so this host must emit
                    zero services while keeping its DNS name as a hostname.
                    Roughly a third of a real Zabbix estate looks like this.
  rz-apipa-only     A 169.254/16 interface -- what a host reports when DHCP
                    failed. The platform KEEPS link-local, so if the integration
                    did not filter it, two unrelated such hosts would correlate
                    to each other. The invariant only catches this because a
                    real address of this shape is present.
  rz-junk-mac       inventory macaddress_a is free text and macaddress_b is
                    all-zero. Both are real things sites put in those fields;
                    neither may reach a NetworkInterface.
  rz-macro-port     An interface whose port is a {$MACRO} reference only the
                    server can resolve. Zabbix accepts it; it is not a number.
  rz-disabled       status=1. Must be absent unless include_disabled is set.

Plus the "Zabbix server" host Zabbix creates itself, which is left exactly as
shipped: a name with a space in it, on 127.0.0.1. That row is not seeded, it is
discovered, because what it proves is what the real product ships.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"]
ENDPOINT = BASE + "/api_jsonrpc.php"

ADMIN_USER = "Admin"
ADMIN_PASSWORD = "zabbix"

GROUP_NAME = "runZero Container Test"

# Chosen to sit well clear of Docker's own pools so nothing here can be confused
# with an address the harness or the host actually owns. Zabbix stores these as
# plain configuration -- nothing is ever polled -- so they need not be routable.
NET = "10.211.55."

_seq = [0]


def rpc(method, params, token=None, allow_error=False):
    _seq[0] += 1
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": _seq[0]}
    headers = {
        # Zabbix checks this before any JSON-RPC handling and answers a bare 412
        # with no body when it does not recognise the value.
        "Content-Type": "application/json-rpc",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        ENDPOINT, data=json.dumps(body).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as exc:
        raise RuntimeError("%s -> HTTP %s %s" % (method, exc.code, exc.read().decode()[:300]))
    try:
        payload = json.loads(raw)
    except ValueError:
        raise RuntimeError("%s did not return JSON: %s" % (method, raw[:300]))
    if "error" in payload:
        if allow_error:
            return None
        raise RuntimeError("%s -> %s" % (method, json.dumps(payload["error"])[:400]))
    return payload.get("result")


def wait_for_api(timeout=420, interval=3):
    """Bounded poll. The frontend answers HTTP long before the schema is in."""
    deadline = time.time() + timeout
    last = "never attempted"
    while time.time() < deadline:
        try:
            version = rpc("apiinfo.version", {})
            if version:
                return version
            last = "empty version"
        except Exception as exc:
            last = str(exc)[:200]
        time.sleep(interval)
    sys.exit("zabbix API never became ready within %ds (last: %s)" % (timeout, last))


def create_host(token, groupid, spec):
    params = {
        "host": spec["host"],
        "groups": [{"groupid": groupid}],
        "interfaces": spec.get("interfaces", []),
        "status": spec.get("status", 0),
    }
    for key in ("name", "description", "tags"):
        if key in spec:
            params[key] = spec[key]
    if "inventory" in spec:
        # -1 (disabled) is the shipped default, and selectInventory then answers
        # with an empty ARRAY rather than an object. Manual mode is what makes
        # the inventory an object at all.
        params["inventory_mode"] = 0
        params["inventory"] = spec["inventory"]
    result = rpc("host.create", params, token)
    return str(result["hostids"][0])


def main():
    version = wait_for_api()

    session = rpc("user.login", {"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    if not isinstance(session, str) or not session:
        sys.exit("user.login did not return a session string: %r" % (session,))

    users = rpc("user.get", {"output": ["userid"], "filter": {"username": [ADMIN_USER]}}, session)
    if not users:
        sys.exit("no %s user after login" % ADMIN_USER)
    userid = str(users[0]["userid"])

    created = rpc("token.create", {"name": "runzero-container-test", "userid": userid}, session)
    tokenid = str(created["tokenids"][0])
    generated = rpc("token.generate", [tokenid], session)
    token = generated[0]["token"]
    if len(token) < 32:
        sys.exit("generated API token looks wrong: %r" % token[:60])
    # The runZero CLI splits a --kwargs value on commas into a fabricated second
    # parameter, so a credential containing one cannot be passed at all. Zabbix
    # mints 64 hex characters; check rather than assume.
    if "," in token:
        sys.exit("generated API token contains a comma and cannot be passed as a kwarg")

    groupid = str(rpc("hostgroup.create", {"name": GROUP_NAME}, token)["groupids"][0])

    hosts = [
        {
            "key": "switch_id",
            "host": "rz-core-switch",
            "name": "rz-core-switch",
            "description": "Fully populated host: two interfaces, both inventory MACs.",
            "interfaces": [
                {"type": 1, "main": 1, "useip": 1, "ip": NET + "21", "dns": "", "port": "10050"},
                {"type": 2, "main": 1, "useip": 1, "ip": NET + "21", "dns": "", "port": "161",
                 "details": {"version": 2, "community": "{$SNMP_COMMUNITY}"}},
            ],
            "tags": [{"tag": "env", "value": "lab"}, {"tag": "critical", "value": ""}],
            "inventory": {
                "type": "Switch",
                "os": "Cisco IOS",
                "os_full": "Cisco IOS 15.2(4)E7",
                "macaddress_a": "0C:C4:7A:1B:2C:3D",
                "macaddress_b": "0c-c4-7a-1b-2c-3e",
                "serialno_a": "FDO1234X5YZ",
                "vendor": "Cisco",
                "model": "Catalyst 2960X",
                "software": "IOS",
                "software_app_a": "NX-API",
                "location": "Rack 4",
            },
        },
        {
            "key": "dns_id",
            "host": "rz-dns-by-name",
            "name": "rz-dns-by-name",
            # useip=0: Zabbix stores ip as the empty string and polls the DNS
            # name. A Service needs an address, so this must emit none.
            "interfaces": [
                {"type": 1, "main": 1, "useip": 0, "ip": "", "dns": "ns1.lab.example.com",
                 "port": "10050"},
            ],
            "inventory": {"type": "Server", "os": "Debian GNU/Linux"},
        },
        {
            "key": "apipa_id",
            "host": "rz-apipa-only",
            "name": "rz-apipa-only",
            "interfaces": [
                {"type": 1, "main": 1, "useip": 1, "ip": "169.254.10.5", "dns": "", "port": "10050"},
            ],
        },
        {
            "key": "junk_mac_id",
            "host": "rz-junk-mac",
            "name": "rz-junk-mac",
            "interfaces": [
                {"type": 1, "main": 1, "useip": 1, "ip": NET + "25", "dns": "", "port": "10050"},
            ],
            "inventory": {
                # Free text. macaddress_a and macaddress_b are not validated by
                # Zabbix in any way; this is what sites actually put in them.
                "macaddress_a": "see label on rear panel",
                "macaddress_b": "00:00:00:00:00:00",
            },
        },
        {
            "key": "macro_port_id",
            "host": "rz-macro-port",
            "name": "rz-macro-port",
            "interfaces": [
                {"type": 1, "main": 1, "useip": 1, "ip": NET + "26", "dns": "",
                 "port": "{$AGENT_PORT}"},
            ],
        },
        {
            "key": "disabled_id",
            "host": "rz-disabled",
            "name": "rz-disabled",
            "status": 1,
            "interfaces": [
                {"type": 1, "main": 1, "useip": 1, "ip": NET + "99", "dns": "", "port": "10050"},
            ],
        },
    ]

    out = {"api_version": version, "group_id": groupid, "group_name": GROUP_NAME}
    for spec in hosts:
        out[spec["key"]] = create_host(token, groupid, spec)

    # The shipped "Zabbix server" host is discovered rather than assumed: its id
    # and its enabled/disabled state are decisions the product makes, and this
    # test is here to observe them, not to encode a guess about them.
    builtin = rpc("host.get", {
        "output": ["hostid", "host", "name", "status"],
        "filter": {"host": ["Zabbix server"]},
    }, token)
    if not builtin:
        sys.exit("the shipped 'Zabbix server' host is missing; the schema import "
                 "did not run to completion")
    out["builtin_id"] = str(builtin[0]["hostid"])
    out["builtin_name"] = builtin[0]["name"]
    out["builtin_status"] = str(builtin[0]["status"])

    # How many host groups exist decides how many host.get chunks the run makes,
    # and the manifest sets group_chunk well below it on purpose so the chunking
    # loop and its cross-chunk dedupe run against real data.
    groups = rpc("hostgroup.get", {"output": ["groupid"]}, token)
    out["group_count"] = str(len(groups))

    out["api_token"] = token
    print(json.dumps(out))


if __name__ == "__main__":
    main()
