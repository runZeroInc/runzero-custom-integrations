#!/usr/bin/env python3
"""Take a blank GLPI from first boot to an instance the integration can read,
without a human touching Setup -> General -> API.

A fresh GLPI ships with its REST API switched OFF -- `enable_api` is 0 in
glpi_configs, and `enable_api_login_credentials` is 0 as well -- and with a
single API client restricted to 127.0.0.1. That combination is the most common
GLPI integration failure, so the seed reproduces the operator's fix rather than
sidestepping it:

  1. `bin/console config:set` turns on `enable_api`,
     `enable_api_login_credentials` and `enable_api_login_external_token`, and
     turns on `enabled_inventory` in the *inventory* context. The context
     matters: `config:set` defaults to `core`, and setting `enabled_inventory`
     without `-c inventory` writes a second, ignored row while the native
     inventory endpoint keeps answering "Inventory is disabled".
  2. An API client with an App-Token and no IP restriction is created THROUGH
     THE API, from inside the container. GLPI matches the caller's source
     address against glpi_apiclients before it looks at any token, so the
     shipped "full access from localhost" client only answers to 127.0.0.1 --
     and the scanner runs on the host, which reaches GLPI as the compose bridge
     gateway. Bootstrapping from inside the container is the only way in that
     does not poke the database.
  3. A personal API token is set on the `glpi` user, so the integration runs
     over the credential CONFIG actually prefers.

Then three records are created, each one there to settle a claim the offline
fixtures only assert:

  * `rz-inv-01` arrives through GLPI's NATIVE INVENTORY endpoint, carrying the
    GLPI container's own eth0 MAC and address plus its loopback. GLPI files the
    loopback as a NetworkPortLocal, which is the port class the integration
    drops -- so the emitted asset having exactly one port, and no 127.0.0.1, is
    the record-level evidence that the filter works on data the software wrote
    rather than on data a fixture author invented. The container MAC is locally
    administered, so the platform's network_interface() clears that bit and the
    emitted MAC differs from the one GLPI stores.
  * `rz-future-02` is stamped with a date_creation and a last_inventory_update
    in 2027. GLPI stores and returns both verbatim. runZero rejects an entire
    asset record whose first- or last-seen time is in the future, so this row
    exists purely to prove the integration's clamp keeps it.
  * `rz-switch-01` is a NetworkEquipment. GLPI runs a separate auto-increment
    per item type, so it takes an id that a Computer already holds. The seed
    fails loudly if that collision does NOT happen, because the whole point of
    putting the ItemType in the foreign id is that it does.
"""

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"]
PROJECT = os.environ["RZ_PROJECT"]
COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
SERVICE = os.environ["RZ_SERVICE"]

ADMIN_USER = "glpi"
ADMIN_PASSWORD = "glpi"

# The GLPI-Agent inventory schema validates every field it is handed, so these
# are the spellings it accepts: lowercase link states, and a deviceid whose
# trailing six dash-separated fields are the moment the agent minted it.
INVENTORY_NAME = "rz-inv-01"
INVENTORY_DEVICEID = INVENTORY_NAME + "-2026-01-15-09-30-00"
FUTURE_NAME = "rz-future-02"
SWITCH_NAME = "rz-switch-01"
FUTURE_CREATED = "2027-03-01 12:00:00"
FUTURE_INVENTORIED = "2027-03-02 12:00:00"
# GLPI round-trips text through its legacy input sanitizer, so this comes back
# as "HQ &#62; Floor 2 &#38; ...". The integration decodes it again.
FUTURE_COMMENT = 'HQ > Floor 2 & "lab"'


def compose(*args, timeout=300):
    argv = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE] + list(args)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        sys.exit("docker compose %s failed (%d):\n%s\n%s" % (
            args[0], proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]))
    return proc.stdout


def in_container(shell, timeout=300):
    return compose("exec", "-T", SERVICE, "sh", "-c", shell, timeout=timeout)


def console(*args):
    """Run a GLPI console command as the web user, as the docs describe."""
    quoted = " ".join("'%s'" % a for a in args)
    return in_container("su www-data -s /bin/bash -c 'cd /var/www/glpi && php bin/console %s "
                        "--no-interaction'" % quoted.replace("'", "'\"'\"'"))


def request(path, method="GET", headers=None, body=None, timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    head = {"Accept": "application/json"}
    if data:
        head["Content-Type"] = "application/json"
    head.update(headers or {})
    req = urllib.request.Request(BASE + path, data=data, headers=head, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as exc:
        sys.exit("%s %s failed: %s %s" % (method, path, exc.code, exc.read().decode()[:500]))
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except ValueError:
        sys.exit("%s %s did not return JSON:\n%s" % (method, path, raw[:500]))


def attach(headers, itemtype, items_id, port_name, mac, address, hostname):
    """Give an item a network port with a MAC and one address.

    GLPI models this as three linked rows -- NetworkPort, a NetworkName hanging
    off the port, an IPAddress hanging off the name -- and the integration reads
    them back through the `with_networkports` expansion.
    """
    port = request("/apirest.php/NetworkPort", "POST", headers, {"input": {
        "itemtype": itemtype, "items_id": items_id, "name": port_name, "mac": mac,
        "instantiation_type": "NetworkPortEthernet", "logical_number": 1,
    }})["id"]
    name = request("/apirest.php/NetworkName", "POST", headers, {"input": {
        "itemtype": "NetworkPort", "items_id": port, "name": hostname,
    }})["id"]
    request("/apirest.php/IPAddress", "POST", headers, {"input": {
        "itemtype": "NetworkName", "items_id": name, "name": address,
    }})


def normalize_mac(mac):
    """What the platform's network_interface() will do to this MAC.

    It clears the locally administered bit, so a container-assigned address is
    not the address that reaches the asset.
    """
    octets = mac.lower().split(":")
    octets[0] = "%02x" % (int(octets[0], 16) & 0xFD)
    return ":".join(octets)


def main():
    # --- 1. the settings page, without the settings page ------------------
    for key in ("enable_api", "enable_api_login_credentials",
                "enable_api_login_external_token"):
        console("config:set", key, "1")
    # `-c inventory` is load-bearing; see the module docstring.
    console("config:set", "-c", "inventory", "enabled_inventory", "1")

    # --- 2. an API client the host is actually allowed to use -------------
    app_token = secrets.token_hex(20)
    opened = in_container(
        'curl -sS -H "Authorization: Basic $(printf %s:%s | base64)"'
        ' -H "Accept: application/json" http://localhost/apirest.php/initSession'
        % (ADMIN_USER, ADMIN_PASSWORD))
    match = re.search(r'"session_token"\s*:\s*"([0-9a-zA-Z]+)"', opened)
    if not match:
        sys.exit("could not open a bootstrap session from inside the container: %s"
                 % opened[:400])
    # No ipv4_range_* at all: a NULL range is how GLPI spells "any address", and
    # the scanner arrives from whatever the compose bridge gateway happens to be.
    payload = json.dumps({"input": {
        "name": "runzero container test", "is_active": 1, "app_token": app_token}})
    created = in_container(
        'curl -sS -X POST -H "Session-Token: %s" -H "Content-Type: application/json"'
        " -d '%s' http://localhost/apirest.php/APIClient" % (match.group(1), payload))
    if '"id"' not in created:
        sys.exit("could not create the API client: %s" % created[:400])

    # --- 3. the credential the integration will use -----------------------
    basic = base64.b64encode(("%s:%s" % (ADMIN_USER, ADMIN_PASSWORD)).encode()).decode()
    session = request("/apirest.php/initSession",
                      headers={"App-Token": app_token,
                               "Authorization": "Basic " + basic}).get("session_token", "")
    if not session:
        sys.exit("initSession over the published port returned no session token")
    api_headers = {"App-Token": app_token, "Session-Token": session}

    users = request("/apirest.php/User?range=0-99", headers=api_headers)
    admin = next((u for u in users if u.get("name") == ADMIN_USER), None)
    if not admin:
        sys.exit("no %r user in a fresh install: %s"
                 % (ADMIN_USER, [u.get("name") for u in users]))
    user_token = secrets.token_hex(20)
    request("/apirest.php/User/%s" % admin["id"], "PUT", api_headers,
            {"input": {"id": admin["id"], "api_token": user_token}})
    # Prove the token the manifest is about to hand the integration really works
    # before anything is seeded, so a credential problem cannot masquerade as a
    # parsing problem later.
    check = request("/apirest.php/initSession",
                    headers={"App-Token": app_token,
                             "Authorization": "user_token " + user_token})
    if not check.get("session_token"):
        sys.exit("the personal API token did not authenticate")
    request("/apirest.php/killSession",
            headers={"App-Token": app_token, "Session-Token": check["session_token"]})

    # --- 4. a computer GLPI's own inventory pipeline created ---------------
    facts = in_container(
        'cat /sys/class/net/eth0/address && php -r "echo gethostbyname(gethostname());"')
    parts = [line.strip() for line in facts.splitlines() if line.strip()]
    if len(parts) < 2:
        sys.exit("could not read the container's own eth0: %r" % facts)
    agent_mac, agent_ip = parts[0], parts[-1]
    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", agent_mac):
        sys.exit("container eth0 MAC looks wrong: %r" % agent_mac)

    inventory = {
        "action": "inventory",
        "itemtype": "Computer",
        "deviceid": INVENTORY_DEVICEID,
        "content": {
            "versionclient": "GLPI-Agent_v1.10",
            "hardware": {"name": INVENTORY_NAME,
                         "uuid": "6f1e7b8a-0000-4000-8000-000000000001"},
            "bios": {"smanufacturer": "Dell Inc.", "smodel": "PowerEdge R650",
                     "ssn": "SVC-INV-01", "mmanufacturer": "Dell Inc.",
                     "msn": "MB-INV-01"},
            "operatingsystem": {"full_name": "Debian GNU/Linux 12 (bookworm)",
                                "name": "Debian", "version": "12", "arch": "x86_64",
                                "kernel_name": "linux", "kernel_version": "6.1.0"},
            "networks": [
                {"description": "eth0", "ipaddress": agent_ip, "ipmask": "255.255.0.0",
                 "mac": agent_mac, "status": "up", "type": "ethernet",
                 "virtualdev": False},
                # The container's real loopback. GLPI files this as a
                # NetworkPortLocal carrying 127.0.0.1, which is exactly the port
                # class and the address the integration has to drop.
                {"description": "lo", "ipaddress": "127.0.0.1", "ipmask": "255.0.0.0",
                 "mac": "00:00:00:00:00:00", "status": "up", "type": "loopback",
                 "virtualdev": True},
            ],
            "softwares": [
                {"name": "openssh-server", "version": "9.2p1", "publisher": "Debian",
                 "system_category": "admin"},
            ],
        },
    }
    answer = request("/front/inventory.php", "POST",
                     {"User-Agent": "GLPI-Agent_v1.10"}, inventory)
    if answer.get("RESPONSE") != "SEND":
        sys.exit("GLPI refused the inventory: %s" % json.dumps(answer)[:500])

    computers = request("/apirest.php/Computer?range=0-99&get_hateoas=false",
                        headers=api_headers)
    inventory_id = next((c["id"] for c in computers if c.get("name") == INVENTORY_NAME), None)
    if inventory_id is None:
        sys.exit("the inventory was accepted but created no computer: %s"
                 % [c.get("name") for c in computers])

    # --- 5. the record that only survives if the clamp works ---------------
    type_id = request("/apirest.php/ComputerType", "POST", api_headers,
                      {"input": {"name": "Server"}})["id"]
    future_id = request("/apirest.php/Computer", "POST", api_headers, {"input": {
        "name": FUTURE_NAME, "serial": "SVC-FUT-02", "otherserial": "INV-0002",
        "comment": FUTURE_COMMENT, "computertypes_id": type_id,
    }})["id"]
    attach(api_headers, "Computer", future_id, "eno1", "00:11:22:33:44:55",
           "10.77.0.12", FUTURE_NAME)
    # Written last so that adding the port cannot overwrite it.
    request("/apirest.php/Computer/%s" % future_id, "PUT", api_headers, {"input": {
        "id": future_id,
        "date_creation": FUTURE_CREATED,
        "last_inventory_update": FUTURE_INVENTORIED,
    }})
    stored = request("/apirest.php/Computer/%s?get_hateoas=false" % future_id,
                     headers=api_headers)
    if stored.get("date_creation") != FUTURE_CREATED or \
            stored.get("last_inventory_update") != FUTURE_INVENTORIED:
        sys.exit("GLPI did not keep the future timestamps: %s / %s"
                 % (stored.get("date_creation"), stored.get("last_inventory_update")))

    # --- 6. the id collision the ItemType namespace exists to survive ------
    switch_id = request("/apirest.php/NetworkEquipment", "POST", api_headers, {"input": {
        "name": SWITCH_NAME, "serial": "SN-SW-01",
        "sysdescr": "Cisco IOS Software, Catalyst L3 Switch Software",
    }})["id"]
    attach(api_headers, "NetworkEquipment", switch_id, "Po1", "00:11:22:33:44:66",
           "10.77.0.13", SWITCH_NAME)
    computer_ids = {inventory_id, future_id}
    if switch_id not in computer_ids:
        sys.exit("NetworkEquipment took id %s, which no Computer holds (%s); this "
                 "scenario cannot prove the ItemType belongs in the foreign id"
                 % (switch_id, sorted(computer_ids)))

    request("/apirest.php/killSession", headers=api_headers)

    print(json.dumps({
        "app_token": app_token,
        "user_token": user_token,
        "inventory_id": inventory_id,
        "future_id": future_id,
        "switch_id": switch_id,
        "agent_mac": agent_mac,
        "agent_mac_normalized": normalize_mac(agent_mac),
        "agent_ip": agent_ip,
    }))


if __name__ == "__main__":
    main()
