#!/usr/bin/env python3
"""Take a freshly migrated LibreNMS to an instance with an API token and three
devices, one of which is genuinely polled over SNMP.

Everything that has a supported command uses it -- `lnms user:add`,
`lnms device:add`, `lnms device:discover`, `lnms device:poll` are the same
commands the install documentation gives an operator. Only the API token is
written directly, because LibreNMS ships no CLI for one: tokens are minted from
the web UI, and `lnms list` has no token command at all. The row is exactly what
ApiToken::generateToken() writes -- user_id, a bin2hex(random_bytes(16)) value
in token_hash, a description, disabled=0 -- and the token is generated here with
the same shape rather than being a constant, so nothing downstream can quietly
depend on a hard-coded credential.

The three devices, and what each is for:

  10.221.9.5   The real one. A net-snmp agent running in the stack, discovered
               and polled over SNMPv2c, so its ports, its ifPhysAddress, its
               bound addresses and its ARP table all come from an actual SNMP
               walk rather than from a fixture author's imagination. This is the
               device that makes the collection paths real: it publishes an
               eth0 whose ifPhysAddress is the container MAC, an lo with a NULL
               ifPhysAddress, and -- because the agent answered the poller --
               an ARP entry for the poller itself.

  10.221.9.1   Ping-only. LibreNMS records it with snmp_disable=1, no ports and
               no addresses of its own, which is a perfectly ordinary state for
               a real estate and one that has to survive the per-device calls
               answering 404.

  10.221.9.77  Added with --force and SNMPv3 credentials, never reachable. It
               exists to put authname/authpass/cryptopass into the devices
               table, so the assertion that those never reach a runZero
               attribute is made against a server that really is returning them.
               It also exercises the never-polled shape: no ip, no ports, and a
               sysName LibreNMS defaults to the bare hostname.
"""

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"]
PROJECT = os.environ["RZ_PROJECT"]
COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
APP = os.environ.get("RZ_SERVICE") or "librenms"
DB = "db"

ADMIN_USER = "runzero"
ADMIN_PASSWORD = "RunZeroContainerTest123!"

AGENT_IP = "10.221.9.5"
AGENT_COMMUNITY = "rzpublic"
GATEWAY_IP = "10.221.9.1"
UNREACHABLE_IP = "10.221.9.77"

# Deliberately not a real credential anywhere. The point of the row is that the
# API hands these back in cleartext; they authenticate against nothing.
V3_USER = "rzv3user"
V3_AUTH_PASS = "rzAuthPass123"
V3_PRIV_PASS = "rzPrivPass123"


def compose(service, argv, timeout=600, check=True):
    full = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
            "exec", "-T", service] + list(argv)
    proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        sys.exit("`%s` failed (%d):\n%s\n%s" % (
            " ".join(argv), proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]))
    return (proc.stdout or "") + (proc.stderr or "")


def lnms(argv, timeout=600, check=True):
    return compose(APP, ["lnms"] + list(argv), timeout=timeout, check=check)


def sql(statement, timeout=120):
    return compose(DB, ["mariadb", "-ulibrenms", "-plibrenms", "librenms",
                        "--skip-column-names", "-e", statement], timeout=timeout)


def api(path, token, timeout=120):
    request = urllib.request.Request(
        BASE + path, headers={"X-Auth-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        sys.exit("GET %s failed: %s %s" % (path, exc.code, exc.read().decode()[:400]))


def wait_for_snmp(timeout=180, interval=3):
    """Bounded poll: the agent has to answer before a device can be added.

    device:add without --force does a real snmpget, so adding the device before
    the agent is listening fails with a message about SNMP rather than about
    timing, and the run would look like an integration bug.
    """
    deadline = time.time() + timeout
    last = "never attempted"
    while time.time() < deadline:
        out = compose(APP, ["snmpget", "-v2c", "-c", AGENT_COMMUNITY, "-t", "2",
                            AGENT_IP, "SNMPv2-MIB::sysName.0"], timeout=60, check=False)
        if "rz-snmp-target" in out:
            return
        last = out.strip()[-200:]
        time.sleep(interval)
    sys.exit("the SNMP agent never answered within %ds (last: %s)" % (timeout, last))


def main():
    lnms(["user:add", ADMIN_USER, "-p", ADMIN_PASSWORD, "-r", "admin",
          "-e", "runzero@example.com"])

    # ApiToken::randomTokenValue() is bin2hex(random_bytes(16)); same shape here.
    # Hex only, so it can never contain the comma that the runZero CLI would
    # split into a fabricated second parameter.
    token = secrets.token_hex(16)
    sql("insert into api_tokens (user_id, token_hash, description, disabled) "
        "select user_id, '%s', 'runzero-container-test', 0 from users "
        "where username='%s';" % (token, ADMIN_USER))
    if sql("select count(*) from api_tokens where token_hash='%s';" % token).strip() != "1":
        sys.exit("the API token row was not written")

    wait_for_snmp()

    # ifName association matches what the LibreNMS docs recommend for Linux and
    # UNIX hosts, and is what makes the port rows stable across re-discovery.
    lnms(["device:add", AGENT_IP, "--v2c", "--community", AGENT_COMMUNITY,
          "--port-association-mode", "ifName"])
    lnms(["device:discover", AGENT_IP])
    lnms(["device:poll", AGENT_IP])

    lnms(["device:add", GATEWAY_IP, "--ping-only", "--os", "linux",
          "--hardware", "Lab Gateway", "--sysName", "rz-ping-only"])
    lnms(["device:poll", GATEWAY_IP])

    lnms(["device:add", UNREACHABLE_IP, "--v3",
          "--security-name", V3_USER,
          "--auth-password", V3_AUTH_PASS, "--auth-protocol", "SHA-256",
          "--privacy-password", V3_PRIV_PASS, "--privacy-protocol", "AES",
          "--force"])

    # The ARP entry is the one seeded fact that depends on traffic rather than
    # configuration: the agent holds an entry for the poller because the poller
    # just talked to it. Verified rather than assumed, and re-discovered once if
    # the first walk raced the agent's cache -- a silently empty ARP table would
    # leave half this integration untested while the case still reported green.
    for _ in range(3):
        if sql("select count(*) from ipv4_mac;").strip() not in ("", "0"):
            break
        lnms(["device:discover", AGENT_IP])
    arp_rows = sql("select count(*) from ipv4_mac;").strip()
    if arp_rows in ("", "0"):
        sys.exit("the agent's ARP table stayed empty; the endpoint half of this "
                 "integration would not be exercised")

    ports = sql("select count(*) from ports;").strip()
    if ports != "2":
        sys.exit("expected the agent to publish 2 ports (lo, eth0), got %r" % ports)

    # Ids are read back through the API rather than assumed to be 1, 2, 3: the
    # API answering at all is part of what the seed is proving, and a discovered
    # id cannot drift if the seeding order ever changes.
    listing = api("/api/v0/devices", token)
    by_host = {d.get("hostname"): d for d in listing.get("devices", [])}
    for wanted in (AGENT_IP, GATEWAY_IP, UNREACHABLE_IP):
        if wanted not in by_host:
            sys.exit("device %s missing from /devices (have %s)" % (wanted, sorted(by_host)))

    agent = by_host[AGENT_IP]
    # The whole reason this integration keeps an allowlist rather than copying
    # the record. Assert the premise here, in the seed, so the case fails loudly
    # if a future LibreNMS ever stops leaking these -- at which point the
    # attribute assertions downstream would be proving nothing.
    if agent.get("community") != AGENT_COMMUNITY:
        sys.exit("/devices no longer returns the SNMP community in cleartext "
                 "(got %r); the exposure this case documents has changed"
                 % agent.get("community"))
    v3 = by_host[UNREACHABLE_IP]
    if v3.get("authpass") != V3_AUTH_PASS or v3.get("cryptopass") != V3_PRIV_PASS:
        sys.exit("/devices no longer returns the SNMPv3 auth and privacy "
                 "passwords in cleartext; the exposure this case documents has changed")

    print(json.dumps({
        "api_token": token,
        "agent_id": str(agent["device_id"]),
        "ping_id": str(by_host[GATEWAY_IP]["device_id"]),
        "v3_id": str(v3["device_id"]),
        "agent_sys_name": agent.get("sysName"),
        "arp_rows": arp_rows,
        # The leaked values themselves are deliberately NOT published here. The
        # checks above are the evidence; echoing a credential into the seed
        # output would put it in the manifest, and this suite should not model
        # handling one carelessly even when the credential authenticates nothing.
    }))


if __name__ == "__main__":
    main()
