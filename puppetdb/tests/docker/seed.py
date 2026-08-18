#!/usr/bin/env python3
"""Submit Facter facts for two nodes through PuppetDB's real command API.

This is the same `replace facts` command a Puppet agent run submits, so
PuppetDB stores, indexes, and serves the facts exactly as it would in
production -- including the parts the integration is most likely to get wrong:
structured facts arrive as nested JSON, and the fact table is paged by
individual fact row rather than by node.

The two nodes are chosen to exercise address filtering against real storage:

  web01  carries a loopback interface with the all-zero MAC that Facter reports
         for it. Importing either would give every node in the estate one shared
         address and merge the whole estate onto a single asset.
  db01   carries a second interface holding an APIPA 169.254/16 address, which
         the platform deliberately keeps (unlike loopback, which it filters), so
         a script that fails to drop it produces a genuinely wrong asset.
"""

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["RZ_BASE"]

PRODUCER_TIMESTAMP = "2026-01-02T03:04:05.000Z"


def facts(certname, hostname, ipv4, mac, extra_interfaces=None):
    interfaces = {
        # Facter reports loopback on every node, with an all-zero MAC.
        "lo": {"ip": "127.0.0.1", "netmask": "255.0.0.0", "mac": "00:00:00:00:00:00"},
        "eth0": {"ip": ipv4, "netmask": "255.255.255.0", "mac": mac},
    }
    interfaces.update(extra_interfaces or {})
    return {
        "certname": certname,
        "environment": "production",
        "producer_timestamp": PRODUCER_TIMESTAMP,
        "producer": "puppetserver.corp.example.com",
        "values": {
            "fqdn": certname,
            "hostname": hostname,
            "domain": "corp.example.com",
            "kernel": "Linux",
            "architecture": "x86_64",
            "operatingsystem": "Ubuntu",
            "operatingsystemrelease": "22.04",
            "osfamily": "Debian",
            "virtual": "physical",
            "os": {
                "name": "Ubuntu",
                "family": "Debian",
                "architecture": "x86_64",
                "release": {"full": "22.04", "major": "22.04"},
            },
            "networking": {
                "hostname": hostname,
                "fqdn": certname,
                "domain": "corp.example.com",
                "ip": ipv4,
                "mac": mac,
                "interfaces": interfaces,
            },
            "dmi": {
                "manufacturer": "Dell Inc.",
                "product": {"name": "PowerEdge R640", "serial_number": "SVC-" + hostname.upper()},
                "chassis": {"type": "Rack Mount Chassis"},
            },
            "processors": {"count": 8, "physicalcount": 1,
                           "models": ["Intel(R) Xeon(R) Gold 6130 CPU @ 2.10GHz"]},
            "memory": {"system": {"total_bytes": 34359738368}},
        },
    }


NODES = [
    facts("web01.corp.example.com", "web01", "10.20.0.10", "00:11:22:33:44:55"),
    facts("db01.corp.example.com", "db01", "10.20.0.11", "00:11:22:33:44:66",
          extra_interfaces={
              # A NIC that never got a DHCP lease. The platform keeps link-local
              # addresses, so this one reaches the asset unless the script drops it.
              "eth1": {"ip": "169.254.10.5", "netmask": "255.255.0.0",
                       "mac": "00:11:22:33:44:77"},
          }),
]


def submit(payload):
    body = json.dumps(payload).encode()
    query = urllib.parse.urlencode({
        "command": "replace_facts",
        "version": "5",
        "certname": payload["certname"],
        "checksum": hashlib.sha1(body).hexdigest(),
    })
    request = urllib.request.Request(
        BASE + "/pdb/cmd/v1?" + query, data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        sys.exit("submitting facts for %s failed: %s %s" % (
            payload["certname"], exc.code, exc.read().decode()[:400]))


def stored_certnames():
    try:
        with urllib.request.urlopen(BASE + "/pdb/query/v4/nodes", timeout=30) as response:
            return {node.get("certname") for node in json.load(response)}
    except Exception:
        return set()


def main():
    for payload in NODES:
        submit(payload)

    # Commands are queued and applied by a worker, so the node is not visible
    # the instant the POST returns. Poll the query API for it rather than
    # guessing at a sleep duration.
    wanted = {node["certname"] for node in NODES}
    for _ in range(120):
        if wanted <= stored_certnames():
            break
        time.sleep(1)
    else:
        sys.exit("PuppetDB never made the seeded nodes queryable: have %s, want %s"
                 % (sorted(stored_certnames()), sorted(wanted)))

    print(json.dumps({
        "web_certname": NODES[0]["certname"],
        "db_certname": NODES[1]["certname"],
    }))


if __name__ == "__main__":
    main()
