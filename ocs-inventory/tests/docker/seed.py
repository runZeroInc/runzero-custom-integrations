#!/usr/bin/env python3
"""Take a blank OCS Inventory NG container to a server the integration can read.

Four things have to happen before a single computer exists, and every one of
them is something a real operator hits:

  1. **The schema.** The image's own entrypoint deletes
     `ocsreports/install.php`, so the documented "browse to /ocsreports and
     follow the installer" step cannot be taken and the database stays empty --
     the REST API answers HTTP 500 `Table 'ocsweb.hardware' doesn't exist` and
     the communication server answers 500 to every agent. The seed does what
     install.php would: it loads the image's own `files/ocsbase_new.sql`, then
     applies `files/update/<n>.sql` in order, because that dump declares
     GUI_VERSION 7068 while the shipped console is GUI_VER 7078. Until 7078.sql
     lands the engine logs "Bad setting. `SNMP_LINK_TAG` is not set" and rejects
     every inventory with `end;error`.
  2. **The REST API's access control.** The OCS source tarball's
     `ocsinventory-restapi.conf` still carries `Require ip 127.0.0.1` inside
     `<Location /ocsapi>`, which is what a `setup.sh` install gets. The Docker
     image ships its own copy of that file WITHOUT the Require line, so the API
     is reachable from anywhere. The seed inspects what is actually installed,
     widens it if the restriction is there, and reports which it found.
  3. **A credential.** The README tells operators to put HTTP Basic on the
     `/ocsapi` location, since OCS ships no user database for the REST API. The
     seed does exactly that -- a `zzz-` conf ordered after the OCS one, an
     htpasswd file, `a2enconf`, `apache2ctl -k graceful` -- so the integration
     is exercised over the credential a production deployment actually uses.
  4. **Inventories.** Two computers are delivered through the communication
     server the way an agent delivers them: a PROLOG to open the session, then
     a zlib-compressed INVENTORY document.

The two computers are chosen for what they settle:

  * `rz-ocs-01` is the OCS container reporting ITSELF, with VIRTUALDEV computed
    the way the Unix agent computes it -- from `/sys/devices/virtual/net`. In a
    container that marks eth0 virtual as well as lo, because a container's eth0
    is a veth. So every adapter is filtered, and the asset's only addressing
    comes from the joined `hardware.IPADDR` fallback -- with the loopback
    dropped out of that joined list. Its LASTCOME is written by a server in
    Europe/Paris and published with no offset, so it reads as two hours in the
    future: the platform would reject the whole record if the script did not
    clamp it.
  * `rz-ocs-02` carries one real NIC plus the three software devices a Docker
    host really reports -- a `docker0` bridge flagged VIRTUALDEV, a VMware
    adapter that is NOT flagged and can only be recognised from its
    description, and a loopback. One MAC survives; three do not.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zlib

BASE = os.environ["RZ_BASE"]
PROJECT = os.environ["RZ_PROJECT"]
COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
SERVICE = os.environ["RZ_SERVICE"]

DB_SERVICE = "dbsrv"
DB_NAME = "ocsweb"
DB_USER = "ocs"
DB_PASS = "ocs"

API_USER = "runzero"
API_PASSWORD = "RunZeroContainerTest123"

CONSOLE_DIR = "/usr/share/ocsinventory-reports/ocsreports"
RESTAPI_CONF = "/etc/apache2/conf-available/zz-ocsinventory-restapi.conf"
AUTH_CONF = "/etc/apache2/conf-available/zzz-runzero-ocsapi-auth.conf"
HTPASSWD = "/etc/apache2/ocsapi.htpasswd"

FILE_MARKER = "@@RZFILE "

HOST_ONE = "rz-ocs-01"
HOST_TWO = "rz-ocs-02"
# The OCS agent mints its DEVICEID once, as "<name>-YYYY-MM-DD-HH-MM-SS", and
# never changes it; the integration recovers a first-seen time from that tail.
DEVICE_ONE = HOST_ONE + "-2026-01-15-09-30-00"
DEVICE_TWO = HOST_TWO + "-2025-11-02-14-05-33"

AGENT = "OCS-NG_unified_unix_agent_v2.10.0"


def compose(args, stdin=None, timeout=600, check=True):
    argv = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE] + list(args)
    proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    if check and proc.returncode != 0:
        sys.exit("docker compose %s failed (%d):\n%s\n%s" % (
            args[0], proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]))
    return proc


def in_service(service, shell, stdin=None, timeout=600, check=True):
    return compose(["exec", "-T", service, "sh", "-c", shell],
                   stdin=stdin, timeout=timeout, check=check)


def sql(statements, check=True):
    """Run SQL against the OCS database, through the database container."""
    return in_service(DB_SERVICE,
                      "mysql -u%s -p%s %s" % (DB_USER, DB_PASS, DB_NAME),
                      stdin=statements, check=check)


def sql_value(statement):
    proc = sql("%s;" % statement)
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def install_schema():
    """Do install.php's job: load the base dump, then every later update file.

    install.php is deleted by the image's own entrypoint, so this is the only
    way a container reaches a usable schema without a hand-written dump.
    """
    base = in_service(SERVICE, "cat %s/files/ocsbase_new.sql" % CONSOLE_DIR).stdout
    if "CREATE TABLE" not in base:
        sys.exit("could not read ocsbase_new.sql out of the image")
    proc = sql(base, check=False)
    if proc.returncode != 0:
        sys.exit("loading ocsbase_new.sql failed:\n%s" % proc.stderr[-2000:])

    target = in_service(SERVICE, "grep -o \"GUI_VER', *'[0-9]*\" %s/var.php" % CONSOLE_DIR).stdout
    match = re.search(r"(\d+)", target)
    if not match:
        sys.exit("could not read GUI_VER out of var.php: %r" % target)
    target = int(match.group(1))
    current = int(re.sub(r"\D", "", sql_value(
        "select tvalue from config where name='GUI_VERSION'")) or 0)

    dumped = in_service(SERVICE,
                        'for f in %s/files/update/*.sql; do echo "%s$(basename $f .sql)";'
                        " cat $f; echo; done" % (CONSOLE_DIR, FILE_MARKER)).stdout
    applied = 0
    for chunk in dumped.split(FILE_MARKER)[1:]:
        head, _, body = chunk.partition("\n")
        version = int(re.sub(r"\D", "", head) or 0)
        if not (current < version <= target):
            continue
        # Several of these fail because ocsbase_new.sql is a newer dump than the
        # GUI_VERSION it declares, so the column or index already exists. That is
        # what update.php sees too; only the final version matters.
        sql(body, check=False)
        applied += 1
    sql("update config set tvalue='%d' where name='GUI_VERSION';" % target)
    return current, target, applied


def open_restapi():
    """Report whether /ocsapi is bound to loopback, and widen it if it is."""
    conf = in_service(SERVICE, "cat %s" % RESTAPI_CONF).stdout
    restricted = bool(re.search(r"^\s*Require\s+(ip|host)\s", conf, re.M))
    if restricted:
        in_service(SERVICE, "sed -i -E 's/^[[:space:]]*Require[[:space:]]+(ip|host)[[:space:]].*$/"
                            "  Require all granted/' %s" % RESTAPI_CONF)
    return restricted


def add_basic_credential():
    """Put HTTP Basic on /ocsapi, which is what the integration's README tells
    an operator to do. Apache merges <Location> blocks for the same path, and
    conf-enabled is read in filename order, so a `zzz-` file lands after the
    OCS one."""
    digest = base64.b64encode(hashlib.sha1(API_PASSWORD.encode()).digest()).decode()
    in_service(SERVICE, "cat > %s" % HTPASSWD,
               stdin="%s:{SHA}%s\n" % (API_USER, digest))
    in_service(SERVICE, "cat > %s" % AUTH_CONF, stdin=(
        "<Location /ocsapi>\n"
        "  AuthType Basic\n"
        '  AuthName "OCS REST API"\n'
        "  AuthUserFile %s\n"
        "  Require valid-user\n"
        "</Location>\n" % HTPASSWD))
    in_service(SERVICE, "a2enconf zzz-runzero-ocsapi-auth && apache2ctl -k graceful")


def wait_for(check, what, timeout=240, interval=3):
    deadline = time.time() + timeout
    last = "never attempted"
    while time.time() < deadline:
        ok, last = check()
        if ok:
            return
        time.sleep(interval)
    sys.exit("%s did not come up within %ds (last: %s)" % (what, timeout, last))


def api(path, user=None, password=None):
    headers = {"Accept": "application/json"}
    if user:
        headers["Authorization"] = "Basic " + base64.b64encode(
            ("%s:%s" % (user, password)).encode()).decode()
    request = urllib.request.Request(BASE + path, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def agent_post(xml, what):
    """Deliver a document the way the OCS agent does: zlib over HTTP."""
    request = urllib.request.Request(
        BASE + "/ocsinventory", data=zlib.compress(xml.encode()),
        headers={"Content-Type": "application/x-compress", "User-Agent": AGENT},
        method="POST")
    try:
        with urllib.request.urlopen(request, timeout=240) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        sys.exit("%s was refused: HTTP %s %s" % (what, exc.code, exc.read()[:400]))
    try:
        return zlib.decompress(raw).decode()
    except zlib.error:
        return raw.decode("utf-8", "replace")


def escape(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def section(tag, fields):
    return "<%s>%s</%s>" % (tag, "".join(
        "<%s>%s</%s>" % (key, escape(value), key) for key, value in fields.items()), tag)


def deliver(deviceid, hardware, bios, networks, softwares):
    prolog = ("<?xml version='1.0' encoding='UTF-8'?>\n<REQUEST><DEVICEID>%s</DEVICEID>"
              "<QUERY>PROLOG</QUERY></REQUEST>" % deviceid)
    if "<RESPONSE>SEND</RESPONSE>" not in agent_post(prolog, "PROLOG for " + deviceid):
        sys.exit("the communication server did not accept the PROLOG for %s" % deviceid)
    content = (section("HARDWARE", hardware) + section("BIOS", bios)
               + "".join(section("NETWORKS", n) for n in networks)
               + "".join(section("SOFTWARES", s) for s in softwares))
    reply = agent_post(
        "<?xml version='1.0' encoding='UTF-8'?>\n<REQUEST><CONTENT>%s</CONTENT>"
        "<DEVICEID>%s</DEVICEID><QUERY>INVENTORY</QUERY></REQUEST>" % (content, deviceid),
        "INVENTORY for " + deviceid)
    if "<REPLY>" not in reply:
        sys.exit("the communication server rejected the inventory for %s: %s"
                 % (deviceid, reply[:400]))


def container_interfaces():
    """Read the OCS container's own interfaces, the way the Unix agent does.

    The agent decides VIRTUALDEV from /sys/devices/virtual/net, which inside a
    container catches the veth that is eth0 as well as lo.
    """
    out = in_service(SERVICE,
                     'for i in /sys/class/net/*; do n=$(basename $i); v=0;'
                     ' [ -e /sys/devices/virtual/net/$n ] && v=1;'
                     ' echo "$n $(cat $i/address) $v"; done').stdout
    interfaces = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3:
            interfaces.append({"name": parts[0], "mac": parts[1], "virtual": parts[2]})
    if not interfaces:
        sys.exit("could not read the container's own interfaces: %r" % out)
    # Docker itself is the authority on the address it handed this container;
    # asking the container costs a tool (`hostname -I`, `ip`, `getent`) that a
    # slimmer base image is entitled not to ship.
    container = compose(["ps", "-q", SERVICE]).stdout.split()
    if not container:
        sys.exit("could not find the %s container" % SERVICE)
    inspected = subprocess.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container[-1]],
        capture_output=True, text=True, timeout=120)
    address = inspected.stdout.strip()
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", address):
        sys.exit("could not read the container's own address: %r / %r"
                 % (address, inspected.stderr[-400:]))
    return interfaces, address


def main():
    before, after, applied = install_schema()
    loopback_bound = open_restapi()
    add_basic_credential()

    def unauthorized():
        status, _ = api("/ocsapi/v1/computers?start=0&limit=1")
        return status == 401, "status %s" % status
    wait_for(unauthorized, "the /ocsapi Basic credential")

    def authorized():
        status, body = api("/ocsapi/v1/computers?start=0&limit=1", API_USER, API_PASSWORD)
        return status == 200, "status %s %s" % (status, body[:80])
    wait_for(authorized, "the REST API")

    # --- the OCS container, reporting itself -----------------------------
    interfaces, address = container_interfaces()
    primary = next((i for i in interfaces if i["name"] != "lo"), None)
    if not primary:
        sys.exit("the container has no interface other than lo")
    networks = []
    for interface in interfaces:
        row = {"DESCRIPTION": interface["name"], "MACADDR": interface["mac"],
               "STATUS": "Up", "VIRTUALDEV": interface["virtual"]}
        if interface["name"] == "lo":
            row.update({"IPADDRESS": "127.0.0.1", "IPMASK": "255.0.0.0",
                        "TYPE": "loopback"})
        else:
            row.update({"IPADDRESS": address, "IPMASK": "255.255.0.0",
                        "TYPE": "ethernet", "SPEED": "10000"})
        networks.append(row)
    deliver(
        DEVICE_ONE,
        {"NAME": HOST_ONE, "DESCRIPTION": "Linux x86_64",
         # Joined exactly as the Unix agent joins them, loopback included.
         "IPADDR": "%s/127.0.0.1" % address,
         "OSNAME": "Ubuntu 22.04.3 LTS", "OSVERSION": "5.15.0-89-generic",
         "OSCOMMENTS": "#99-Ubuntu SMP", "ARCH": "x86_64", "MEMORY": "7936",
         "SWAP": "1024", "PROCESSORT": "Intel(R) Xeon(R) CPU E5-2680 v4",
         "PROCESSORS": "2400", "PROCESSORN": "4", "USERID": "root",
         "WORKGROUP": "example.com", "DEFAULTGATEWAY": "172.28.0.1",
         "UUID": "4c4c4544-0043-3010-8043-b7c04f4d3232", "VMSYSTEM": "Physical",
         "CHECKSUM": "262143", "USERAGENT": AGENT},
        {"SMANUFACTURER": "Dell Inc.", "SMODEL": "OptiPlex 7070", "SSN": "RZOCS001",
         "MMANUFACTURER": "Dell Inc.", "MMODEL": "0J37VM", "MSN": "MB-RZOCS001",
         "BMANUFACTURER": "Dell Inc.", "BVERSION": "1.14.0", "BDATE": "06/12/2023",
         "TYPE": "Mini Tower", "ASSETTAG": "RZ-ASSET-01"},
        networks,
        [{"NAME": "openssh-server", "VERSION": "8.9p1", "PUBLISHER": "Ubuntu",
          "FOLDER": "/usr/sbin"},
         {"NAME": "nginx", "VERSION": "1.18.0", "PUBLISHER": "Ubuntu",
          "FOLDER": "/usr/sbin"}])

    # --- a host whose adapter list is mostly software --------------------
    deliver(
        DEVICE_TWO,
        {"NAME": HOST_TWO, "DESCRIPTION": "Linux x86_64", "IPADDR": "10.88.0.21",
         "OSNAME": "Ubuntu 24.04.1 LTS", "OSVERSION": "6.8.0-45-generic",
         "ARCH": "x86_64", "MEMORY": "16384", "USERID": "operator",
         "WORKGROUP": "WORKGROUP", "DEFAULTGATEWAY": "10.88.0.1",
         "UUID": "00000000-0000-0000-0000-000000000000", "CHECKSUM": "262143",
         "USERAGENT": AGENT},
        # A numeric SMBIOS chassis type, which some agents write instead of the
        # resolved string, and an SMBIOS placeholder where a serial belongs.
        {"SMANUFACTURER": "LENOVO", "SMODEL": "20XW", "SSN": "Default string",
         "TYPE": "10", "ASSETTAG": "No Asset Tag"},
        [{"DESCRIPTION": "eth0", "IPADDRESS": "10.88.0.21", "IPMASK": "255.255.255.0",
          "IPSUBNET": "10.88.0.0", "IPGATEWAY": "10.88.0.1",
          "MACADDR": "b4:2e:99:1c:0a:77", "STATUS": "Up", "TYPE": "ethernet",
          "VIRTUALDEV": "0", "SPEED": "1000"},
         # The bridge every Docker host has. Its MAC is not the host's.
         {"DESCRIPTION": "docker0", "IPADDRESS": "172.17.0.1", "IPMASK": "255.255.0.0",
          "MACADDR": "02:42:9d:3b:11:22", "STATUS": "Up", "TYPE": "bridge",
          "VIRTUALDEV": "1"},
         # NOT flagged virtual by the agent. Only the description gives it away.
         {"DESCRIPTION": "VMware Virtual Ethernet Adapter for VMnet8",
          "IPADDRESS": "192.168.121.1", "IPMASK": "255.255.255.0",
          "MACADDR": "00:50:56:c0:00:08", "STATUS": "Up", "TYPE": "ethernet",
          "VIRTUALDEV": "0"},
         {"DESCRIPTION": "lo", "IPADDRESS": "127.0.0.1", "IPMASK": "255.0.0.0",
          "MACADDR": "00:00:00:00:00:00", "STATUS": "Up", "TYPE": "loopback",
          "VIRTUALDEV": "1"}],
        [{"NAME": "curl", "VERSION": "8.5.0", "PUBLISHER": "Ubuntu",
          "FOLDER": "/usr/bin"}])

    # --- read back what OCS actually stored ------------------------------
    status, body = api("/ocsapi/v1/computers?start=0&limit=50", API_USER, API_PASSWORD)
    if status != 200:
        sys.exit("the computers route answered %s: %s" % (status, body[:400]))
    listing = json.loads(body) or {}
    by_name = {}
    for key, record in listing.items():
        hardware = (record or {}).get("hardware") or {}
        by_name[hardware.get("NAME")] = hardware
    for wanted in (HOST_ONE, HOST_TWO):
        if wanted not in by_name:
            sys.exit("OCS accepted the inventory but stored no %s (stored: %s)"
                     % (wanted, sorted(by_name)))
    one, two = by_name[HOST_ONE], by_name[HOST_TWO]

    print(json.dumps({
        "username": API_USER,
        "password": API_PASSWORD,
        "one_id": one["ID"],
        "two_id": two["ID"],
        "container_ip": address,
        "container_mac": primary["mac"],
        "schema_from": before,
        "schema_to": after,
        "updates_applied": applied,
        # Whether the installed <Location /ocsapi> was bound to loopback, which
        # is the difference between this image and a setup.sh install.
        "restapi_loopback_bound": "yes" if loopback_bound else "no",
        # LASTCOME as OCS stored it. The database server is in Europe/Paris and
        # the API publishes no offset, so this reads as a future timestamp.
        "one_lastcome": one.get("LASTCOME"),
    }))


if __name__ == "__main__":
    main()
