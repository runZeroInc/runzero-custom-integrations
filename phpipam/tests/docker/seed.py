#!/usr/bin/env python3
"""Install phpIPAM's schema, enable its API, and create records through it.

phpIPAM's container image does not install itself. `start_apache2` starts Apache
and nothing else, and the schema arrives only when a human browses to /install/
and clicks through the wizard -- so a fresh stack answers every API call with
`Base table or view not found: phpipam.settings`. This script does what the
wizard does: imports db/SCHEMA.sql out of the web image into the database.

Everything after that is deliberately split. Three things cannot be done over
the API because the API is not reachable until they are done, so they are
written to the database directly:

  * the admin password, because SCHEMA.sql ships the default account with
    passChange='Yes' and phpIPAM refuses to authenticate until it is changed;
  * settings.api, because the API is disabled in a fresh install and answers
    `503 API server disabled`;
  * the API app itself, which normally exists only after a visit to
    Administration -> API.

Everything else -- the section, the subnet, the addresses, the device -- is
created through the real REST API over real TLS, so the rows the integration
reads back were written by phpIPAM's own controllers rather than injected behind
them.

The app is created with `ssl_token` security on purpose. api/index.php offers
only two ways in: `ssl_token`/`ssl_code`, which require Tools::isHttps(); or
`none`, which additionally requires api_allow_unsafe===true in config.php.
Anything else is `503 SSL connection is required for API` -- including a request
that really did arrive over TLS, because TLS terminates in the proxy. compose.yml
sets IPAM_TRUST_X_FORWARDED so isHttps() believes the X-Forwarded-Proto the
proxy sends, which is what a real deployment behind a terminator must also do.
"""

import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
PROJECT = os.environ["RZ_PROJECT"]
HOST_PORT = os.environ["RZ_HOST_PORT"]

# Not $BASE, and not 127.0.0.1. The proxy serves a certificate for `localhost`
# and selects its site from SNI plus the Host header, so a request addressed to
# the bare address is refused during the handshake. `localhost` resolves to the
# same place and is what the integration is pointed at too.
BASE = "https://localhost:%s" % HOST_PORT

DB_SERVICE = "db"
WEB_SERVICE = "phpipam-www"
DB_NAME = "phpipam"
DB_ROOT_PASSWORD = "ipamroot"

ADMIN_USER = "Admin"
ADMIN_PASSWORD = "runzero-test-pw-2026"
APP_ID = "runzero"

# 3 is read/write. The app the *integration* uses only ever reads, but the same
# app is what creates the fixtures below, and phpIPAM answers `401 invalid
# permissions` to every POST from a read-only app.
APP_PERMISSIONS = 3

SECTION_NAME = "rz-lab"
SUBNET = "10.90.0.0"
SUBNET_MASK = "24"

# Three addresses, chosen to cover the three shapes the integration treats
# differently: one with both a hostname and a MAC, one with a hostname only, and
# one bare reservation that `require_identity` should drop.
ADDRESSES = [
    {"ip": "10.90.0.21", "hostname": "rz-web01", "mac": "00:11:22:33:44:55",
     "description": "web server"},
    {"ip": "10.90.0.22", "hostname": "rz-db01", "description": "database, no MAC"},
    {"ip": "10.90.0.23", "description": "bare reservation, no identity"},
]

DEVICE = {"hostname": "rz-sw01", "ip_addr": "10.90.0.10", "description": "lab switch"}

EXEC_TIMEOUT = 300
API_TIMEOUT = 30

# The proxy's certificate comes from Caddy's own internal CA and is trusted by
# nothing. The integration is run with tls_disable_validation for the same
# reason; see manifest.json.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def compose(argv, stdin=None, capture_binary=False):
    full = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE] + list(argv)
    try:
        proc = subprocess.run(full, capture_output=True, timeout=EXEC_TIMEOUT,
                              input=stdin)
    except subprocess.SubprocessError as exc:
        die("docker compose %r failed to run: %s" % (argv[:3], exc))
    if proc.returncode != 0:
        die("docker compose %r failed (exit %d):\n%s"
            % (argv[:3], proc.returncode,
               (proc.stderr or b"").decode("utf-8", "replace")[-2000:]))
    return proc.stdout if capture_binary else proc.stdout.decode("utf-8", "replace")


def mysql(sql, stdin=None):
    """Run SQL as root. Used only for what the API cannot do to itself."""
    argv = ["exec", "-T", DB_SERVICE, "mariadb", "-u", "root",
            "-p" + DB_ROOT_PASSWORD, DB_NAME]
    if sql is not None:
        argv += ["-N", "-B", "-e", sql]
    return compose(argv, stdin=stdin)


def install_schema():
    """Do what the /install/ wizard does: load db/SCHEMA.sql."""
    schema = compose(["exec", "-T", WEB_SERVICE, "cat", "/phpipam/db/SCHEMA.sql"],
                     capture_binary=True)
    if b"CREATE TABLE" not in schema:
        die("/phpipam/db/SCHEMA.sql did not look like a schema (%d bytes)" % len(schema))
    mysql(None, stdin=schema)
    tables = mysql("SELECT COUNT(*) FROM information_schema.tables "
                   "WHERE table_schema='%s'" % DB_NAME).strip()
    if not tables.isdigit() or int(tables) < 20:
        die("schema import left only %r tables" % tables)
    return int(tables)


def enable_api_and_admin():
    """Set a known admin password, turn the API on, and register the app."""
    # phpIPAM stores a PHP password_hash(). Computing it in the web container is
    # the only way to be sure it matches whatever algorithm this build defaults
    # to, rather than hard-coding a bcrypt cost that a future image changes.
    hashed = compose(["exec", "-T", WEB_SERVICE, "php", "-r",
                      'echo password_hash("%s", PASSWORD_DEFAULT);' % ADMIN_PASSWORD]).strip()
    if not hashed.startswith("$2"):
        die("password_hash returned %r" % hashed[:40])
    # passChange='Yes' on the shipped account makes phpIPAM demand a new
    # password before it will authenticate anything, API included.
    mysql("UPDATE users SET password='%s', passChange='No' WHERE username='%s'"
          % (hashed, ADMIN_USER))
    mysql("UPDATE settings SET api='1'")
    mysql("DELETE FROM api WHERE app_id='%s'" % APP_ID)
    mysql("INSERT INTO api (app_id, app_code, app_permissions, app_security, app_comment) "
          "VALUES ('%s', '', %d, 'ssl_token', 'runzero integration test')"
          % (APP_ID, APP_PERMISSIONS))


def call(method, path, body=None, token=None):
    url = "%s/api/%s%s" % (BASE, APP_ID, path)
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["token"] = token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    if not token:
        import base64
        raw = "%s:%s" % (ADMIN_USER, ADMIN_PASSWORD)
        request.add_header("Authorization", "Basic " +
                           base64.b64encode(raw.encode()).decode())
    try:
        with urllib.request.urlopen(request, timeout=API_TIMEOUT, context=TLS) as response:
            payload = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", "replace")
    except Exception as exc:
        die("%s %s failed: %s" % (method, path, exc))
    try:
        return json.loads(payload)
    except ValueError:
        die("%s %s did not return JSON: %s" % (method, path, payload[:300]))


def login():
    body = call("POST", "/user/")
    token = (body.get("data") or {}).get("token")
    if not token:
        die("phpIPAM refused the API login: %s" % json.dumps(body)[:400])
    return token


def must(body, what):
    if not body.get("success") and body.get("code") not in (200, 201):
        die("%s failed: %s" % (what, json.dumps(body)[:400]))
    return body


def main():
    tables = install_schema()
    enable_api_and_admin()
    token = login()

    must(call("POST", "/sections/", {"name": SECTION_NAME,
                                     "description": "runzero container test"}, token),
         "creating the section")
    sections = call("GET", "/sections/", token=token).get("data") or []
    section_id = next((str(s["id"]) for s in sections if s.get("name") == SECTION_NAME), "")
    if not section_id:
        die("the section was created but does not appear in /sections/")

    must(call("POST", "/subnets/", {"subnet": SUBNET, "mask": SUBNET_MASK,
                                    "sectionId": section_id,
                                    "description": "rz-lab subnet"}, token),
         "creating the subnet")
    subnets = call("GET", "/sections/%s/subnets/" % section_id, token=token).get("data") or []
    subnet_id = next((str(s["id"]) for s in subnets if s.get("subnet") == SUBNET), "")
    if not subnet_id:
        die("the subnet was created but does not appear under its section")

    for address in ADDRESSES:
        payload = dict(address)
        payload["subnetId"] = subnet_id
        must(call("POST", "/addresses/", payload, token), "creating %s" % address["ip"])

    device = dict(DEVICE)
    device["sections"] = section_id
    must(call("POST", "/devices/", device, token), "creating the device")

    # Read back through the same endpoints the integration walks, so the ids the
    # manifest asserts are the ones it will actually see.
    rows = call("GET", "/subnets/%s/addresses/" % subnet_id, token=token).get("data") or []
    by_ip = dict((r.get("ip"), r) for r in rows)
    for address in ADDRESSES:
        if address["ip"] not in by_ip:
            die("address %s is missing from the subnet after creation" % address["ip"])

    devices = call("GET", "/devices/", token=token).get("data") or []
    device_id = next((str(d["id"]) for d in devices
                      if d.get("hostname") == DEVICE["hostname"]), "")
    if not device_id:
        die("the device was created but does not appear in /devices/")

    # phpIPAM's SCHEMA.sql ships demo content -- sections, subnets and addresses
    # that a real first install also gets. It is imported alongside the seeded
    # rows rather than deleted, because it is genuine phpIPAM data and the
    # integration has to cope with it; the counts are reported so the manifest
    # can assert against reality instead of against the seed alone.
    demo_subnets = mysql("SELECT COUNT(*) FROM subnets").strip()
    demo_addresses = mysql("SELECT COUNT(*) FROM ipaddresses").strip()

    print(json.dumps({
        "port": HOST_PORT,
        "base": BASE,
        "app_id": APP_ID,
        "username": ADMIN_USER,
        "password": ADMIN_PASSWORD,
        "tables": str(tables),
        "section_id": section_id,
        "section_name": SECTION_NAME,
        "subnet_id": subnet_id,
        "web_id": str(by_ip["10.90.0.21"]["id"]),
        "db_id": str(by_ip["10.90.0.22"]["id"]),
        "bare_id": str(by_ip["10.90.0.23"]["id"]),
        "device_id": device_id,
        "total_subnets": demo_subnets,
        "total_addresses": demo_addresses,
    }))


if __name__ == "__main__":
    main()
