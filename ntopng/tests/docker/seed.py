#!/usr/bin/env python3
"""Take a fresh ntopng through its first-login gate, mint an API token, and
report what it made of the captured traffic.

Three things have to happen before the integration can read anything, and none
of them is optional:

1. **The forced password change.** A new ntopng refuses every authenticated
   request until the admin password has been changed away from the default.
   Until then the embedded web server answers *every* URL -- the REST v2
   endpoints included, and including requests carrying correct HTTP Basic
   credentials -- with a 302 to /lua/change_password.lua. `admin:admin` is
   therefore not a working credential on a fresh install; it is only enough to
   retire itself. The change is driven through the product's own form, which
   carries a hidden `csrf` value that the server validates: post without it and
   the fields are discarded silently, the form is re-served with status 200, and
   ntopng.prefs.admin_password_changed stays 0. That silent discard is worth
   knowing about -- it looks exactly like a successful request.

2. **The API token.** The integration prefers `Authorization: Token <token>`
   over Basic, so the token path is the one worth exercising. ntopng mints it at
   /lua/rest/v2/create/ntopng/api_token.lua -- the example in the image's own
   source is `curl -u admin:admin -d '{"username": "Mario"}'` -- and the value
   is generated, so it has to be discovered rather than hard-coded.

3. **The traffic.** ntopng reads the capture the sniffer produced, and the host
   table fills as those packets are parsed rather than at startup. The wait
   below is for the seeded addresses to actually appear, so a slow machine fails
   here with a clear message instead of later as an empty asset list.

Everything the manifest asserts is discovered here, because ntopng mints or
derives all of it: the interface id (0 for a pcap input, not the 1 a live NIC
would get), the generated token, and the host rows themselves.
"""

import base64
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ["RZ_BASE"].rstrip("/")

# Must satisfy ntopng's own password pattern -- 5-128 characters from a
# word/symbol set (getPasswordInputPattern in lua_utils_get.lua) -- and
# change_password.lua explicitly refuses the literal "admin".
NEW_PASSWORD = "runzero-test-pw-2026"

# Must match compose.yml.
GATEWAY_IP = "10.222.9.1"
SNIFFER_IP = "10.222.9.3"
CLIENT_A_IP = "10.222.9.11"
CLIENT_B_IP = "10.222.9.12"
CLIENT_A_MAC = "00:11:22:33:44:66"
CLIENT_B_MAC = "02:42:0a:de:09:0b"
SNIFFER_MAC = "00:11:22:33:44:77"

# Every address the run must see before the integration is pointed at ntopng.
EXPECTED_IPS = [GATEWAY_IP, SNIFFER_IP, CLIENT_A_IP, CLIENT_B_IP]

HTTP_TIMEOUT = 30
LOGIN_DEADLINE = 300
HOSTS_DEADLINE = 420

CSRF_RE = re.compile(r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']')

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def note(message):
    # Diagnostics go to stderr: the harness parses the LAST STDOUT LINE as JSON.
    print(message, file=sys.stderr)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the 302 visible.

    Following it is what turns ntopng's "you are not authenticated" into an
    HTML page with status 200, which is the single most confusing thing about
    this API and the reason the integration checks for a JSON decode failure
    rather than for a 401.
    """

    def redirect_request(self, *_args, **_kwargs):
        return None


# A cookie jar rather than manual header juggling: the session ntopng hands out
# at /authorize.html is what authorises the password change. The TLS context
# goes on the handler because OpenerDirector.open() takes no `context` keyword.
JAR = http.cookiejar.CookieJar()


def request(path, data=None, headers=None, method=None, form=False, follow=False, jar=JAR):
    """Return (status, body, location). Never raises for an HTTP status."""
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = json.dumps(data).encode()
            hdrs.setdefault("Content-Type", "application/json")

    handlers = [urllib.request.HTTPSHandler(context=CTX)]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    if not follow:
        handlers.append(NoRedirect())
    opener = urllib.request.build_opener(*handlers)

    req = urllib.request.Request(BASE + path, data=body, headers=hdrs,
                                 method=method or ("POST" if body is not None else "GET"))
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as response:
            return (response.status, response.read().decode("utf-8", "replace"),
                    response.headers.get("Location"))
    except urllib.error.HTTPError as exc:
        return (exc.code, exc.read().decode("utf-8", "replace"), exc.headers.get("Location"))
    except Exception as exc:
        return 0, str(exc), None


def basic_header(password):
    raw = base64.b64encode(("admin:%s" % password).encode()).decode()
    return {"Authorization": "Basic " + raw}


def wait_for_web():
    deadline = time.time() + LOGIN_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, _, _ = request("/lua/login.lua", method="GET")
        if status == 200:
            note("web server answering")
            return
        last = "status %s" % status
        time.sleep(3)
    die("ntopng's web server never answered /lua/login.lua within %ds (last: %s)"
        % (LOGIN_DEADLINE, last))


def login(password):
    """Sign in and return True when a session was actually established.

    A wrong password is a 302 to /lua/login.lua?reason=wrong-credentials, and a
    right one is a 302 to /, so the Location is the only reliable signal --
    both set cookies.
    """
    status, _, location = request("/authorize.html",
                                  data={"user": "admin", "password": password, "referer": ""},
                                  form=True)
    ok = status == 302 and "wrong-credentials" not in (location or "")
    return ok, "status %s -> %s" % (status, location)


def retire_default_password():
    """Drive ntopng's own change-password form, CSRF token and all."""
    deadline = time.time() + LOGIN_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        ok, detail = login("admin")
        if ok:
            note("authenticated as admin/admin")
            break
        last = detail
        time.sleep(3)
    else:
        die("could not sign in to ntopng as admin/admin within %ds (last: %s)"
            % (LOGIN_DEADLINE, last))

    status, body, _ = request("/lua/change_password.lua", method="GET")
    if status != 200:
        die("the change-password form returned status %s" % status)
    match = CSRF_RE.search(body)
    if not match:
        die("no csrf token in the change-password form; ntopng validates it "
            "server-side and silently drops the POST fields without one")
    csrf = match.group(1)

    status, _, location = request("/lua/change_password.lua",
                                  data={"csrf": csrf,
                                        "new_password": NEW_PASSWORD,
                                        "confirm_password": NEW_PASSWORD},
                                  form=True)
    # Success is the httpRedirect at the end of change_password.lua. A 200 here
    # means the form was re-served -- the CSRF check or a validation rule
    # rejected the post -- and the default password is still in place.
    if status != 302:
        die("changing the admin password did not take (status %s, location %s). "
            "ntopng re-serves the form rather than reporting an error when the "
            "csrf token is missing or stale." % (status, location))

    ok, detail = login(NEW_PASSWORD)
    if not ok:
        die("the new admin password was not accepted afterwards (%s)" % detail)
    note("default admin password retired and the new one verified")


def create_api_token():
    """Mint an API token for admin over HTTP Basic, as the vendor documents."""
    deadline = time.time() + LOGIN_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, body, location = request("/lua/rest/v2/create/ntopng/api_token.lua",
                                         data={"username": "admin"},
                                         headers=basic_header(NEW_PASSWORD),
                                         jar=None)
        if status == 200:
            try:
                parsed = json.loads(body)
            except ValueError:
                last = "status 200 but the body was HTML, not JSON"
            else:
                token = ((parsed.get("rsp") or {}).get("api_token") or "").strip()
                if token:
                    note("minted API token (%d chars)" % len(token))
                    return token
                last = "status 200, no api_token in %s" % json.dumps(parsed)[:160]
        else:
            last = "status %s -> %s" % (status, location)
        time.sleep(3)
    die("could not create an ntopng API token within %ds (last: %s)" % (LOGIN_DEADLINE, last))


def rest(path, payload, token):
    """One REST v2 read with the token, returning (data, error)."""
    status, body, location = request(path, data=payload, jar=None,
                                     headers={"Authorization": "Token " + token,
                                              "Accept": "application/json"})
    if status != 200:
        return None, "status %s -> %s" % (status, location)
    try:
        return json.loads(body), None
    except ValueError:
        return None, "response was not JSON: %s" % body[:160].replace("\n", " ")


def main():
    wait_for_web()
    retire_default_password()
    token = create_api_token()

    data, err = rest("/lua/rest/v2/get/ntopng/interfaces.lua", {}, token)
    if err:
        die("listing interfaces failed: %s" % err)
    interfaces = [i for i in (data.get("rsp") or []) if isinstance(i, dict)]
    if not interfaces:
        die("ntopng reported no monitored interfaces")
    ifid = interfaces[0].get("ifid")
    ifname = str(interfaces[0].get("ifname") or "")
    note("interface ifid=%s ifname=%s" % (ifid, ifname))

    # Wait for the capture to be parsed into the host table. The packets are
    # real, so they arrive as fast as ntopng can read them -- and "as fast as
    # ntopng can read them" is a very different number under emulation.
    # Two conditions, not one. The addresses have to appear, AND the clients'
    # reverse DNS has to have landed: ntopng resolves names asynchronously
    # through Docker's embedded resolver, and until it does, active.lua falls
    # back to putting the host's own IP in the `name` field. Pointing the
    # scanner at it in that window would drop the hostnames the manifest
    # asserts, so the wait covers resolution too.
    deadline = time.time() + HOSTS_DEADLINE
    hosts = {}
    envelope = {}
    last = "no hosts yet"
    while time.time() < deadline:
        data, err = rest("/lua/rest/v2/get/host/active.lua",
                         {"ifid": str(ifid), "mode": "local",
                          "currentPage": 1, "perPage": 250}, token)
        if err:
            last = err
        else:
            envelope = (data.get("rsp") or {})
            rows = envelope.get("data") or []
            hosts = {str(r.get("ip")): r for r in rows if isinstance(r, dict)}
            missing = [ip for ip in EXPECTED_IPS if ip not in hosts]
            unresolved = [ip for ip in (CLIENT_A_IP, CLIENT_B_IP)
                          if str((hosts.get(ip) or {}).get("name") or ip) == ip]
            if not missing and not unresolved:
                break
            last = "missing %s; names unresolved for %s" % (missing or "nothing", unresolved or "nothing")
        time.sleep(4)
    else:
        die("ntopng never settled within %ds (last: %s). The sniffer writes a pcap of "
            "real traffic and ntopng reads it at startup; check that the sniffer "
            "exited 0, that the capture is non-empty, and that Docker's embedded "
            "resolver answers PTR queries for the client containers."
            % (HOSTS_DEADLINE, last))

    note("host table holds: %s" % ", ".join(sorted(hosts)))

    # The link-local rows are the strongest thing this case proves, and they are
    # not contrived: the containers' own IPv6 stacks emit MLD and neighbour
    # traffic, ntopng files each fe80:: address as a LOCAL host, and the
    # platform would happily keep a link-local address on an interface. The
    # integration has to drop them, and the manifest asserts that by id -- so
    # the addresses, which come from randomly generated veth MACs, are reported
    # here rather than guessed.
    link_local = sorted(ip for ip in hosts if ip.lower().startswith("fe80:"))
    if not link_local:
        die("ntopng reported no link-local hosts, so the assertion that they are "
            "dropped would pass for the wrong reason. Expected at least one fe80:: "
            "row from the containers' own IPv6 neighbour traffic.")
    note("link-local rows ntopng calls local: %s" % ", ".join(link_local))

    # `totalRows` is the field a pager would naturally count towards. The
    # integration deliberately does not, because active.lua assigns it from a
    # variable that is never set, so it is nil in Lua and absent from the JSON.
    # Report what this build really does, so the manifest asserts the claim
    # against the software rather than against a reading of its source.
    total_rows_present = "totalRows" in envelope
    note("active.lua envelope keys: %s; totalRows present: %s"
         % (sorted(envelope.keys()), total_rows_present))

    macs = {}
    data, err = rest("/lua/rest/v2/get/mac/macs_list.lua",
                     {"ifid": str(ifid), "start": 0, "length": 250}, token)
    if not err:
        for row in (data.get("rsp") or []):
            if isinstance(row, dict) and row.get("mac"):
                macs[str(row["mac"]).lower()] = row
    note("mac table holds: %s" % ", ".join(sorted(macs)))

    # Mirrors DEVICE_TYPE_LABELS in ntopng.star. runZero accepts a closed set of
    # device types and silently discards anything else, so the integration maps
    # ntopng's vocabulary onto it rather than passing the label through -- and
    # this seed has to apply the same mapping or it would assert the raw label
    # the script no longer emits. Labels with no honest equivalent map to "",
    # meaning the asset carries no deviceType at all.
    DEVICE_TYPE_LABELS = {
        "printer": "Printer", "workstation": "Desktop", "laptop": "Laptop",
        "tablet": "Tablet", "phone": "Mobile", "tv": "Smart TV",
        "wifi": "WAP", "wireless": "WAP", "nas": "", "networking": "",
        "multimedia": "", "video": "", "iot": "", "unknown": "",
    }

    def mac_field(mac, key):
        record = macs.get(mac.lower()) or {}
        if key == "device_type_label":
            raw = str((record.get("device_type") or {}).get("device_type_label") or "")
            return DEVICE_TYPE_LABELS.get(raw.strip().lower(), "")
        if key == "device_type_label_raw":
            return str((record.get("device_type") or {}).get("device_type_label") or "")
        return str(record.get(key) or "")

    gateway_mac = str((hosts.get(GATEWAY_IP) or {}).get("mac") or "")

    result = {
        "api_token": token,
        "password": NEW_PASSWORD,
        "ifid": ifid,
        "ifname": ifname,
        "gateway_ip": GATEWAY_IP,
        "gateway_mac": gateway_mac,
        "client_a_ip": CLIENT_A_IP,
        "client_b_ip": CLIENT_B_IP,
        "sniffer_ip": SNIFFER_IP,
        "client_a_mac": CLIENT_A_MAC,
        "client_b_mac": CLIENT_B_MAC,
        "sniffer_mac": SNIFFER_MAC,
        "link_local_ip": link_local[0],
        "link_local_count": len(link_local),
        "client_a_manufacturer": mac_field(CLIENT_A_MAC, "manufacturer"),
        "client_a_devtype": mac_field(CLIENT_A_MAC, "device_type_label"),
        "client_a_devtype_raw": mac_field(CLIENT_A_MAC, "device_type_label_raw"),
        "client_b_manufacturer": mac_field(CLIENT_B_MAC, "manufacturer"),
        "client_b_devtype": mac_field(CLIENT_B_MAC, "device_type_label"),
        "gateway_devtype": mac_field(gateway_mac, "device_type_label") if gateway_mac else "",
        # Discovered, not chosen. ntopng resolved these through Docker's
        # embedded resolver, so the value carries the compose project name --
        # which carries the harness pid. The sniffer has already exited by the
        # time ntopng resolves, so its PTR is gone and its `name` falls back to
        # its own address; that is asserted separately, as an absent hostname.
        "client_a_name": str((hosts.get(CLIENT_A_IP) or {}).get("name") or ""),
        "client_b_name": str((hosts.get(CLIENT_B_IP) or {}).get("name") or ""),
        "sniffer_name": str((hosts.get(SNIFFER_IP) or {}).get("name") or ""),
        "client_a_os_id": (hosts.get(CLIENT_A_IP) or {}).get("os"),
        "host_count": len(hosts),
        "mac_count": len(macs),
        "total_rows_present": "true" if total_rows_present else "false",
    }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
