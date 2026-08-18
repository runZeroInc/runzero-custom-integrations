#!/usr/bin/env python3
"""Take a blank Snipe-IT from first boot to an instance with a real API token
and real hardware, without a human touching the setup wizard.

The steps are the ones the product itself documents, run non-interactively:

  1. `snipeit:create-admin` creates the admin user.
  2. A `settings` row is written. Snipe-IT's CheckForSetup middleware redirects
     every request -- including API requests -- to /setup until both a user and
     a settings row exist, so without this the API answers HTML, not JSON.
  3. `passport:install` generates the OAuth keys, then a personal access token
     is minted for the admin. That token is the `api_token` parameter.
  4. Three hardware rows are created over the REST API, so the records under
     test were written the same way an operator would write them.

The three rows are chosen deliberately. Two carry distinct MAC addresses in the
stock "MAC Address" custom field; the third carries none. Starlark locals are
function-scoped rather than loop-scoped, so a row with custom fields but no MAC
used to inherit the previous row's -- importing a monitor that carried a
server's MAC, and merging two unrelated pieces of hardware. The third row is
what proves that no longer happens.
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"]
PROJECT = os.environ["RZ_PROJECT"]
COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
SERVICE = os.environ["RZ_SERVICE"]

ADMIN_USER = "runzero"
ADMIN_PASSWORD = "RunZeroContainerTest123!"


def artisan(*args, timeout=300):
    argv = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
            "exec", "-T", SERVICE, "php", "artisan"] + list(args)
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        sys.exit("artisan %s failed (%d):\n%s\n%s" % (
            args[0], proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:]))
    return proc.stdout.replace("\r", "")


def tinker(php):
    """Run a PHP snippet and return whatever it printed between the markers.

    Tinker decorates its output, so the snippet brackets its own result rather
    than the caller guessing which line matters.
    """
    out = artisan("tinker", "--execute", 'echo "<<<"; %s echo ">>>";' % php)
    if "<<<" not in out or ">>>" not in out:
        sys.exit("tinker produced no delimited output:\n%s" % out[-2000:])
    return out.split("<<<", 1)[1].rsplit(">>>", 1)[0].strip()


def api(path, method="GET", token=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            raw = response.read().decode()
    except urllib.error.HTTPError as exc:
        sys.exit("%s %s failed: %s %s" % (method, path, exc.code, exc.read().decode()[:400]))
    try:
        return json.loads(raw)
    except ValueError:
        sys.exit("%s %s did not return JSON (setup wizard still gating?):\n%s" % (
            method, path, raw[:400]))


def created(payload, what):
    if payload.get("status") != "success":
        sys.exit("creating %s failed: %s" % (what, json.dumps(payload.get("messages"))[:400]))
    return payload["payload"]["id"]


def main():
    artisan("snipeit:create-admin",
            "--first_name=runZero", "--last_name=Container",
            "--email=runzero@example.com",
            "--username=" + ADMIN_USER, "--password=" + ADMIN_PASSWORD)

    # Snipe-IT validates this model, so every field it marks required has to be
    # present or save() silently returns false and the wizard stays up.
    settings_id = tinker(
        '$s = new \\App\\Models\\Setting;'
        ' $s->site_name = "runZero Container Test";'
        ' $s->email_domain = "example.com";'
        ' $s->email_format = "firstname.lastname";'
        ' $s->username_format = "firstname.lastname";'
        ' $s->next_auto_tag_base = 1;'
        ' $s->auto_increment_assets = 0;'
        ' $s->alert_email = "runzero@example.com";'
        ' $s->default_currency = "USD";'
        ' $s->locale = "en-US";'
        ' $s->brand = 1;'
        ' $s->pwd_secure_min = 8;'
        ' if (!$s->save()) { echo "SAVE FAILED: " . json_encode($s->getErrors()); }'
        ' else { echo $s->id; }')
    if not settings_id.isdigit():
        sys.exit("could not complete Snipe-IT setup: %s" % settings_id)

    artisan("passport:install", "--force")
    token = tinker('$u = \\App\\Models\\User::where("username","%s")->firstOrFail();'
                   ' echo $u->createToken("runzero-container-test")->accessToken;' % ADMIN_USER)
    if len(token) < 100:
        sys.exit("personal access token looks wrong: %r" % token[:120])

    # A stock install ships a "MAC Address" custom field already attached to the
    # "Asset with MAC Address" fieldset. Look both up by name rather than
    # assuming the ids, and fail loudly if the shipped data ever changes.
    fieldsets = api("/api/v1/fieldsets", token=token).get("rows", [])
    fieldset = next((f for f in fieldsets if "MAC" in f.get("name", "")), None)
    if not fieldset:
        sys.exit("no stock fieldset carrying the MAC Address field: %s"
                 % [f.get("name") for f in fieldsets])

    category_id = created(api("/api/v1/categories", "POST", token,
                              {"name": "Servers", "category_type": "asset"}), "category")
    manufacturer_id = created(api("/api/v1/manufacturers", "POST", token,
                                  {"name": "Dell Inc."}), "manufacturer")
    model_id = created(api("/api/v1/models", "POST", token, {
        "name": "PowerEdge R640", "model_number": "R640",
        "category_id": category_id, "manufacturer_id": manufacturer_id,
        "fieldset_id": fieldset["id"],
    }), "model")

    status = next((s for s in api("/api/v1/statuslabels", token=token).get("rows", [])
                   if s.get("type") == "deployable"), None)
    if not status:
        sys.exit("no deployable status label in a stock install")

    rows = [
        {"asset_tag": "RZ-0001", "name": "web01", "serial": "SVC12345",
         "_snipeit_mac_address_1": "00:11:22:33:44:55"},
        {"asset_tag": "RZ-0002", "name": "db01", "serial": "SVC12346",
         "_snipeit_mac_address_1": "00:11:22:33:44:66"},
        # No MAC. Must not inherit db01's.
        {"asset_tag": "RZ-0003", "name": "monitor01", "serial": "SVC12347"},
    ]
    ids = {}
    for row in rows:
        row.update({"model_id": model_id, "status_id": status["id"]})
        ids[row["asset_tag"]] = created(
            api("/api/v1/hardware", "POST", token, row), row["asset_tag"])

    listing = api("/api/v1/hardware", token=token)
    if listing.get("total") != len(rows):
        sys.exit("expected %d hardware rows, the API reports %s"
                 % (len(rows), listing.get("total")))

    print(json.dumps({
        "api_token": token,
        "web_id": ids["RZ-0001"],
        "db_id": ids["RZ-0002"],
        "monitor_id": ids["RZ-0003"],
    }))


if __name__ == "__main__":
    main()
