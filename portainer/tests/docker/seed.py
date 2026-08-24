#!/usr/bin/env python3
"""Seed a fresh Portainer CE so the integration can authenticate and read.

Portainer boots with no users at all and refuses every API call until an
administrator exists, so there is no such thing as a useful read-only Portainer
container -- the credential has to be created before the integration runs.

The sequence is the same one a human performs in the setup wizard:

  1. create the initial administrator          POST /api/users/admin/init
  2. exchange the password for a session       POST /api/auth
  3. wait for the local environment to appear  GET  /api/endpoints
  4. mint a long-lived API key                 POST /api/users/1/tokens

Step 3 is a wait rather than a create. Portainer's `--host` flag adopts the
mounted socket as the "primary" environment, but it does so from a background
job that lands a moment after the admin user exists -- so a seed that creates
its own environment races that job and wins, leaving TWO environments pointing
at the same Docker daemon. That is not a hypothetical: it is how the duplicate
`docker:<host>:host:<daemon-id>` ids in this integration were first observed.

The daemon's identity is discovered rather than assumed. `ID`, `Name` and
`Architecture` differ on every machine, so the manifest asserts them through
${seed.*} instead of hard-coding a value that only matches this laptop.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["RZ_BASE"].rstrip("/")
USERNAME = "admin"
# Portainer enforces a 12-character minimum. It guards a container that is
# destroyed at the end of the test and is never reachable off the loopback
# interface, so it is written here rather than generated -- a fixed value keeps
# a failed run reproducible by hand.
PASSWORD = "runzero-test-pw-2026"

# Portainer answers in well under a second on any machine that can run it at
# all; these bounds exist so a wedged container fails the test in a minute
# instead of hanging the whole suite.
API_TIMEOUT = 15
ADMIN_DEADLINE = 120
ENDPOINT_DEADLINE = 120


def call(method, path, body=None, headers=None, raw=False):
    """One JSON API call. Returns (status, parsed-or-text)."""
    data = None
    request_headers = dict(headers or {})
    if body is not None and not raw:
        data = json.dumps(body).encode()
        request_headers["Content-Type"] = "application/json"
    elif raw:
        data = body
    request = urllib.request.Request(BASE + path, data=data,
                                     headers=request_headers, method=method)
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


def create_admin():
    """Create the first administrator, tolerating one that already exists."""
    deadline = time.time() + ADMIN_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, body = call("POST", "/api/users/admin/init",
                            {"Username": USERNAME, "Password": PASSWORD})
        if status == 200:
            return
        # 409 means an administrator is already initialised. A re-run against a
        # surviving container is not an error as long as the password matches,
        # and login below is what actually proves that.
        if status == 409:
            return
        last = "status %s: %s" % (status, str(body)[:200])
        time.sleep(2)
    die("could not create the Portainer admin user within %ds (last: %s)"
        % (ADMIN_DEADLINE, last))


def login():
    status, body = call("POST", "/api/auth",
                        {"Username": USERNAME, "Password": PASSWORD})
    if status != 200 or not isinstance(body, dict) or not body.get("jwt"):
        die("Portainer login failed (status %s): %s" % (status, str(body)[:300]))
    return body["jwt"]


def wait_for_environment(auth):
    """Wait for the environment Portainer builds from the mounted socket.

    Creating one here instead would produce a second environment for the same
    daemon; see the module docstring.
    """
    deadline = time.time() + ENDPOINT_DEADLINE
    last = "never attempted"
    while time.time() < deadline:
        status, body = call("GET", "/api/endpoints", headers=auth)
        if status == 200 and isinstance(body, list) and body:
            return body[0]
        last = "status %s, %s environment(s)" % (
            status, len(body) if isinstance(body, list) else "?")
        time.sleep(2)
    die("Portainer never registered a Docker environment within %ds (last: %s). "
        "Is /var/run/docker.sock mounted into the container?"
        % (ENDPOINT_DEADLINE, last))


def main():
    create_admin()
    jwt = login()
    auth = {"Authorization": "Bearer " + jwt}

    environment = wait_for_environment(auth)
    environment_id = environment.get("Id")

    status, body = call("POST", "/api/users/1/tokens",
                        {"password": PASSWORD, "description": "runzero-integration-test"},
                        headers=auth)
    if status not in (200, 201) or not isinstance(body, dict) or not body.get("rawAPIKey"):
        die("could not mint a Portainer API key (status %s): %s" % (status, str(body)[:300]))
    api_key = body["rawAPIKey"]

    # Read the daemon back through Portainer's own proxy -- the same path the
    # integration takes -- so the values asserted in the manifest are the ones
    # the integration will actually see, not something read a different way.
    status, info = call("GET", "/api/endpoints/%s/docker/info" % environment_id,
                        headers={"X-API-Key": api_key})
    if status != 200 or not isinstance(info, dict) or not info.get("ID"):
        die("Docker /info through the Portainer proxy failed (status %s): %s"
            % (status, str(info)[:300]))

    daemon_name = str(info.get("Name") or "")
    # The integration drops a daemon name that is a placeholder or a bare
    # address, and a daemon with neither a name nor an address is skipped
    # entirely -- which would surface as a baffling "0 assets" instead of a
    # clear message. Fail here, where the cause is obvious.
    if daemon_name.lower() in ("localhost", "localhost.localdomain", "unknown", ""):
        die("the Docker daemon reports hostname %r, which the integration treats as "
            "a placeholder. This test needs a daemon with a real hostname; it is a "
            "property of the machine running the test, not of the integration."
            % daemon_name)

    print(json.dumps({
        "api_key": api_key,
        "environment_id": environment_id,
        "environment_name": str(environment.get("Name") or ""),
        "daemon_id": str(info.get("ID")),
        "daemon_name": daemon_name,
        "server_version": str(info.get("ServerVersion") or ""),
        "architecture": str(info.get("Architecture") or ""),
        "os_type": str(info.get("OSType") or ""),
    }))


if __name__ == "__main__":
    main()
