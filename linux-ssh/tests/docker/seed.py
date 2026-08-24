#!/usr/bin/env python3
"""Give the SSH server a key to trust, an identity to report, and read both back.

Three things have to exist before the integration can run:

  1. an authorized key for the `runzero` account, because the container is
     started with PASSWORD_ACCESS=false and will refuse every other method;
  2. an /etc/machine-id, because the image ships without one -- correctly, since
     a machine-id is meant to be generated per installation rather than baked
     into an image -- and it is the value the integration uses as the asset id;
  3. the server's own host key, so the integration can be run with `host_key`
     set and actually verify what it connected to.

The keypair is generated here rather than committed. A private key in the
repository is a private key in the repository even when it guards a container
that lives for ninety seconds, and it would be the only one in the tree.

-- The newline problem --------------------------------------------------------
A PEM private key contains newlines, and a seed value containing a raw newline
cannot survive the harness. `containers.expand_seed` substitutes ${seed.*} into
the *serialised* manifest and re-parses it with json.loads, so a literal newline
in the substituted value lands inside a JSON string literal and json.loads
rejects it ("Invalid control character"). The value below is therefore emitted
with its newlines pre-escaped as the two characters \\ and n: json.loads turns
those back into real newlines while re-parsing the manifest, so `private_key`
reaches the integration as a correct PEM. This is the only value in the suite
that needs it, and it is the reason `${seed.private_key}` is not the raw key.
"""

import json
import os
import subprocess
import sys
import tempfile

COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
PROJECT = os.environ["RZ_PROJECT"]
HOST_PORT = os.environ["RZ_HOST_PORT"]

SERVICE = "sshd"
USER_NAME = "runzero"
AUTHORIZED_KEYS = "/config/.ssh/authorized_keys"
# ECDSA rather than ed25519, and not by preference. `host_key` populates an
# allowed set but does not constrain which host-key algorithm the SSH client
# offers, and the runtime's client prefers ecdsa-sha2-nistp256 over
# ssh-ed25519 -- so a server that has both (which is every default OpenSSH
# install) presents its ECDSA key, and pinning the ed25519 one fails with:
#
#   dial: ssh handshake: ssh: handshake failed: ssh: host key mismatch:
#   presented ecdsa-sha2-nistp256 key is not in the allowed set
#
# even though the pinned key is genuinely the server's. Verified against this
# container. See manifest.json for what that means for operators; the key read
# here is the one actually negotiated, so this case verifies a real host key
# rather than working around the problem by skipping verification.
HOST_KEY_PUB = "/config/ssh_host_keys/ssh_host_ecdsa_key.pub"
HOST_KEY_TYPE = "ecdsa-sha2-nistp256"

# Fixed rather than random. Unlike a row id the server mints, this is a value the
# *test* installs, so pinning it costs nothing and makes a failed run
# reproducible by hand. It is still echoed through ${seed.machine_id} so the
# manifest and this file cannot drift apart.
MACHINE_ID = "4f3c2a1b9d8e47f0a1b2c3d4e5f60718"

EXEC_TIMEOUT = 60


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def dexec(argv, stdin=None, user=None):
    """Run a command in the sshd container. Returns stdout; dies on failure."""
    full = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE, "exec", "-T"]
    if user:
        full += ["--user", user]
    full += [SERVICE] + list(argv)
    try:
        proc = subprocess.run(full, capture_output=True, text=True,
                              input=stdin, timeout=EXEC_TIMEOUT)
    except subprocess.SubprocessError as exc:
        die("could not exec in the %s container: %s" % (SERVICE, exc))
    if proc.returncode != 0:
        die("exec %r failed (exit %d):\n%s\n%s"
            % (argv, proc.returncode, proc.stdout, proc.stderr))
    return proc.stdout


def generate_keypair(workdir):
    """A throwaway ed25519 keypair. Returns (private PEM, public line)."""
    path = os.path.join(workdir, "id_ed25519")
    proc = subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "runzero-integration-test",
         "-f", path],
        capture_output=True, text=True, timeout=EXEC_TIMEOUT)
    if proc.returncode != 0:
        die("ssh-keygen failed (exit %d): %s" % (proc.returncode, proc.stderr))
    with open(path) as handle:
        private = handle.read()
    with open(path + ".pub") as handle:
        public = handle.read().strip()
    if "PRIVATE KEY" not in private or not public.startswith("ssh-ed25519 "):
        die("ssh-keygen produced something unexpected")
    return private, public


def install_authorized_key(public):
    """Authorise the key for `runzero`, with the ownership sshd insists on."""
    dexec(["sh", "-c", "cat > %s" % AUTHORIZED_KEYS], stdin=public + "\n")
    # sshd refuses a key file that is group- or world-writable, or that the
    # account does not own, and it does so with nothing in the client's error
    # beyond "Permission denied (publickey)". Set both explicitly.
    dexec(["sh", "-c", "chown %s %s && chmod 600 %s"
           % (USER_NAME, AUTHORIZED_KEYS, AUTHORIZED_KEYS)])
    listing = dexec(["sh", "-c", "wc -c < %s" % AUTHORIZED_KEYS]).strip()
    if listing == "0":
        die("authorized_keys is empty after writing it")


def install_machine_id():
    """Give the container the identity a real installation would have.

    The image ships no /etc/machine-id. Without one the integration falls back
    to an id of `<username>@<host>` -- see linux-ssh.star -- which is a weaker
    identity: it changes if the same host is polled as a different user, and two
    different hosts both reached on 127.0.0.1 through forwarded ports collide on
    it. Installing a machine-id is what a real Linux host has, and it puts the
    primary id path under test rather than the fallback.
    """
    dexec(["sh", "-c", "printf '%%s\\n' %s > /etc/machine-id" % MACHINE_ID])
    got = dexec(["sh", "-c", "cat /etc/machine-id"]).strip()
    if got != MACHINE_ID:
        die("machine-id did not stick: wrote %r, read back %r" % (MACHINE_ID, got))


def read_facts():
    """Read back exactly what the integration will collect, the same way."""
    facts = {}
    facts["hostname"] = dexec(["sh", "-c", "hostname -f 2>/dev/null || hostname"]).strip()
    facts["kernel"] = dexec(["sh", "-c", "uname -r"]).strip()

    # The SMBIOS chassis type, read from the same file the integration reads and
    # for the same reason `kernel` is read back rather than hard-coded: /sys is
    # the HOST's, not the container's, so this is Docker's VM on a Mac and the
    # bare metal on a Linux CI box, and the number differs on every machine this
    # suite runs on. `|| true` keeps the exec from dying where there is no DMI
    # table at all -- see the manifest for what an empty value means there.
    facts["chassis_type"] = dexec(
        ["sh", "-c", "cat /sys/class/dmi/id/chassis_type 2>/dev/null || true"]).strip()

    os_release = dexec(["sh", "-c", "cat /etc/os-release"])
    pretty, version_id = "", ""
    for line in os_release.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty = line.split("=", 1)[1].strip().strip('"')
        if line.startswith("VERSION_ID="):
            version_id = line.split("=", 1)[1].strip().strip('"')
    if not pretty:
        die("no PRETTY_NAME in /etc/os-release; the integration reports it as `os`")
    facts["os_name"] = pretty
    facts["os_version"] = version_id

    # The host key the integration will be asked to verify. Only the type and
    # the base64 blob are passed: the trailing comment is a label, not part of
    # the key, and a verifier that happened to compare whole lines would be
    # matching on it.
    host_key_line = dexec(["sh", "-c", "cat %s" % HOST_KEY_PUB]).strip()
    parts = host_key_line.split()
    if len(parts) < 2 or parts[0] != HOST_KEY_TYPE:
        die("unexpected host key in %s: %r" % (HOST_KEY_PUB, host_key_line[:120]))
    facts["host_key"] = "%s %s" % (parts[0], parts[1])
    return facts


def main():
    if not os.environ.get("RZ_COMPOSE_FILE"):
        die("RZ_COMPOSE_FILE is not set; this script is run by the container harness")

    workdir = tempfile.mkdtemp(prefix="rz-ssh-seed-")
    try:
        private, public = generate_keypair(workdir)
        install_authorized_key(public)
        install_machine_id()
        facts = read_facts()

        if facts["hostname"].lower() in ("localhost", "localhost.localdomain", ""):
            die("the container reports hostname %r, which the integration would put "
                "straight into `hostnames`. Check `hostname:` in compose.yml."
                % facts["hostname"])

        print(json.dumps({
            "port": HOST_PORT,
            "username": USER_NAME,
            "machine_id": MACHINE_ID,
            # Pre-escaped; see the module docstring. This is NOT the raw PEM.
            "private_key": private.replace("\\", "\\\\").replace("\n", "\\n"),
            "host_key": facts["host_key"],
            "hostname": facts["hostname"],
            "os_name": facts["os_name"],
            "os_version": facts["os_version"],
            "kernel": facts["kernel"],
            "chassis_type": facts["chassis_type"],
        }))
    finally:
        # The private key never touches the repository and does not outlive the
        # run; the container it authorises is destroyed moments later anyway.
        for name in ("id_ed25519", "id_ed25519.pub"):
            try:
                os.remove(os.path.join(workdir, name))
            except OSError:
                pass
        try:
            os.rmdir(workdir)
        except OSError:
            pass


if __name__ == "__main__":
    main()
