#!/usr/bin/env python3
"""Fill the shares with known contents and prove the server enforces what it claims.

The integration reports, per share, the names of the top-level entries it can
see. So the seed's job is to put a known set of files behind each share and hand
the manifest back the exact strings the script should produce from them --
derived from a real listing of what ended up on disk, not from the list this
script meant to write. If the image, the VFS stack, or a stray dotfile added
anything, that shows up here as a seed failure rather than as a mystery
difference in an asserted attribute.

Four things have to be true before the integration runs, and none of them are
assumed:

  1. the polling account can authenticate -- otherwise every later failure
     reads as "no shares" instead of "bad password";
  2. the server enumerates exactly the shares this stack configured, so a
     `smb.share_count` assertion is anchored to something independently
     observed rather than to a number someone typed;
  3. `restricted$` really is refused to the polling account, at the server, with
     NT_STATUS_ACCESS_DENIED -- a share that merely *looks* restricted in
     smb.conf would let the case pass while proving nothing;
  4. and `restricted$` really is readable by somebody. A share nobody can read
     is indistinguishable from a broken path, so the denial is demonstrated
     from both sides.

-- On sort order ------------------------------------------------------------
The entry strings are built with Python's `sorted()`, which orders by code
point. That is the same order the runtime produces: go-smb2's `ReadDir` ends
with `sort.Slice(fis, func(i, j) bool { return fis[i].Name() < fis[j].Name() })`
-- a byte-wise comparison, not a locale-aware one. Every name created here is
ASCII, where the two agree exactly. `reports` deliberately holds one
capitalised name so the case pins byte order rather than dictionary order: a
locale-aware collation would sort Quarterly.pdf last instead of first.
"""

import json
import os
import subprocess
import sys

COMPOSE_FILE = os.environ["RZ_COMPOSE_FILE"]
PROJECT = os.environ["RZ_PROJECT"]
HOST_PORT = os.environ["RZ_HOST_PORT"]

SERVICE = "samba"

# Must match compose.yml. Written here rather than generated: the container is
# destroyed at the end of the test and is never reachable off loopback, and a
# fixed value keeps a failed run reproducible by hand. `check_login` below
# authenticates with it, so a drift between the two files fails there.
POLL_USER = "runzero"
POLL_PASSWORD = "runZero-Test-Pw-2026!"
OTHER_USER = "otheruser"
OTHER_PASSWORD = "Other-Pw-2026!"

# The share the polling account must not be able to read, and the share that
# exists to prove an accessible-but-empty share is still reported as
# inaccessible. Both are asserted by name in the manifest.
# Two denied shares, differing only in their names. `restricted$` is skipped by
# the script before any mount is attempted; `finance` is plain-named, so it is
# attempted, refused, and has to be survived. Both are proved denied below.
DENIED_SHARE = "restricted$"
DENIED_PLAIN_SHARE = "finance"
EMPTY_SHARE = "empty"

# Every share this stack configures, plus the IPC$ Samba adds by itself. The
# integration's `smb.share_count` is the length of this list, so it is checked
# against the server's own enumeration rather than trusted.
EXPECTED_SHARES = sorted([
    "public", "reports", "bulk", "empty", "ADMIN$", "restricted$", "finance",
    "IPC$",
])

# The script keeps only the first 20 entries of a share: `", ".join(entries[:20])`.
# `bulk` holds more than that on purpose -- see the manifest.
ENTRY_LIMIT = 20
BULK_FILES = 25

EXEC_TIMEOUT = 90

# What each share should contain once seeding is done, checked against a real
# listing afterwards. `subdir` is a directory rather than a file: the script
# appends `e["name"]` without looking at `e["is_dir"]`, so a directory has to
# appear in the entries string exactly like a file does, and this pins that.
EXPECTED_CONTENTS = {
    "public": ["hosts.csv", "readme.txt", "subdir"],
    "reports": ["Quarterly.pdf", "q3.txt", "q4.txt"],
    "bulk": ["file-%02d.dat" % n for n in range(1, BULK_FILES + 1)],
    "admin": ["backup.bin"],
    "restricted": ["secret.txt"],
    "finance": ["payroll.csv"],
    "empty": [],
}

# Share name -> the directory backing it, as compose.yml configures it.
SHARE_PATHS = {
    "public": "/shares/public",
    "reports": "/shares/reports",
    "bulk": "/shares/bulk",
    "empty": "/shares/empty",
    "ADMIN$": "/shares/admin",
    "restricted$": "/shares/restricted",
    "finance": "/shares/finance",
}


def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)


def dexec(argv, stdin=None):
    """Run a command in the samba container. Returns stdout; dies on failure."""
    full = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
            "exec", "-T", SERVICE] + list(argv)
    try:
        proc = subprocess.run(full, capture_output=True, text=True,
                              input=stdin, timeout=EXEC_TIMEOUT)
    except subprocess.SubprocessError as exc:
        die("could not exec in the %s container: %s" % (SERVICE, exc))
    if proc.returncode != 0:
        die("exec %r failed (exit %d):\n%s\n%s"
            % (argv[:3], proc.returncode, proc.stdout, proc.stderr))
    return proc.stdout


def smbclient(share, user, password, command="ls"):
    """Run one smbclient command as `user`. Returns (ok, output).

    Never dies: both outcomes are interesting here. This is the server's own
    client talking to the server over the same protocol the integration uses, so
    a refusal it reports is the refusal the integration would meet.
    """
    full = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
            "exec", "-T", SERVICE,
            "smbclient", "//127.0.0.1/" + share,
            "-U", "%s%%%s" % (user, password), "-c", command]
    try:
        proc = subprocess.run(full, capture_output=True, text=True, timeout=EXEC_TIMEOUT)
    except subprocess.SubprocessError as exc:
        return False, "smbclient could not be run: %s" % exc
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def create_contents():
    """Write the files behind every share, then fix ownership.

    Done as one shell script rather than a file-per-exec: `docker compose exec`
    costs about a fifth of a second each, and 25 of them for `bulk` alone would
    dominate the runtime of the whole case.

    The three values this script needs are substituted with str.replace rather
    than with %-formatting, and every fixed file body is written as an argument
    to `printf '%s\\n'` rather than as the format itself. Both rules exist for
    the same reason: the first draft used %-formatting and wrote a file whose
    contents began with `%PDF`, which the format pass turned back into a live
    printf directive and sh rejected with `invalid format`. Content is data, and
    keeping it out of format position is what stops it becoming code.
    """
    script = r"""
set -e
# The share directories, not /shares itself: the image declares /shares as a
# VOLUME, so it is a mount point and `rm -rf /shares` fails with "Resource
# busy". Clearing the contents is also what makes this script safe to re-run
# against a container that survived an interrupted run.
rm -rf /shares/public /shares/reports /shares/bulk /shares/empty \
       /shares/admin /shares/restricted /shares/finance
mkdir -p /shares/public/subdir /shares/reports /shares/bulk /shares/empty \
         /shares/admin /shares/restricted /shares/finance

printf '%s\n' 'hello from public'              > /shares/public/readme.txt
printf '%s\n' 'id,name' '1,web01' '2,db01'     > /shares/public/hosts.csv
printf '%s\n' 'nested'                         > /shares/public/subdir/nested.txt

printf '%s\n' 'q3 revenue'                     > /shares/reports/q3.txt
printf '%s\n' 'q4 revenue'                     > /shares/reports/q4.txt
printf '%s\n' '%PDF-1.4 not really'            > /shares/reports/Quarterly.pdf

i=1
while [ $i -le @BULK@ ]; do
  name="$(printf 'file-%02d.dat' "$i")"
  printf '%s\n' "bulk payload $i"              > "/shares/bulk/$name"
  i=$((i + 1))
done

printf '%s\n' 'admin only'                     > /shares/admin/backup.bin
printf '%s\n' 'secret'                         > /shares/restricted/secret.txt
printf '%s\n' 'employee,salary'                > /shares/finance/payroll.csv

# The polling account owns everything it is meant to read. The two denied shares
# go to the other account with a mode that excludes everyone else, so each
# refusal is enforced by the filesystem as well as by `valid users` in smb.conf.
chown -R @POLL@:@POLL@ /shares/public /shares/reports /shares/bulk \
                       /shares/empty /shares/admin
chmod -R 755 /shares/public /shares/reports /shares/bulk /shares/empty /shares/admin
chown -R @OTHER@:@OTHER@ /shares/restricted /shares/finance
chmod -R 700 /shares/restricted /shares/finance
echo rz-contents-written
"""
    script = (script
              .replace("@BULK@", str(BULK_FILES))
              .replace("@POLL@", POLL_USER)
              .replace("@OTHER@", OTHER_USER))

    out = dexec(["sh", "-s"], stdin=script)
    if "rz-contents-written" not in out:
        die("share contents were not written:\n%s" % out)


def read_back(directory):
    """The names actually present in a share directory, sorted as the runtime sorts.

    `ls -A` rather than `ls`: it shows dotfiles, which is the point. Nothing here
    creates one, so if the image's VFS stack (catia/fruit/streams_xattr) or
    anything else drops a file into a share, this is where it becomes visible --
    and it would otherwise turn up as an unexplained extra name inside an
    asserted entries string.
    """
    out = dexec(["sh", "-c", "ls -A %s 2>/dev/null || true" % directory])
    return sorted(name for name in out.split("\n") if name.strip())


def entries_string(names):
    """Exactly what the integration builds: `", ".join(entries[:20])`."""
    return ", ".join(names[:ENTRY_LIMIT])


def check_contents():
    """Every share holds what it was meant to hold, and nothing else."""
    actual = {}
    for key, path in (("public", "/shares/public"), ("reports", "/shares/reports"),
                      ("bulk", "/shares/bulk"), ("admin", "/shares/admin"),
                      ("restricted", "/shares/restricted"),
                      ("finance", "/shares/finance"), ("empty", "/shares/empty")):
        got = read_back(path)
        want = sorted(EXPECTED_CONTENTS[key])
        if got != want:
            die("%s holds %r, expected %r. The manifest asserts the entries "
                "string built from this listing, so it must be exact."
                % (path, got, want))
        actual[key] = got
    return actual


def check_login():
    """The polling account can authenticate at all."""
    ok, output = smbclient("public", POLL_USER, POLL_PASSWORD)
    if not ok:
        die("the polling account %r could not read //public:\n%s\n"
            "ACCOUNT_%s in compose.yml and POLL_PASSWORD in this file must match."
            % (POLL_USER, output, POLL_USER))


def check_enumeration():
    """The server enumerates exactly the shares this stack configured.

    `smb.share_count` is asserted as a literal in the manifest, and a literal is
    only worth anything if something independent agrees with it. This is that
    something: smbclient's own share list, read over SMB from the server, as the
    polling account.
    """
    ok, output = smbclient("public", POLL_USER, POLL_PASSWORD, command="ls")
    if not ok:
        die("could not list shares as %r:\n%s" % (POLL_USER, output))

    full = ["docker", "compose", "-p", PROJECT, "-f", COMPOSE_FILE,
            "exec", "-T", SERVICE, "smbclient", "-L", "127.0.0.1",
            "-U", "%s%%%s" % (POLL_USER, POLL_PASSWORD)]
    try:
        proc = subprocess.run(full, capture_output=True, text=True, timeout=EXEC_TIMEOUT)
    except subprocess.SubprocessError as exc:
        die("could not enumerate shares: %s" % exc)
    text = (proc.stdout or "") + (proc.stderr or "")

    seen = []
    for line in text.splitlines():
        parts = line.split()
        # The share table is "<name> <Disk|IPC> [comment]", indented. Anything
        # without one of those two type words is a header or a footer.
        if len(parts) >= 2 and parts[1] in ("Disk", "IPC") and line.startswith((" ", "\t")):
            seen.append(parts[0])
    seen = sorted(seen)
    if seen != EXPECTED_SHARES:
        die("the server enumerates %r, expected %r. smb.share_count is asserted "
            "as a literal against this list.\n%s" % (seen, EXPECTED_SHARES, text))
    return seen


def check_one_denial(share, witness):
    """One share is refused to the polling account and readable by the other one.

    Both halves matter. Without the first the case would assert a refusal that
    never happened; without the second a typo in the path would look exactly
    like a working access control -- an unreadable share and a broken one are
    indistinguishable from the polling side alone.
    """
    ok, output = smbclient(share, POLL_USER, POLL_PASSWORD)
    if ok:
        die("%r was READABLE by the polling account %r, but this case exists to "
            "cover a share it cannot read:\n%s" % (share, POLL_USER, output))
    status = "NT_STATUS_ACCESS_DENIED"
    if status not in output:
        die("%r was refused to %r, but not with %s -- the refusal must be an "
            "entitlement decision rather than a missing path or a dead share:\n%s"
            % (share, POLL_USER, status, output))

    ok, output = smbclient(share, OTHER_USER, OTHER_PASSWORD)
    if not ok:
        die("%r was refused to %r as well. A share nobody can read does not "
            "prove the denial is about entitlement:\n%s"
            % (share, OTHER_USER, output))
    if witness not in output:
        die("%r did not list %s for %r; the share is not backed by the "
            "directory this seed wrote:\n%s" % (share, witness, OTHER_USER, output))
    return status


def check_denials():
    """Both denied shares, proved the same way and for different reasons.

    `restricted$` is never mounted -- the script skips it on its name -- so its
    denial only has to be real enough that the skip is protecting something.
    `finance` is the one that matters: it is plain-named, so the script attempts
    it, and the run has to survive the refusal and go on to report the rest of
    the host. Before the runtime returned None from a refused mount that was
    impossible to test, because the attempt aborted the script.
    """
    status = check_one_denial(DENIED_SHARE, "secret.txt")
    plain_status = check_one_denial(DENIED_PLAIN_SHARE, "payroll.csv")
    if plain_status != status:
        die("the two denied shares were refused differently (%r vs %r); both "
            "must be entitlement refusals for the case to mean what it says"
            % (status, plain_status))
    return status


def main():
    if not os.environ.get("RZ_COMPOSE_FILE"):
        die("RZ_COMPOSE_FILE is not set; this script is run by the container harness")

    create_contents()
    contents = check_contents()
    check_login()
    shares = check_enumeration()
    denied_status = check_denials()

    bulk = contents["bulk"]
    if len(bulk) <= ENTRY_LIMIT:
        die("`bulk` holds %d entries, which is not more than the script's limit of "
            "%d. This share exists to prove the entries string is truncated."
            % (len(bulk), ENTRY_LIMIT))

    print(json.dumps({
        "port": HOST_PORT,
        "username": POLL_USER,
        "password": POLL_PASSWORD,
        # The exact attribute values the integration should produce, built from
        # what is really on disk behind each share.
        "public_entries": entries_string(contents["public"]),
        "reports_entries": entries_string(contents["reports"]),
        "bulk_entries": entries_string(bulk),
        "admin_entries": entries_string(contents["admin"]),
        # Diagnostics: not asserted, but printed by the harness on every run, so
        # a failure shows what the server said next to what the asset claimed.
        "share_names": " ".join(shares),
        "share_total": str(len(shares)),
        "bulk_total": str(len(bulk)),
        "bulk_dropped": " ".join(bulk[ENTRY_LIMIT:]),
        "denied_share": DENIED_SHARE,
        "denied_plain_share": DENIED_PLAIN_SHARE,
        "denied_status": denied_status,
        "empty_share": EMPTY_SHARE,
    }))


if __name__ == "__main__":
    main()
