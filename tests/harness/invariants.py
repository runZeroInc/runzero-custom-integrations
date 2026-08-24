"""Invariants every integration's emitted assets should satisfy.

These encode defects found by review that a generic wiring check cannot see. A
scenario runs all of them unless it names one in `invariants.skip`, with a
reason -- an integration that legitimately violates one should say why in its
scenario file rather than silently opting out.
"""

import base64
import json
import re

MAX_CHILDREN = 99

# Addresses that identify nothing.
#
# Know what this check can and cannot prove. The platform's NormalizeAddress
# (runzero/net/ip.go) already rejects loopback, multicast, and unspecified as a
# "filtered range", so those never reach an emitted asset no matter what the
# script does -- a script that puts 127.0.0.1 on an interface produces an asset
# with NO address rather than a matchable one. This check therefore cannot
# detect a loopback bug from the emitted assets; catch that with a record-level
# assertion instead (assert the asset is skipped, or that a specific real
# address survived alone).
#
# What it does catch is LINK-LOCAL, which the platform deliberately keeps:
# IsUnicast explicitly allows APIPA 169.254/16 and fe80::/10. A host that failed
# to get a DHCP lease reports an APIPA address that identifies nothing, and two
# such hosts can correlate to each other on it. The loopback entries stay in the
# list as a cheap guard in case that platform behaviour ever changes.
BAD_PREFIXES = ("127.", "169.254.", "0.0.0.0", "::1", "fe80:", "::")

# A MAC written with any of the usual separators. Deliberately NOT matching a
# bare run of twelve hex characters: that is indistinguishable from a legitimate
# opaque id. BMC Discovery's node fallback (bmc-discovery:<host>:node:aabbccdd0004)
# and a separator-stripped MAC (unifi-site-manager:<host>:device:F4E2C6C23F13)
# are the same shape, so matching it flags real ids as defects, and an invariant
# that cries wolf gets skipped everywhere and stops protecting anything.
# Separator-stripped MACs therefore have to be caught by review, not here.
MAC_RE = re.compile(r"\b[0-9a-fA-F]{2}([:\-.])[0-9a-fA-F]{2}(\1[0-9a-fA-F]{2}){4}\b")

# Names that are not the host's identity. local_fqdn is literally "localhost" on
# many UNIX hosts, and several sources fall back to naming a host after its IP.
PLACEHOLDER_NAMES = {"localhost", "localhost.localdomain", "unknown", "none", "null", "-"}
IPV4_NAME_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _children(info, key):
    """Decode a base64 child collection (_services/_software/_vulnerabilities)."""
    raw = info.get(key)
    if not raw:
        return []
    try:
        decoded = json.loads(base64.b64decode(raw))
    except Exception:
        return []
    return decoded if isinstance(decoded, list) else []


def _values(info, key):
    raw = info.get(key)
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(v) for v in raw]
    return [p.strip() for p in str(raw).split(",") if p.strip()]


def unique_ids(assets, _cfg):
    """No two assets in one run may share a foreign id."""
    seen, dupes = set(), set()
    for a in assets:
        aid = a.get("id", "")
        if aid in seen:
            dupes.add(aid)
        seen.add(aid)
    if dupes:
        return "duplicate foreign ids emitted in one run: %s" % sorted(dupes)[:5]
    return None


def namespaced_ids(assets, _cfg):
    """Ids must carry a tenant/appliance scope so two deployments cannot collide.

    The scope is the part that distinguishes ONE deployment of a product from
    another -- the appliance host, the tenant id, the site id. Two GLPI servers
    both have a Computer with id 12, and the source alone does not separate
    them, so an id-matching integration that omits the scope merges unrelated
    assets. An integration whose vendor id is globally unique (a real UUID, an
    Apple hardware UDID) has nothing to scope and legitimately skips this.

    The house shape is <slug>:<host-or-cluster-scope>:<vendor-id>. The slug is
    NOT redundant with the source: the platform blocks a merge between two
    records of one source whose foreign ids differ, so the id text is what keeps
    integrations from colliding, and it has to stay distinct per integration.

    Note what this cannot see: it checks only that SOME scope is present, not
    that it is the right one.
    """
    bare = [a.get("id", "") for a in assets if ":" not in a.get("id", "")]
    if bare:
        return "ids are not namespaced by a scope: %s" % bare[:5]
    return None


def no_loopback_interfaces(assets, _cfg):
    """Loopback, unspecified, and link-local must never reach an interface."""
    bad = []
    for a in assets:
        for ip in _values(a, "ipAddresses"):
            if ip.startswith(BAD_PREFIXES):
                bad.append("%s -> %s" % (a.get("id", "?"), ip))
    if bad:
        return "non-identifying addresses on interfaces: %s" % bad[:5]
    return None


def no_mac_in_id(assets, _cfg):
    """A MAC must not be the foreign id.

    network_interface and normalize_mac clear the locally administered bit for
    cross-source matching, so two distinct endpoints can normalize to the same
    value. That is correct for an interface and wrong for identity.
    """
    bad = [a.get("id", "") for a in assets if MAC_RE.search(a.get("id", ""))]
    if bad:
        return "foreign id contains a MAC address: %s" % bad[:5]
    return None


def child_caps(assets, _cfg):
    """Child collections are capped at 99 at the ImportAsset boundary."""
    bad = []
    for a in assets:
        for key in ("_services", "_software", "_vulnerabilities"):
            n = len(_children(a, key))
            if n > MAX_CHILDREN:
                bad.append("%s %s=%d" % (a.get("id", "?"), key, n))
    if bad:
        return "child collections exceed %d: %s" % (MAX_CHILDREN, bad[:5])
    return None


def has_correlator(assets, _cfg):
    """Every asset needs an id and at least one correlating attribute."""
    bad = []
    for a in assets:
        if not a.get("id"):
            bad.append("(no id)")
            continue
        if not (_values(a, "ipAddresses") or _values(a, "macAddresses") or _values(a, "hostnames")):
            bad.append(a.get("id"))
    if bad:
        return "assets with no MAC, IP, or hostname to correlate on: %s" % bad[:5]
    return None


def no_placeholder_hostnames(assets, _cfg):
    """Placeholder names correlate unrelated hosts; a bare IP is not a name."""
    bad = []
    for a in assets:
        for name in _values(a, "hostnames"):
            low = name.strip().lower()
            if low in PLACEHOLDER_NAMES or IPV4_NAME_RE.match(low):
                bad.append("%s -> %s" % (a.get("id", "?"), name))
    if bad:
        return "placeholder hostnames emitted: %s" % bad[:5]
    return None


def service_addresses_sane(assets, _cfg):
    """A service must sit on a real port and a non-placeholder address."""
    bad = []
    for a in assets:
        for svc in _children(a, "_services"):
            port = svc.get("port")
            addr = str(svc.get("address") or "")
            if not isinstance(port, int) or port < 1 or port > 65535:
                bad.append("%s port=%r" % (a.get("id", "?"), port))
            elif addr.startswith(BAD_PREFIXES):
                bad.append("%s address=%s" % (a.get("id", "?"), addr))
    if bad:
        return "implausible services: %s" % bad[:5]
    return None


ALL = {
    "unique_ids": unique_ids,
    "namespaced_ids": namespaced_ids,
    "no_loopback_interfaces": no_loopback_interfaces,
    "no_mac_in_id": no_mac_in_id,
    "child_caps": child_caps,
    "has_correlator": has_correlator,
    "no_placeholder_hostnames": no_placeholder_hostnames,
    "service_addresses_sane": service_addresses_sane,
}


def run(assets, skip, cfg=None):
    """Return a list of (name, failure message) for each invariant that failed.

    cfg carries scenario context an invariant may need, currently the
    integration slug. Nothing consults it today; it stays wired because an
    invariant that has to reason about which integration it is checking cannot
    be added without it.
    """
    failures = []
    for name, fn in sorted(ALL.items()):
        if name in skip:
            continue
        msg = fn(assets, cfg)
        if msg:
            failures.append((name, msg))
    return failures
