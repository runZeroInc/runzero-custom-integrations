# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.
# This script was generated with AI.

CONFIG = {
    "id": "runzero-linux-ssh",
    "name": "Linux via SSH",
    "type": "inbound",
    "description": "Collects host facts from Linux/Unix targets over SSH and reports them as assets.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "validationMode": "compile",
    "params": [
        {"key": "host", "label": "Target host", "type": "string", "required": True},
        {"key": "port", "label": "SSH port", "type": "int", "required": False, "default": 22, "min": 1, "max": 65535},
        {"key": "username", "label": "Username", "type": "string", "required": True},
        {"key": "password", "label": "Password", "type": "secret", "required": False},
        {"key": "private_key", "label": "Private key (PEM)", "type": "textarea", "required": False},
        {"key": "private_key_passphrase", "label": "Private key passphrase", "type": "secret", "required": False},
        {"key": "host_key", "label": "Expected host public key (authorized_keys format)", "type": "textarea", "required": False},
        {"key": "insecure_ignore_host_key", "label": "Skip host key verification (insecure)", "type": "bool", "required": False, "default": False, "description": "Connect without verifying the server's host key. The runtime has no trust-on-first-use cache, so host_key is required unless this is enabled. Only use on a trusted network path."},
        {"key": "timeout", "label": "Connection timeout (seconds)", "type": "int", "required": False, "default": 30, "min": 1, "max": 600},
    ],
}

load("runzero.types", "ImportAsset", "NetworkInterface")
load("runzero.ssh", ssh_dial="dial")
load("net", "ip_address")
load("kwargs", "require", "get_string", "get_int", "get_bool")


# SMBIOS System Enclosure type (DMTF SMBIOS 3.x, Type 3 field 05h). The kernel
# publishes the raw number at /sys/class/dmi/id/chassis_type and dmidecode
# prints the DMTF name for the same byte, so both spellings are keyed here.
# Only the values that name a form factor outright are mapped: "Other" (1) and
# "Unknown" (2) are what a hypervisor and most ARM boards report, and the
# expansion and peripheral chassis (18-22, 25-27) describe an enclosure rather
# than the machine, so all of them leave the type unset and let runZero's own
# fingerprinting decide.
CHASSIS_DEVICE_TYPES = {
    "3": "Desktop",
    "4": "Desktop",
    "6": "Desktop",
    "7": "Desktop",
    "13": "Desktop",
    "15": "Desktop",
    "24": "Desktop",
    "35": "Desktop",
    "desktop": "Desktop",
    "low profile desktop": "Desktop",
    "mini tower": "Desktop",
    "tower": "Desktop",
    "all in one": "Desktop",
    "space-saving": "Desktop",
    "sealed-case pc": "Desktop",
    "mini pc": "Desktop",
    "8": "Laptop",
    "9": "Laptop",
    "10": "Laptop",
    "14": "Laptop",
    "31": "Laptop",
    "32": "Laptop",
    "portable": "Laptop",
    "laptop": "Laptop",
    "notebook": "Laptop",
    "sub notebook": "Laptop",
    "convertible": "Laptop",
    "detachable": "Laptop",
    "30": "Tablet",
    "tablet": "Tablet",
    "17": "Server",
    "23": "Server",
    "28": "Server",
    "29": "Server",
    "main server chassis": "Server",
    "rack mount chassis": "Server",
    "blade": "Server",
    "blade enclosing": "Server",
}


def _run(session, cmd):
    stdout, stderr, code = session.run(cmd)
    if code != 0:
        return ""
    return stdout.strip()


def _hostname(session):
    return _run(session, "hostname -f 2>/dev/null || hostname")


def _os_release(session):
    raw = _run(session, "cat /etc/os-release 2>/dev/null")
    name = ""
    version = ""
    for line in raw.split("\n"):
        if line.startswith("PRETTY_NAME="):
            name = line.split("=", 1)[1].strip('"')
        if line.startswith("VERSION_ID="):
            version = line.split("=", 1)[1].strip('"')
    return name, version


def _chassis_type(session):
    """Return the host's SMBIOS chassis type as reported, or "" if it has none.

    The sysfs file is preferred over dmidecode because it is world-readable and
    needs no root, and because it carries the raw DMTF number rather than a
    name that has changed spelling between dmidecode releases. Both are absent
    on a machine with no DMI table at all -- most ARM boards, and many
    containers -- and an absent chassis type must leave the device type unset
    rather than fall back to a guess.
    """
    raw = _run(session, "cat /sys/class/dmi/id/chassis_type 2>/dev/null")
    if not raw:
        raw = _run(session, "dmidecode -s chassis-type 2>/dev/null")
    return raw.split("\n")[0].strip()


def _device_type(chassis):
    """Map an SMBIOS chassis type onto a runZero device type, or None."""
    if not chassis:
        return None
    return CHASSIS_DEVICE_TYPES.get(chassis.lower(), None)


def _macs_and_ips(session):
    out = _run(session, "ip -o link show 2>/dev/null; echo ---; ip -o -4 addr show 2>/dev/null; echo ---; ip -o -6 addr show 2>/dev/null")
    parts = out.split("---")
    mac_by_iface = {}
    v4 = {}
    v6 = {}
    if len(parts) >= 1:
        for line in parts[0].split("\n"):
            line = line.strip()
            if not line:
                continue
            # "1: lo: <LOOPBACK,UP> mtu 65536 ... link/loopback 00:00:00:00:00:00 brd ..."
            chunks = line.split()
            if len(chunks) < 2:
                continue
            # `ip -o link` names a VLAN sub-interface, veth end, or bond/bridge
            # slave as "eth0@if262:", while `ip addr` reports plain "eth0" --
            # so the parent name is everything before the "@", or the join
            # against the address maps below never matches and every address on
            # such an interface is silently dropped.
            iface = chunks[1].split("@")[0].rstrip(":")
            if "link/ether" in line:
                idx = chunks.index("link/ether")
                if idx + 1 < len(chunks):
                    mac_by_iface[iface] = chunks[idx + 1]
    if len(parts) >= 2:
        for line in parts[1].split("\n"):
            chunks = line.split()
            if len(chunks) < 4:
                continue
            iface = chunks[1]
            cidr = chunks[3]
            ip = cidr.split("/")[0]
            v4.setdefault(iface, []).append(ip)
    if len(parts) >= 3:
        for line in parts[2].split("\n"):
            chunks = line.split()
            if len(chunks) < 4:
                continue
            iface = chunks[1]
            cidr = chunks[3]
            ip = cidr.split("/")[0]
            v6.setdefault(iface, []).append(ip)

    interfaces = []
    for iface, mac in mac_by_iface.items():
        v4s = []
        v6s = []
        for ip in v4.get(iface, []):
            addr = ip_address(ip)
            if addr:
                v4s.append(addr)
        for ip in v6.get(iface, []):
            addr = ip_address(ip)
            if addr:
                v6s.append(addr)
        interfaces.append(NetworkInterface(macAddress=mac, ipv4Addresses=v4s, ipv6Addresses=v6s))
    return interfaces


def main(*args, **kwargs):
    require(kwargs, "host", "username")
    host = get_string(kwargs, "host")
    port = get_int(kwargs, "port", default=22)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password", default="")
    private_key = get_string(kwargs, "private_key", default="")
    private_key_passphrase = get_string(kwargs, "private_key_passphrase", default="")
    host_key = get_string(kwargs, "host_key", default="")
    insecure_ignore_host_key = get_bool(kwargs, "insecure_ignore_host_key", default=False)
    timeout = get_int(kwargs, "timeout", default=30)

    if not password and not private_key:
        print("either password or private_key is required")
        return []

    # The runtime requires a pinned host key or an explicit opt-out -- there is
    # no trust-on-first-use -- and dial() raises on the missing-key default,
    # which would end the task as an error. Check it here and say what to do.
    if not host_key and not insecure_ignore_host_key:
        print("host_key is required unless insecure_ignore_host_key is enabled. " +
              "Capture it on the target with: cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub")
        return []
    if host_key and insecure_ignore_host_key:
        # dial() rejects the combination outright; the pin is the stronger
        # statement, so it wins.
        print("both host_key and insecure_ignore_host_key are set; verifying against the pinned host key")
        insecure_ignore_host_key = False

    session = ssh_dial(
        host=host,
        port=port,
        username=username,
        password=password,
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
        host_key=host_key,
        insecure_ignore_host_key=insecure_ignore_host_key,
        timeout=timeout,
    )
    hostname = _hostname(session)
    os_name, os_version = _os_release(session)
    kernel = _run(session, "uname -r")
    machine_id = _run(session, "cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null")
    chassis = _chassis_type(session)
    interfaces = _macs_and_ips(session)
    session.close()

    asset_id = machine_id if machine_id else "{}@{}".format(username, host)
    asset = ImportAsset(
        id=asset_id,
        hostnames=[hostname] if hostname else [],
        os=os_name,
        osVersion=os_version,
        deviceType=_device_type(chassis),
        networkInterfaces=interfaces,
        customAttributes={
            "ssh.target": "{}:{}".format(host, port),
            "kernel": kernel,
            "machine_id": machine_id,
            # The raw SMBIOS value behind deviceType, kept so an operator can
            # see why a host was or was not typed.
            "chassis_type": chassis,
        },
    )
    # Stream the asset to runZero via report_assets instead of returning a list.
    report_assets(asset)
    return None
