CONFIG = {
    "id": "runzero-linux-ssh",
    "name": "Linux via SSH",
    "type": "inbound",
    "description": "Collects host facts from Linux/Unix targets over SSH and reports them as assets.",
    "version": "26052700",
    "minVersion": "5.1.0",
    "validationMode": "compile",
    "params": [
        {"key": "host", "label": "Target host", "type": "string", "required": True},
        {"key": "port", "label": "SSH port", "type": "int", "required": False, "default": 22, "min": 1, "max": 65535},
        {"key": "username", "label": "Username", "type": "string", "required": True},
        {"key": "password", "label": "Password", "type": "secret", "required": False},
        {"key": "private_key", "label": "Private key (PEM)", "type": "textarea", "required": False},
        {"key": "private_key_passphrase", "label": "Private key passphrase", "type": "secret", "required": False},
        {"key": "host_key", "label": "Expected host public key (authorized_keys format)", "type": "textarea", "required": False},
        {"key": "timeout", "label": "Connection timeout (seconds)", "type": "int", "required": False, "default": 30, "min": 1, "max": 600},
    ],
}

load("runzero.types", "ImportAsset", "NetworkInterface")
load("runzero.ssh", ssh_dial="dial")
load("net", "ip_address")
load("kwargs", "require", "get_string", "get_int")


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
            iface = chunks[1].rstrip(":")
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
    timeout = get_int(kwargs, "timeout", default=30)

    if not password and not private_key:
        print("either password or private_key is required")
        return []

    session = ssh_dial(
        host=host,
        port=port,
        username=username,
        password=password,
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
        host_key=host_key,
        timeout=timeout,
    )
    hostname = _hostname(session)
    os_name, os_version = _os_release(session)
    kernel = _run(session, "uname -r")
    machine_id = _run(session, "cat /etc/machine-id 2>/dev/null || cat /var/lib/dbus/machine-id 2>/dev/null")
    interfaces = _macs_and_ips(session)
    session.close()

    asset_id = machine_id if machine_id else "{}@{}".format(username, host)
    asset = ImportAsset(
        id=asset_id,
        hostnames=[hostname] if hostname else [],
        os=os_name,
        osVersion=os_version,
        networkInterfaces=interfaces,
        customAttributes={
            "ssh.target": "{}:{}".format(host, port),
            "kernel": kernel,
            "machine_id": machine_id,
        },
    )
    # Stream the asset to runZero via report_assets instead of returning a list.
    report_assets(asset)
    return None
