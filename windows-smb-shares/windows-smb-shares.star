CONFIG = {
    "id": "runzero-windows-smb-shares",
    "name": "Windows SMB shares",
    "type": "inbound",
    "description": "Enumerates SMB shares on a Windows host and reports the host plus accessible shares as a runZero asset.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "validationMode": "compile",
    "params": [
        {"key": "host", "label": "Target host", "type": "string", "required": True},
        {"key": "port", "label": "SMB port", "type": "int", "required": False, "default": 445, "min": 1, "max": 65535},
        {"key": "username", "label": "Username (may include DOMAIN\\user)", "type": "string", "required": True},
        {"key": "password", "label": "Password", "type": "secret", "required": False},
        {"key": "nt_hash", "label": "NTLM hash (hex)", "type": "string", "required": False},
        {"key": "domain", "label": "Domain (optional)", "type": "string", "required": False, "default": ""},
        {"key": "timeout", "label": "Connection timeout (seconds)", "type": "int", "required": False, "default": 30, "min": 1, "max": 600},
    ],
}

load("runzero.types", "ImportAsset")
load("runzero.smb", smb_dial="dial")
load("kwargs", "require", "get_string", "get_int")


def main(*args, **kwargs):
    require(kwargs, "host", "username")
    host = get_string(kwargs, "host")
    port = get_int(kwargs, "port", default=445)
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password", default="")
    nt_hash = get_string(kwargs, "nt_hash", default="")
    domain = get_string(kwargs, "domain", default="")
    timeout = get_int(kwargs, "timeout", default=30)

    if not password and not nt_hash:
        print("either password or nt_hash is required")
        return []

    session = smb_dial(
        host=host,
        port=port,
        username=username,
        password=password,
        nt_hash=nt_hash,
        domain=domain,
        timeout=timeout,
    )

    shares = session.list_shares()
    visible_count = 0
    share_attrs = {}
    for name in shares:
        share_attrs["share.{}".format(name)] = "listed"
        # Attempt to mount each share and count top-level entries; we
        # silently skip shares we cannot access (typical for IPC$ or
        # admin shares without privilege).
        if name.endswith("$") and name != "ADMIN$":
            continue
        entries = []
        share = session.mount(share=name)
        result = share.list(path="/")
        for e in result:
            entries.append(e["name"])
        share.unmount()
        if len(entries) > 0:
            visible_count += 1
            share_attrs["share.{}.entries".format(name)] = ", ".join(entries[:20])
    session.close()

    attrs = {
        "smb.target": "{}:{}".format(host, port),
        "smb.share_count": "{}".format(len(shares)),
        "smb.accessible_share_count": "{}".format(visible_count),
    }
    attrs.update(share_attrs)

    asset = ImportAsset(
        id="smb://{}:{}".format(host, port),
        hostnames=[host],
        os="Windows",
        customAttributes=attrs,
    )
    # Stream the asset to runZero via report_assets instead of returning a list.
    report_assets(asset)
    return None
