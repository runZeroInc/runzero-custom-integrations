CONFIG = {
    "id": "runzero-windows-smb-shares",
    "name": "Windows SMB shares",
    "type": "inbound",
    "description": "Enumerates SMB shares on a Windows host and reports the host plus accessible shares as a runZero asset.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
        # Skip the interprocess-communication pipe and hidden administrative
        # shares by name. These are not file shares -- IPC$ in particular is a
        # named-pipe endpoint that a directory listing means nothing against --
        # so there is nothing to report even where the account could reach them.
        if name.endswith("$") and name != "ADMIN$":
            continue

        # Everything below tolerates a refusal. Entitlement does not follow
        # naming: any share can be denied to the polling account, and the skip
        # above is a guess about intent rather than a check of access. Where the
        # runtime supports it, mount() and list() answer None when the server
        # refuses on permissions, so a share this account cannot read costs us
        # that share and nothing else.
        #
        # These checks are what a script can do; they are not sufficient on
        # their own. On a runtime that still raises on a refused tree connect --
        # every released Explorer as of this writing -- there is no return value
        # to test and the whole run is lost with the first denied share, because
        # Starlark has no exception handling and the only way to discover the
        # refusal is to attempt the mount. See README.md, "A refused share
        # depends on the runtime".
        share = session.mount(share=name)
        if share == None:
            share_attrs["share.{}".format(name)] = "denied"
            continue

        # A successful mount does not imply a readable root: Windows commonly
        # grants the tree connect and then refuses the listing via an ACL.
        result = share.list(path="/")
        share.unmount()
        if result == None:
            share_attrs["share.{}".format(name)] = "denied"
            continue

        entries = []
        for e in result:
            entries.append(e["name"])
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
