CONFIG = {
    "id": "runzero-windows-wmi",
    "name": "Windows WMI",
    "type": "inbound",
    "description": "Collect a Windows host's OS, hardware, network, services, and installed software via WinRM or DCE-RPC WMI.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "validationMode": "compile",
    "params": [
        {
            "key": "host",
            "label": "Host",
            "description": "Hostname or IP of the Windows target.",
            "type": "string",
            "required": True,
        },
        {
            "key": "username",
            "label": "Username",
            "description": "DOMAIN\\\\user, user@domain, or local account.",
            "type": "string",
            "required": True,
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
        {
            "key": "transport",
            "label": "Transport",
            "type": "enum",
            "options": ["winrm-https", "winrm-http", "wmi-tcp", "wmi-smb"],
            "default": "winrm-https",
        },
        {
            "key": "winrm_port",
            "label": "WinRM port",
            "type": "int",
            "min": 0,
            "max": 65535,
            "default": 0,
        },
        {
            "key": "winrm_insecure",
            "label": "Skip TLS verification (NOT for production)",
            "type": "bool",
            "default": False,
        },
        {
            "key": "winrm_ca_cert",
            "label": "PEM CA bundle",
            "type": "textarea",
        },
        {
            "key": "winrm_auth",
            "label": "WinRM auth",
            "type": "enum",
            "options": ["ntlm", "basic"],
            "default": "ntlm",
        },
        {
            "key": "wmi_namespace",
            "label": "WMI namespace",
            "type": "string",
            "default": "//./root/cimv2",
        },
        {
            "key": "timeout",
            "label": "Timeout (seconds)",
            "type": "int",
            "min": 1,
            "max": 600,
            "default": 60,
        },
    ],
}

load("runzero.types", "ImportAsset", "NetworkInterface", "Software")
load("runzero.winrm", winrm_dial="dial")
load("runzero.wmi", wmi_dial="dial")
load("kwargs", "require", "get_string", "get_int", "get_bool")
load("net", "ip_address")

# Queries kept short so the WQL stays well under the 4 KiB limit.
Q_OS = "SELECT Caption, Version, BuildNumber, OSArchitecture, CSName, InstallDate FROM Win32_OperatingSystem"
Q_CS = "SELECT Manufacturer, Model, Domain, SystemType, PCSystemType, TotalPhysicalMemory FROM Win32_ComputerSystem"
Q_NIC = "SELECT Description, MACAddress, IPAddress, DHCPEnabled, IPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=true"
Q_SVC = "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service"
Q_PROD = "SELECT Name, Version, Vendor, InstallDate FROM Win32_Product"
Q_ENC = "SELECT ChassisTypes FROM Win32_SystemEnclosure"

# SMBIOS System Enclosure type (DMTF SMBIOS 3.x, Type 3 field 05h), which is
# what Win32_SystemEnclosure.ChassisTypes reports. Only the values that name a
# form factor outright are mapped; "Other" (1), "Unknown" (2), the expansion
# and peripheral chassis (18-22, 25-27), and the ambiguous historical types
# ("Pizza Box", "Lunch Box") are deliberately absent, so a machine that reports
# one of those keeps no device type and runZero's own fingerprinting decides.
CHASSIS_DEVICE_TYPES = {
    "3": "Desktop",           # Desktop
    "4": "Desktop",           # Low Profile Desktop
    "6": "Desktop",           # Mini Tower
    "7": "Desktop",           # Tower
    "13": "Desktop",          # All in One
    "15": "Desktop",          # Space-saving
    "24": "Desktop",          # Sealed-case PC
    "35": "Desktop",          # Mini PC
    "8": "Laptop",            # Portable
    "9": "Laptop",            # Laptop
    "10": "Laptop",           # Notebook
    "14": "Laptop",           # Sub Notebook
    "31": "Laptop",           # Convertible
    "32": "Laptop",           # Detachable
    "30": "Tablet",           # Tablet
    "17": "Server",           # Main Server Chassis
    "23": "Server",           # Rack Mount Chassis
    "28": "Server",           # Blade
    "29": "Server",           # Blade Enclosure
}

# Win32_ComputerSystem.PCSystemType, which Windows derives from the same SMBIOS
# data. It is coarser than the chassis type -- it cannot see a tablet, and it
# folds every portable into "Mobile" -- so it is only consulted when the
# enclosure reports nothing usable. 6 ("Appliance PC") and 8 ("Maximum") name
# no form factor and are left out.
PC_SYSTEM_TYPES = {
    "1": "Desktop",           # Desktop
    "2": "Laptop",            # Mobile
    "3": "Desktop",           # Workstation
    "4": "Server",            # Enterprise Server
    "5": "Server",            # SOHO Server
    "7": "Server",            # Performance Server
}


def _smbios_key(value):
    """Return a WMI numeric as a plain integer string for a map lookup.

    ChassisTypes and PCSystemType are uint16 in CIM, but the value arrives here
    through PowerShell's ConvertTo-Json and then the runtime's Go-to-Starlark
    conversion, so it can present as an int, a float, or a string depending on
    the transport. Normalising to one spelling keeps the lookup from silently
    missing on a host where the type happened to decode as 9.0 rather than 9.
    """
    if value == None:
        return ""
    text = str(value).strip()
    if text.endswith(".0"):
        text = text[:-len(".0")]
    return text


def _chassis_values(enc_rows):
    """Return every SMBIOS chassis type reported, normalised to integer strings."""
    values = []
    for row in enc_rows:
        raw = row.get("ChassisTypes")
        if type(raw) != "list":
            raw = [raw]
        for value in raw:
            key = _smbios_key(value)
            if key and key not in values:
                values.append(key)
    return values


def _device_type(enc_rows, cs_row):
    """Return the runZero device type for this host, or None if unknown."""
    for value in _chassis_values(enc_rows):
        mapped = CHASSIS_DEVICE_TYPES.get(value, "")
        if mapped:
            return mapped
    return PC_SYSTEM_TYPES.get(_smbios_key(cs_row.get("PCSystemType")), None)


def _ip_list(raw):
    if raw == None:
        return [], []
    if type(raw) == "string":
        raw = [raw]
    ip4, ip6 = [], []
    for s in raw:
        if not s:
            continue
        addr = ip_address(s)
        if addr == None:
            continue
        if addr.version == 4:
            ip4.append(addr)
        else:
            ip6.append(addr)
    return ip4, ip6


def _build_nics(nic_rows):
    out = []
    for r in nic_rows:
        mac = r.get("MACAddress") or ""
        ip4, ip6 = _ip_list(r.get("IPAddress"))
        if not mac and not ip4 and not ip6:
            continue
        out.append(NetworkInterface(macAddress=mac, ipv4Addresses=ip4, ipv6Addresses=ip6))
    return out


def _build_software(prod_rows):
    out = []
    for r in prod_rows:
        name = r.get("Name") or ""
        if not name:
            continue
        out.append(Software(
            id=name[:255],
            product=name[:255],
            vendor=(r.get("Vendor") or "")[:255],
            version=(r.get("Version") or "")[:255],
        ))
    return out


def _collect_winrm(host, username, password, transport, port, insecure, ca, auth, namespace, timeout):
    https = transport == "winrm-https"
    s = winrm_dial(
        host=host,
        username=username,
        password=password,
        port=port,
        https=https,
        insecure_skip_verify=insecure,
        ca_cert=ca,
        auth=auth,
        timeout=timeout,
    )
    os_rows = s.wql(Q_OS, namespace=namespace)
    cs_rows = s.wql(Q_CS, namespace=namespace)
    enc_rows = s.wql(Q_ENC, namespace=namespace)
    nic_rows = s.wql(Q_NIC, namespace=namespace)
    svc_rows = s.wql(Q_SVC, namespace=namespace)
    prod_rows = s.wql(Q_PROD, namespace=namespace)
    s.close()
    return os_rows, cs_rows, enc_rows, nic_rows, svc_rows, prod_rows


def _collect_wmi(host, username, password, transport, namespace, timeout):
    s = wmi_dial(
        host=host,
        username=username,
        password=password,
        transport="smb" if transport == "wmi-smb" else "tcp",
        namespace=namespace,
        timeout=timeout,
    )
    os_rows = s.query(Q_OS)
    cs_rows = s.query(Q_CS)
    enc_rows = s.query(Q_ENC)
    nic_rows = s.query(Q_NIC)
    svc_rows = s.query(Q_SVC)
    prod_rows = s.query(Q_PROD)
    s.close()
    return os_rows, cs_rows, enc_rows, nic_rows, svc_rows, prod_rows


def main(*args, **kwargs):
    require(kwargs, "host", "username", "password")
    host = get_string(kwargs, "host")
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    transport = get_string(kwargs, "transport", default="winrm-https")
    namespace = get_string(kwargs, "wmi_namespace", default="//./root/cimv2")
    timeout = get_int(kwargs, "timeout", default=60)

    if transport.startswith("winrm-"):
        port = get_int(kwargs, "winrm_port", default=0)
        insecure = get_bool(kwargs, "winrm_insecure", default=False)
        ca = get_string(kwargs, "winrm_ca_cert", default="") or None
        auth = get_string(kwargs, "winrm_auth", default="ntlm")
        os_rows, cs_rows, enc_rows, nic_rows, svc_rows, prod_rows = _collect_winrm(
            host, username, password, transport, port, insecure, ca, auth,
            # WinRM helper expects WMI namespace as "root/cimv2" style.
            namespace.lstrip("/").lstrip("."),
            timeout,
        )
    else:
        os_rows, cs_rows, enc_rows, nic_rows, svc_rows, prod_rows = _collect_wmi(
            host, username, password, transport, namespace, timeout,
        )

    os_row = os_rows[0] if os_rows else {}
    cs_row = cs_rows[0] if cs_rows else {}

    hostnames = []
    cs_name = os_row.get("CSName") or cs_row.get("Name")
    if cs_name:
        hostnames.append(cs_name)

    nics = _build_nics(nic_rows)
    software = _build_software(prod_rows)

    custom_attrs = {
        "wmi.manufacturer": cs_row.get("Manufacturer") or "",
        "wmi.model": cs_row.get("Model") or "",
        "wmi.domain": cs_row.get("Domain") or "",
        "wmi.systemType": cs_row.get("SystemType") or "",
        # The raw SMBIOS value behind deviceType, kept so an operator can see
        # why a host was or was not typed without re-running the query.
        "wmi.chassisType": ",".join(_chassis_values(enc_rows)),
        "wmi.serviceCount": str(len(svc_rows)),
        "wmi.transport": transport,
    }
    custom_attrs = {k: v for k, v in custom_attrs.items() if v}

    asset = ImportAsset(
        id=cs_name or host,
        hostnames=hostnames,
        os=os_row.get("Caption") or "",
        osVersion=os_row.get("Version") or "",
        deviceType=_device_type(enc_rows, cs_row),
        networkInterfaces=nics,
        software=software,
        customAttributes=custom_attrs,
    )
    # Stream the asset to runZero via report_assets instead of returning a list.
    report_assets(asset)
    return None
