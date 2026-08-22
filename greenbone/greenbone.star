# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-greenbone",
    "name": "Greenbone (GMP) Import",
    "type": "inbound",
    "description": "Imports assets, services, software, and vulnerabilities from Greenbone/OpenVAS over the Greenbone Management Protocol (GMP), via SSH or TLS.",
    "version": "1",
    "maturity": "alpha",
    # Deliberately ahead of the 5.0.260723.0 the rest of the library declares.
    # GMP is not an HTTP API, so this reaches it through ssh.open_unix() (a
    # direct-streamlocal channel to the gvmd socket) and socket.tls(tls=...);
    # both are newer than 5.0, and an Explorer without them fails inside the
    # transport rather than at install. Lower this only once they have shipped.
    "minVersion": "5.1.260818.0",
    # The Greenbone host id is not a stable runZero identity; always merge
    # scan results into existing assets by IP/MAC/hostname instead.
    "matchBehavior": "no-id-match no-id-break",
    "validationMode": "compile",
    "params": [
        {
            "key": "transport",
            "label": "Transport",
            "description": "How to reach the Greenbone Management Protocol endpoint. SSH forwards to the gvmd UNIX socket on the appliance; TLS connects directly to the GMP TLS port.",
            "type": "enum",
            "required": True,
            "default": "ssh",
            "options": ["ssh", "tls"],
        },
        # --- GMP authentication (both transports) ---
        {
            "key": "gmp_username",
            "label": "GMP username",
            "description": "Greenbone user with access to the scans/reports to import.",
            "type": "string",
            "required": True,
        },
        {
            "key": "gmp_password",
            "label": "GMP password",
            "type": "secret",
            "required": True,
        },
        # --- SSH transport ---
        {
            "key": "ssh_host",
            "label": "SSH host",
            "description": "Hostname or IP of the Greenbone appliance to SSH into.",
            "type": "string",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
            "requiredIf": "transport",
            "requiredIfValue": "ssh",
        },
        {
            "key": "ssh_port",
            "label": "SSH port",
            "type": "int",
            "required": False,
            "default": 22,
            "min": 1,
            "max": 65535,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        {
            "key": "ssh_username",
            "label": "SSH username",
            "type": "string",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
            "requiredIf": "transport",
            "requiredIfValue": "ssh",
        },
        {
            "key": "ssh_password",
            "label": "SSH password",
            "description": "SSH password (or use a private key).",
            "type": "secret",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        {
            "key": "ssh_private_key",
            "label": "SSH private key (PEM)",
            "type": "textarea",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        {
            "key": "ssh_private_key_passphrase",
            "label": "SSH private key passphrase",
            "type": "secret",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        {
            "key": "ssh_host_key",
            "label": "Expected SSH host key",
            "description": "Pin the appliance host key (authorized_keys format, e.g. from ssh-keyscan). Required unless host key checking is disabled.",
            "type": "textarea",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        {
            "key": "ssh_insecure_ignore_host_key",
            "label": "Disable SSH host key check",
            "description": "Accept any SSH host key (unsafe; use only for testing).",
            "type": "bool",
            "required": False,
            "default": False,
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        {
            "key": "gmp_socket_path",
            "label": "gvmd UNIX socket path",
            "description": "Path to the gvmd socket on the appliance to forward to over SSH.",
            "type": "string",
            "required": False,
            "default": "/run/gvmd/gvmd.sock",
            "visibleIf": "transport",
            "visibleIfValue": "ssh",
        },
        # --- TLS transport ---
        {
            "key": "gmp_host",
            "label": "GMP TLS host",
            "description": "Hostname or IP of the GMP TLS listener.",
            "type": "string",
            "required": False,
            "visibleIf": "transport",
            "visibleIfValue": "tls",
            "requiredIf": "transport",
            "requiredIfValue": "tls",
        },
        {
            "key": "gmp_port",
            "label": "GMP TLS port",
            "type": "int",
            "required": False,
            "default": 9390,
            "min": 1,
            "max": 65535,
            "visibleIf": "transport",
            "visibleIfValue": "tls",
        },
        # --- Import scope ---
        {
            "key": "max_age_days",
            "label": "Maximum report age (days)",
            "description": "Only import a task's latest report if it finished within this many days. Use 0 for no age limit.",
            "type": "int",
            "required": False,
            "default": 30,
            "min": 0,
            "max": 3650,
        },
        {
            "key": "task_filter",
            "label": "Task filter (GMP)",
            "description": "Optional GMP filter to select which tasks to import, e.g. 'name~Production' or 'apply_overrides=1'. Leave empty for all tasks.",
            "type": "string",
            "required": False,
            "default": "",
        },
        {
            "key": "report_filter",
            "label": "Report result filter (GMP)",
            "description": "Optional extra GMP filter terms applied to report results, e.g. 'os~Windows'. Combined with the severity and QoD settings below.",
            "type": "string",
            "required": False,
            "default": "",
        },
        {
            "key": "severity_levels",
            "label": "Severity levels",
            "description": "Result severity levels to import: h=high, m=medium, l=low, g=log/info. Include 'g' to import hosts with no vulnerabilities as assets.",
            "type": "string",
            "required": False,
            "default": "hmlg",
        },
        {
            "key": "min_qod",
            "label": "Minimum QoD",
            "description": "Minimum Quality of Detection (0-100) for imported results.",
            "type": "int",
            "required": False,
            "default": 70,
            "min": 0,
            "max": 100,
        },
        {
            "key": "page_size",
            "label": "Results per page",
            "description": "Number of results fetched per GMP page. Larger values reduce round-trips but use more memory per page.",
            "type": "int",
            "required": False,
            "default": 100,
            "min": 1,
            "max": 5000,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
    },
}

load("runzero.types", "ImportAsset", "Service", "ServiceProtocolData", "Software", "Vulnerability")
load("net", "network_interface", "ip_address")
load("xml", xml_parse="parse")
load("time", "parse_time", "now", "parse_duration")
load("kwargs", "require", "get_string", "get_int", "get_bool", "get_http_tls")
load("runzero.ssh", ssh_dial="dial")
load("socket", socket_tls="tls")
load("runzero.progress", progress_info="info")

# Well-known GVM object UUIDs are only needed by the scan-launch integration;
# this importer reads existing reports and needs none.

# Bound a single tag token (element text + one tag). Large enough for a PEM
# or long NVT description carried as element text.
MAX_TAG_BYTES = 4 * 1024 * 1024
# Hard ceiling on a single framed response element, as a safety net against a
# server that never closes an element. Paging keeps real pages far below this.
MAX_RESPONSE_BYTES = 256 * 1024 * 1024
# Safety bound on the number of tag tokens read while framing one response.
MAX_TAGS_PER_RESPONSE = 50000000

# -------------------------
# XML helpers
# -------------------------
def xml_escape(s):
    if s == None:
        return ""
    s = str(s)
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    s = s.replace("\"", "&quot;")
    s = s.replace("'", "&apos;")
    return s

def el_text(el, path):
    """Return the text of the first child matching path, or '' if absent."""
    if el == None:
        return ""
    child = el.find(path)
    if child == None:
        return ""
    return child.text

def trunc(s, n):
    """Truncate to n chars to satisfy ImportAsset field length limits."""
    if s == None:
        return ""
    s = str(s)
    if len(s) > n:
        return s[:n]
    return s

def valid_cve(cve):
    """Match runZero's CVE format: CVE-YYYY-N{4,19}."""
    if not cve or not cve.startswith("CVE-"):
        return False
    parts = cve.split("-")
    if len(parts) != 3:
        return False
    if len(parts[1]) != 4 or not parts[1].isdigit():
        return False
    if len(parts[2]) < 4 or not parts[2].isdigit():
        return False
    return True

def clean_attrs(d):
    """Drop empties and enforce key/value length limits for customAttributes."""
    out = {}
    for k, v in d.items():
        if v == None or v == "":
            continue
        out[trunc(k, 256)] = trunc(v, 1024)
    return out

# -------------------------
# GMP transport + framing
# -------------------------
def gmp_connect(kwargs):
    """Open a socket-like connection to the GMP endpoint. Returns (state, err)
    where state = {"conn": socket, "sess": ssh_session_or_None}."""
    transport = get_string(kwargs, "transport", default="ssh")
    timeout = 60

    if transport == "tls":
        require(kwargs, "gmp_host")
        host = get_string(kwargs, "gmp_host")
        port = get_int(kwargs, "gmp_port", default=9390)
        tls_opts = get_http_tls(kwargs, "tls_")
        conn = socket_tls(host, port, timeout=timeout, tls=tls_opts)
        if not conn:
            return None, "failed to open TLS connection to {}:{}".format(host, port)
        return {"conn": conn, "sess": None}, None

    # SSH transport: dial, then forward to the gvmd UNIX socket.
    require(kwargs, "ssh_host", "ssh_username")
    host = get_string(kwargs, "ssh_host")
    port = get_int(kwargs, "ssh_port", default=22)
    username = get_string(kwargs, "ssh_username")
    password = get_string(kwargs, "ssh_password", default="")
    private_key = get_string(kwargs, "ssh_private_key", default="")
    passphrase = get_string(kwargs, "ssh_private_key_passphrase", default="")
    host_key = get_string(kwargs, "ssh_host_key", default="")
    ignore_host_key = get_bool(kwargs, "ssh_insecure_ignore_host_key", default=False)
    socket_path = get_string(kwargs, "gmp_socket_path", default="/run/gvmd/gvmd.sock")

    if not password and not private_key:
        return None, "SSH transport requires ssh_password or ssh_private_key"
    if not host_key and not ignore_host_key:
        return None, "SSH transport requires ssh_host_key (or enable Disable SSH host key check)"

    sess = ssh_dial(
        host=host,
        port=port,
        username=username,
        password=password,
        private_key=private_key,
        private_key_passphrase=passphrase,
        host_key=host_key,
        insecure_ignore_host_key=ignore_host_key,
        timeout=timeout,
    )
    conn = sess.open_unix(socket_path)
    return {"conn": conn, "sess": sess}, None

def gmp_close(state):
    if state == None:
        return
    if state.get("conn"):
        state["conn"].close()
    if state.get("sess"):
        state["sess"].close()

def gmp_read_element(conn):
    """Read exactly one top-level XML element from conn by tokenizing on '>'
    and tracking tag depth. gvmd escapes '<'/'>' in text, so every '>' ends a
    tag. Returns (element_text, err)."""
    parts = []
    total = 0
    depth = 0
    started = False
    count = 0
    for _ in range(MAX_TAGS_PER_RESPONSE):
        count += 1
        tok = conn.recv_until(b">", max=MAX_TAG_BYTES, timeout=60)
        s = str(tok)
        if len(s) == 0:
            return None, "connection closed before a complete response was read"
        total += len(s)
        if total > MAX_RESPONSE_BYTES:
            return None, "GMP response exceeded {} bytes".format(MAX_RESPONSE_BYTES)
        parts.append(s)
        lt = s.rfind("<")
        if lt < 0:
            # A token with no tag start would be malformed; keep reading.
            continue
        tag = s[lt:]
        if tag.startswith("</"):
            depth -= 1
        elif tag.startswith("<?") or tag.startswith("<!"):
            pass
        elif tag.endswith("/>"):
            started = True
        else:
            depth += 1
            started = True
        if started and depth <= 0:
            return "".join(parts), None
    return None, "GMP response exceeded tag limit"

def gmp_command(conn, request_xml):
    """Send one GMP request and return (parsed_root, status, err)."""
    conn.send(request_xml)
    text, err = gmp_read_element(conn)
    if err:
        return None, "", err
    root = xml_parse(text)
    if root == None:
        return None, "", "failed to parse GMP response XML"
    return root, root.get("status"), None

def gmp_authenticate(conn, username, password):
    req = "<authenticate><credentials><username>{}</username><password>{}</password></credentials></authenticate>".format(
        xml_escape(username), xml_escape(password))
    root, status, err = gmp_command(conn, req)
    if err:
        return err
    if status != "200":
        return "GMP authentication failed (status {})".format(status)
    return None

# -------------------------
# Report parsing / asset mapping
# -------------------------
def inner_report(root):
    """From a get_reports_response, return the inner <report> element."""
    outer = root.find("report")
    if outer == None:
        return None
    inner = outer.find("report")
    if inner != None:
        return inner
    return outer

def parse_port(port_str):
    """'22/tcp' -> (22, 'tcp'); 'general/icmp' -> (None, 'icmp')."""
    if not port_str or "/" not in port_str:
        return None, ""
    left, right = port_str.rsplit("/", 1)
    proto = right.strip().lower()
    if left.isdigit():
        return int(left), proto
    return None, proto

def threat_to_rank(threat, severity):
    """Map GMP threat/severity to runZero severity rank 0-4."""
    sev = 0.0
    if severity:
        sev = float(severity)
    # GMP overloads negative severities as markers rather than scores: -1.0 is
    # False Positive, -2.0 Debug, -3.0 Error (older OpenVAS used -99.0). runZero
    # validates severityScore against a 0.0 minimum and a failure there fails the
    # ENTIRE record, so a single false-positive result would silently drop the
    # whole asset. Treat them as "no score" instead of forwarding them.
    if sev < 0.0:
        return 0, 0.0
    if sev >= 9.0:
        return 4, sev
    if sev >= 7.0:
        return 3, sev
    if sev >= 4.0:
        return 2, sev
    if sev > 0.0:
        return 1, sev
    return 0, sev

def cpe_to_software(cpe, address, port, transport):
    """Parse a CPE 2.2 URI (cpe:/a:vendor:product:version) into a Software."""
    body = cpe
    if cpe.startswith("cpe:/"):
        body = cpe[5:]
    elif cpe.startswith("cpe:2.3:"):
        body = cpe[8:]
    fields = body.split(":")
    vendor = ""
    product = ""
    version = ""
    # cpe 2.2: part:vendor:product:version:...
    if len(fields) >= 2:
        vendor = fields[1]
    if len(fields) >= 3:
        product = fields[2]
    if len(fields) >= 4:
        version = fields[3]
    cpe23 = cpe if cpe.startswith("cpe:/a:") else None
    sw = Software(
        id=trunc("{}:{}".format(address, cpe), 256),
        vendor=trunc(vendor, 128),
        product=trunc(product, 128),
        version=trunc(version, 128),
        cpe23=cpe23,
        serviceAddress=address,
        serviceTransport=transport if transport else "tcp",
        servicePort=port,
    )
    return sw

def host_state_new(ip):
    return {
        "ip": ip,
        "asset_id": "",
        "hostnames": {},
        "macs": {},
        "os_name": "",
        "os_cpe": "",
        "ports": {},        # "port/proto" -> {"port":int,"proto":str,"name":str,"product":str,"banner":str,"severity":str}
        "app_cpes": {},     # cpe -> "port/proto" (or "")
        "software": {},     # cpe -> True
        "vulns": {},        # vuln id -> Vulnerability
        "attrs": {},        # custom attributes
    }

def add_port(hs, port, proto):
    if port == None:
        return None
    key = "{}/{}".format(port, proto)
    if key not in hs["ports"]:
        hs["ports"][key] = {"port": port, "proto": proto, "name": "", "product": "", "version": "", "banner": "", "severity": ""}
    return hs["ports"][key]

def merge_host_detail(hs, host_el):
    asset = host_el.find("asset")
    if asset != None:
        aid = asset.get("asset_id")
        if aid:
            hs["asset_id"] = aid
    for d in host_el.find_all("detail"):
        name = el_text(d, "name")
        value = el_text(d, "value")
        if not name:
            continue
        if name == "best_os_txt" or (name == "OS" and not hs["os_name"] and not value.startswith("cpe:")):
            if value:
                hs["os_name"] = value
        elif name == "best_os_cpe":
            if value:
                hs["os_cpe"] = value
        elif name == "hostname":
            if value:
                hs["hostnames"][value] = True
        elif name == "MAC":
            if value:
                hs["macs"][value] = True
        elif name == "App":
            if value:
                hs["software"][value] = True
        elif name == "ports" or name == "tcp_ports":
            _add_ports_csv(hs, value, "tcp")
        elif name == "udp_ports":
            _add_ports_csv(hs, value, "udp")
        elif name == "Services":
            _merge_services_detail(hs, value)
        elif name.startswith("cpe:/a:") or name.startswith("cpe:2.3:a:"):
            # detail name is an app CPE, value is "PORT/proto"
            hs["software"][name] = True
            hs["app_cpes"][name] = value
        elif name == "traceroute":
            if value:
                hs["attrs"]["greenbone.traceroute"] = value

def _add_ports_csv(hs, value, default_proto):
    if not value:
        return
    for tok in value.replace("\n", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        port, proto = parse_port(tok)
        if port == None and tok.isdigit():
            port = int(tok)
            proto = default_proto
        if port != None:
            add_port(hs, port, proto if proto else default_proto)

def _merge_services_detail(hs, value):
    # "22,tcp,ssh,<banner...>"
    if not value:
        return
    fields = value.split(",", 3)
    if len(fields) < 2:
        return
    if not fields[0].strip().isdigit():
        return
    port = int(fields[0].strip())
    proto = fields[1].strip().lower()
    p = add_port(hs, port, proto)
    if p == None:
        return
    if len(fields) >= 3 and fields[2].strip():
        p["name"] = fields[2].strip()
    if len(fields) >= 4 and fields[3].strip():
        p["banner"] = fields[3].strip()

def merge_result(hs, result_el):
    nvt = result_el.find("nvt")
    oid = ""
    family = ""
    cvss_base = ""
    sev_types = ""
    if nvt != None:
        oid = nvt.get("oid")
        family = el_text(nvt, "family")
        cvss_base = el_text(nvt, "cvss_base")
        severities = nvt.find("severities")
        if severities != None:
            for sv in severities.find_all("severity"):
                t = sv.get("type")
                if t:
                    sev_types += t + " "
    name = el_text(result_el, "name")
    threat = el_text(result_el, "threat")
    severity = el_text(result_el, "severity")
    description = el_text(result_el, "description")
    solution = el_text(nvt, "solution") if nvt != None else ""
    qod = el_text(result_el, "qod/value")
    port_str = el_text(result_el, "port")
    port, proto = parse_port(port_str)

    # A result-level hostname refines the host record.
    host_el = result_el.find("host")
    if host_el != None:
        hn = el_text(host_el, "hostname")
        if hn:
            hs["hostnames"][hn] = True

    rank, sev_score = threat_to_rank(threat, severity)

    cves = []
    if nvt != None:
        refs = nvt.find("refs")
        if refs != None:
            for ref in refs.find_all("ref"):
                if ref.get("type") == "cve":
                    cid = ref.get("id")
                    if cid:
                        cves.append(cid)

    base_attrs = clean_attrs({
        "greenbone.nvt_oid": oid,
        "greenbone.threat": threat,
        "greenbone.qod": qod,
        "greenbone.family": family,
    })

    cvss2 = None
    cvss3 = None
    if cvss_base:
        score = float(cvss_base)
        if score >= 0.0 and score <= 10.0:
            if "v3" in sev_types or "v4" in sev_types:
                cvss3 = score
            else:
                cvss2 = score

    # One Vulnerability per CVE, or a single NVT-scoped entry when no CVE.
    keys = cves if cves else [""]
    for cve in keys:
        vid = "{}:{}".format(oid, cve) if cve else oid
        if port != None:
            vid = "{}:{}/{}".format(vid, port, proto)
        vid = trunc(vid, 256)
        if vid in hs["vulns"]:
            continue
        v = Vulnerability(
            id=vid,
            name=trunc(name, 256),
            description=trunc(description, 1024),
            solution=trunc(solution, 1024),
            category=trunc(family, 256),
            cve=cve if valid_cve(cve) else None,
            serviceAddress=hs["ip"],
            serviceTransport=proto if proto else None,
            servicePort=port,
            cvss2BaseScore=cvss2,
            cvss3BaseScore=cvss3,
            severityRank=rank,
            severityScore=sev_score,
            customAttributes=base_attrs,
        )
        hs["vulns"][vid] = v

def merge_port_summary(hs, port_el):
    """From the report <ports> section: <port><host>IP</host>80/tcp<severity>..."""
    host_child = port_el.find("host")
    port_text = ""
    if host_child != None:
        # "80/tcp" is the tail text following the <host> child.
        port_text = host_child.tail.strip()
    if not port_text:
        port_text = port_el.text.strip()
    port, proto = parse_port(port_text)
    if port == None:
        return
    p = add_port(hs, port, proto)
    sev = el_text(port_el, "severity")
    if p != None and sev:
        p["severity"] = sev

def build_asset(hs, report_id, task_name, scan_end):
    ip = hs["ip"]
    ip_obj = ip_address(ip)
    nic = network_interface(ips=[ip], mac=list(hs["macs"].keys())[0] if hs["macs"] else None)
    nics = [nic] if nic else []

    # Attach app CPEs to their ports where known.
    software = []
    for cpe in hs["software"].keys():
        loc = hs["app_cpes"].get(cpe, "")
        port, proto = parse_port(loc)
        software.append(cpe_to_software(cpe, ip, port, proto))

    services = []
    for key, p in hs["ports"].items():
        proto = p["proto"] if p["proto"] else "tcp"
        pd_name = p["name"] if p["name"] else proto
        pd_attrs = {}
        if p["banner"]:
            pd_attrs["banner"] = trunc(p["banner"], 1024)
        if p["severity"]:
            pd_attrs["severity"] = trunc(p["severity"], 1024)
        # A Service must carry at least one ServiceProtocolData.
        pdata = [ServiceProtocolData(name=trunc(pd_name, 128), attributes=pd_attrs)]
        svc = Service(
            address=ip,
            port=p["port"],
            transport=proto,
            product=trunc(p["product"], 256),
            protocolData=pdata,
        )
        services.append(svc)

    vulns = list(hs["vulns"].values())

    attrs = {}
    for k, v in hs["attrs"].items():
        attrs[k] = v
    attrs["greenbone.report_id"] = report_id
    attrs["greenbone.task"] = task_name
    attrs["greenbone.scan_end"] = scan_end
    if hs["asset_id"]:
        attrs["greenbone.asset_id"] = hs["asset_id"]
    if hs["os_cpe"]:
        attrs["greenbone.os_cpe"] = hs["os_cpe"]

    asset_id = hs["asset_id"] if hs["asset_id"] else "greenbone:{}".format(ip)
    hostnames = []
    for hn in hs["hostnames"].keys():
        hostnames.append(trunc(hn, 260))

    return ImportAsset(
        id=trunc(asset_id, 256),
        hostnames=hostnames,
        os=trunc(hs["os_name"], 256),
        networkInterfaces=nics,
        services=services,
        software=software,
        vulnerabilities=vulns,
        customAttributes=clean_attrs(attrs),    )

# -------------------------
# Report import (paged, streaming)
# -------------------------
def import_report(conn, report_id, task_name, scan_end, kwargs):
    levels = get_string(kwargs, "severity_levels", default="hmlg")
    min_qod = get_int(kwargs, "min_qod", default=70)
    page_size = get_int(kwargs, "page_size", default=100)
    extra_filter = get_string(kwargs, "report_filter", default="")

    pending = {}      # ip -> host_state
    order = []        # ip order across pages (for stable flushing)
    first = 1
    total_assets = 0
    prev_sig = None   # guards against a server that ignores pagination

    for _page in range(1000000):
        filt = "apply_overrides=0 levels={} min_qod={} first={} rows={} sort=host".format(
            levels, min_qod, first, page_size)
        if extra_filter:
            filt = extra_filter + " " + filt
        req = "<get_reports report_id=\"{}\" details=\"1\" lean=\"1\" filter=\"{}\"/>".format(
            xml_escape(report_id), xml_escape(filt))
        root, status, err = gmp_command(conn, req)
        if err:
            print("get_reports failed for {}: {}".format(report_id, err))
            break
        if status != "200":
            print("get_reports status {} for {}".format(status, report_id))
            break
        report = inner_report(root)
        if report == None:
            break

        results = report.find_all("results/result")
        host_blocks = report.find_all("host")
        port_summ = report.find_all("ports/port")
        got = len(results)

        # Forward-progress guard: each result carries a unique id. If a page
        # repeats the previous page's first+last result ids, the server is not
        # honoring pagination, so stop rather than loop on the same data.
        if got > 0:
            sig = "{}|{}".format(results[0].get("id"), results[len(results) - 1].get("id"))
            if sig == prev_sig:
                print("greenbone: report {} pagination did not advance; stopping".format(report_id[:8]))
                break
            prev_sig = sig

        # Track host order within this page (result order == host sort order).
        page_hosts = []
        for r in results:
            hel = r.find("host")
            rip = hel.text if hel != None else ""
            if not rip:
                continue
            if rip not in pending:
                pending[rip] = host_state_new(rip)
                order.append(rip)
            if rip not in page_hosts:
                page_hosts.append(rip)
            merge_result(pending[rip], r)

        for hb in host_blocks:
            hip = el_text(hb, "ip")
            if not hip:
                continue
            if hip not in pending:
                pending[hip] = host_state_new(hip)
                order.append(hip)
            if hip not in page_hosts:
                page_hosts.append(hip)
            merge_host_detail(pending[hip], hb)

        for pe in port_summ:
            hc = pe.find("host")
            hip = hc.text if hc != None else ""
            if hip and hip in pending:
                merge_port_summary(pending[hip], pe)

        last_page = got < page_size

        # Flush hosts that cannot continue into the next page. On the last page
        # everything is flushed; otherwise keep only the trailing host.
        keep = "" if last_page else (page_hosts[-1] if page_hosts else "")
        flushed = []
        for ip in order:
            if ip == keep:
                continue
            if ip in pending:
                report_assets(build_asset(pending[ip], report_id, task_name, scan_end))
                total_assets += 1
                flushed.append(ip)
                pending.pop(ip)
        new_order = []
        for ip in order:
            if ip not in flushed:
                new_order.append(ip)
        order = new_order

        progress_info("greenbone: report {} imported {} assets so far".format(report_id[:8], total_assets))

        if last_page:
            break
        first += page_size

    # Flush any remainder.
    for ip in order:
        if ip in pending:
            report_assets(build_asset(pending[ip], report_id, task_name, scan_end))
            total_assets += 1
    return total_assets

# -------------------------
# Entry point
# -------------------------
def main(*args, **kwargs):
    require(kwargs, "gmp_username", "gmp_password")
    gmp_username = get_string(kwargs, "gmp_username")
    gmp_password = get_string(kwargs, "gmp_password")
    max_age_days = get_int(kwargs, "max_age_days", default=30)
    task_filter = get_string(kwargs, "task_filter", default="")

    state, err = gmp_connect(kwargs)
    if err:
        print("connection failed:", err)
        return None
    if state == None:
        print("connection failed")
        return None
    conn = state["conn"]

    err = gmp_authenticate(conn, gmp_username, gmp_password)
    if err:
        print(err)
        gmp_close(state)
        return None

    # Enumerate tasks and their latest reports.
    task_filt = "rows=-1"
    if task_filter:
        task_filt = task_filter + " rows=-1"
    root, status, err = gmp_command(conn, "<get_tasks filter=\"{}\"/>".format(xml_escape(task_filt)))
    if err or status != "200":
        print("greenbone: get_tasks failed: {}".format(err if err else "status {}".format(status)))
        gmp_close(state)
        return None

    cutoff = None
    if max_age_days > 0:
        cutoff = now() + parse_duration("-{}h".format(max_age_days * 24))

    tasks = root.find_all("task")
    print("greenbone: {} task(s) found".format(len(tasks)))

    total = 0
    imported_reports = 0
    # Age-filtered tasks are counted rather than announced one by one; on a
    # long-lived install most tasks are older than the window and the list of
    # them says nothing the count does not.
    stale = 0
    stale_first = ""
    for task in tasks:
        task_id = task.get("id")
        task_name = el_text(task, "name")
        last_report = task.find("last_report")
        if last_report == None:
            continue
        report_el = last_report.find("report")
        if report_el == None:
            continue
        report_id = report_el.get("id")
        scan_end = el_text(report_el, "scan_end")
        if not report_id:
            continue

        if cutoff != None and scan_end:
            ended = parse_time(scan_end)
            if ended != None and ended.unix < cutoff.unix:
                stale += 1
                if stale == 1:
                    stale_first = "{} (last report {})".format(task_name, scan_end)
                continue

        print("greenbone: importing task '{}' report {} (scan_end {})".format(task_name, report_id[:8], scan_end))
        n = import_report(conn, report_id, task_name, scan_end, kwargs)
        total += n
        imported_reports += 1

    gmp_close(state)
    if stale > 0:
        print("greenbone: skipped {} tasks whose last report is older than {} days (first: {})".format(
            stale, max_age_days, stale_first))
    print("greenbone: imported {} assets from {} report(s)".format(total, imported_reports))
    return None
