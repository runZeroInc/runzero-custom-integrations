# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-greenbone-scan",
    "name": "Greenbone (GMP) Scan Launch",
    "type": "internal",
    "description": "Exports the primary addresses of matching runZero assets and launches a Greenbone/OpenVAS scan against them over the Greenbone Management Protocol (GMP), via SSH or TLS.",
    "version": "1",
    "maturity": "alpha",
    # Deliberately ahead of the 5.0.260723.0 the rest of the library declares.
    # GMP is not an HTTP API, so this reaches it through ssh.open_unix() (a
    # direct-streamlocal channel to the gvmd socket) and socket.tls(tls=...);
    # both are newer than 5.0, and an Explorer without them fails inside the
    # transport rather than at install. Lower this only once they have shipped.
    "minVersion": "5.1.260818.0",
    "validationMode": "compile",
    "params": [
        # --- runZero export source ---
        {
            "key": "runzero_url",
            "label": "runZero console URL",
            "type": "url",
            "required": True,
            "default": "https://console.runzero.com",
        },
        {
            "key": "runzero_export_token",
            "label": "runZero Export API key",
            "description": "Organization Export API key used to read the asset inventory.",
            "type": "secret",
            "required": True,
        },
        {
            "key": "export_filter",
            "label": "Export search filter",
            "description": "runZero asset search to select scan targets. Empty scans all assets. Examples: 'os:Windows', 'last_seen:<30d', 'first_seen:<3d'.",
            "type": "string",
            "required": False,
            "default": "",
        },
        {
            "key": "max_hosts",
            "label": "Maximum hosts",
            "description": "Cap on the number of primary addresses sent to Greenbone.",
            "type": "int",
            "required": False,
            "default": 1000000,
            "min": 1,
            "max": 1000000,
        },
        # --- GMP transport ---
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
            "description": "Pin the appliance host key (authorized_keys format). Required unless host key checking is disabled.",
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
        # --- Scan definition ---
        {
            "key": "target_name",
            "label": "Target/task name prefix",
            "description": "Prefix for the Greenbone target and task created for this scan. A timestamp is appended to keep it unique.",
            "type": "string",
            "required": False,
            "default": "runZero",
        },
        {
            "key": "scan_config_id",
            "label": "Scan config ID",
            "description": "Greenbone scan config UUID. Default is 'Full and fast'.",
            "type": "string",
            "required": False,
            "default": "daba56c8-73ec-11df-a475-002264764cea",
        },
        {
            "key": "scanner_id",
            "label": "Scanner ID",
            "description": "Greenbone scanner UUID. Default is the built-in 'OpenVAS Default' scanner.",
            "type": "string",
            "required": False,
            "default": "08b69003-5fc2-4037-a479-93b440211c73",
        },
        {
            "key": "port_list_id",
            "label": "Port list ID",
            "description": "Greenbone port list UUID. Default is 'All IANA assigned TCP'.",
            "type": "string",
            "required": False,
            "default": "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
        },
        {
            "key": "start_scan",
            "label": "Start scan immediately",
            "description": "Start the task after creating it. Disable to only create the target and task.",
            "type": "bool",
            "required": False,
            "default": True,
        },
    ],
    "includes": {
        "rz_http_": OPTIONS_HTTP,
        "rz_tls_": OPTIONS_TLS,
        "tls_": OPTIONS_TLS,
    },
}

load("http", http_get="get")
load("csv", csv_read="read_all")
load("net", "ip_address")
load("xml", xml_parse="parse")
load("time", "now")
load("kwargs", "require", "get_string", "get_int", "get_bool", "get_url_base", "get_http_options", "get_http_tls")
load("runzero.ssh", ssh_dial="dial")
load("socket", socket_tls="tls")
load("runzero.progress", progress_info="info")

MAX_TAG_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
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

# -------------------------
# GMP transport + framing (shared shape with the import integration)
# -------------------------
def gmp_connect(kwargs):
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
    parts = []
    total = 0
    depth = 0
    started = False
    for _ in range(MAX_TAGS_PER_RESPONSE):
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
    conn.send(request_xml)
    text, err = gmp_read_element(conn)
    if err:
        return None, "", "", err
    root = xml_parse(text)
    if root == None:
        return None, "", "", "failed to parse GMP response XML"
    return root, root.get("status"), root.get("status_text"), None

def gmp_authenticate(conn, username, password):
    req = "<authenticate><credentials><username>{}</username><password>{}</password></credentials></authenticate>".format(
        xml_escape(username), xml_escape(password))
    root, status, status_text, err = gmp_command(conn, req)
    if err:
        return err
    if status != "200":
        return "GMP authentication failed (status {}: {})".format(status, status_text)
    return None

# -------------------------
# runZero export
# -------------------------
def fetch_target_addresses(kwargs):
    """Fetch primary addresses of matching assets from the runZero export CSV
    endpoint. Returns (addresses_list, err)."""
    base_url = get_url_base(kwargs, "runzero_url")
    token = get_string(kwargs, "runzero_export_token")
    search = get_string(kwargs, "export_filter", default="")
    max_hosts = get_int(kwargs, "max_hosts", default=4096)

    options = get_http_options(kwargs, "rz_http_", "rz_tls_", {
        "Authorization": "Bearer {}".format(token),
        "Accept": "text/csv",
    })
    url = base_url + "/api/v1.0/export/org/assets.csv"
    params = {"fields": "address"}
    if search:
        params["search"] = search

    resp = http_get(url, params=params, timeout=3600, **options)
    if not resp:
        return None, "no response from runZero export API"
    if resp.status_code != 200:
        return None, "runZero export returned status {}".format(resp.status_code)

    rows = csv_read(str(resp.body))
    seen = {}
    ordered = []
    for row in rows:
        addr = row.get("address", "").strip()
        if not addr:
            continue
        # Validate and normalize; skip anything that is not an IP.
        parsed = ip_address(addr)
        if parsed == None:
            continue
        key = str(parsed)
        if key in seen:
            continue
        seen[key] = True
        ordered.append(key)
        if len(ordered) >= max_hosts:
            break
    return ordered, None

# -------------------------
# Scan creation
# -------------------------
def create_scan(conn, addresses, kwargs):
    target_prefix = get_string(kwargs, "target_name", default="runZero")
    config_id = get_string(kwargs, "scan_config_id", default="daba56c8-73ec-11df-a475-002264764cea")
    scanner_id = get_string(kwargs, "scanner_id", default="08b69003-5fc2-4037-a479-93b440211c73")
    port_list_id = get_string(kwargs, "port_list_id", default="33d0cd82-57c6-11e1-8ed1-406186ea4fc5")
    start_scan = get_bool(kwargs, "start_scan", default=True)

    stamp = now().format("2006-01-02 15:04:05")
    name = "{} {}".format(target_prefix, stamp)
    hosts = ",".join(addresses)

    # 1) Create the target.
    target_req = "<create_target><name>{}</name><hosts>{}</hosts><port_list id=\"{}\"/><comment>Created by runZero ({} hosts)</comment></create_target>".format(
        xml_escape(name), xml_escape(hosts), xml_escape(port_list_id), len(addresses))
    root, status, status_text, err = gmp_command(conn, target_req)
    if err:
        return "create_target failed: {}".format(err)
    if status != "201":
        return "create_target failed (status {}: {})".format(status, status_text)
    target_id = root.get("id")
    if not target_id:
        return "create_target did not return a target id"
    progress_info("greenbone-scan: created target {} ({} hosts)".format(target_id, len(addresses)))

    # 2) Create the task.
    task_req = "<create_task><name>{}</name><comment>Created by runZero</comment><config id=\"{}\"/><target id=\"{}\"/><scanner id=\"{}\"/></create_task>".format(
        xml_escape(name), xml_escape(config_id), xml_escape(target_id), xml_escape(scanner_id))
    root, status, status_text, err = gmp_command(conn, task_req)
    if err or status != "201":
        # Roll back the orphaned target so a failed run does not litter gvmd.
        gmp_command(conn, "<delete_target target_id=\"{}\" ultimate=\"1\"/>".format(xml_escape(target_id)))
        return "create_task failed (status {}: {}); rolled back target".format(status, status_text if status_text else err)
    task_id = root.get("id")
    if not task_id:
        return "create_task did not return a task id"
    progress_info("greenbone-scan: created task {}".format(task_id))

    # 3) Optionally start the scan.
    if not start_scan:
        print("greenbone-scan: created target {} and task {} (not started)".format(target_id, task_id))
        return None

    root, status, status_text, err = gmp_command(conn, "<start_task task_id=\"{}\"/>".format(xml_escape(task_id)))
    if err or status != "202":
        return "start_task failed (status {}: {})".format(status, status_text if status_text else err)
    report_id = ""
    rep = root.find("report_id")
    if rep != None:
        report_id = rep.text
    print("greenbone-scan: started task {} (target {}, report {})".format(task_id, target_id, report_id))
    return None

# -------------------------
# Entry point
# -------------------------
def main(*args, **kwargs):
    require(kwargs, "runzero_url", "runzero_export_token", "gmp_username", "gmp_password")

    addresses, err = fetch_target_addresses(kwargs)
    if err:
        print("failed to fetch runZero targets:", err)
        return None
    # Nothing to scan: stop before connecting to Greenbone and say why.
    if not addresses:
        search = get_string(kwargs, "export_filter", default="")
        if search:
            print("greenbone-scan: 0 assets matched export filter '{}'; nothing to scan, no Greenbone target created".format(search))
        else:
            print("greenbone-scan: runZero export returned 0 assets; nothing to scan, no Greenbone target created")
        return None
    print("greenbone-scan: {} target address(es) selected".format(len(addresses)))

    state, err = gmp_connect(kwargs)
    if err:
        print("connection failed:", err)
        return None
    if state == None:
        print("connection failed")
        return None
    conn = state["conn"]

    err = gmp_authenticate(conn, get_string(kwargs, "gmp_username"), get_string(kwargs, "gmp_password"))
    if err:
        print(err)
        gmp_close(state)
        return None

    err = create_scan(conn, addresses, kwargs)
    if err:
        print("greenbone-scan:", err)

    gmp_close(state)
    return None
