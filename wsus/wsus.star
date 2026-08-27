# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-wsus",
    "name": "Microsoft WSUS",
    "type": "inbound",
    "description": "Imports computer targets and their missing-update status from a Microsoft WSUS server over WinRM.",
    "version": "1",
    "maturity": "alpha",
    "minVersion": "5.1.260818.0",
    # ComputerTargetId is a GUID WSUS mints from the client's SusClientId, so it
    # is one-per-row in SUSDB and survives renames, re-addressing, and OS
    # upgrades. The addressing WSUS reports alongside it is self-reported by the
    # client and drifts (DHCP, VPN adapters), so it must not veto an id merge.
    # No MAC is ever emitted; the flag is declared anyway so the policy reads
    # complete.
    "matchBehavior": "no-mac-break no-ip-break no-name-break",
    "validationMode": "compile",
    "params": [
        {
            "key": "host",
            "label": "WSUS server host",
            "type": "string",
            "required": True,
            "description": "Hostname or IP of the WSUS server. The WSUS administration API has no remote HTTP interface, so the collection script runs on this server over WinRM.",
        },
        {
            "key": "username",
            "label": "Username",
            "type": "string",
            "required": True,
            "description": "DOMAIN\\\\user, user@domain, or local account with WSUS administration rights (member of WSUS Administrators or local Administrators on the server).",
        },
        {
            "key": "password",
            "label": "Password",
            "type": "secret",
            "required": True,
        },
        {
            "key": "winrm_https",
            "label": "WinRM over HTTPS",
            "type": "bool",
            "default": False,
            "description": "Connect to WinRM on 5986 with TLS instead of 5985.",
        },
        {
            "key": "winrm_port",
            "label": "WinRM port",
            "type": "int",
            "min": 0,
            "max": 65535,
            "default": 0,
            "description": "0 selects the default for the transport: 5985 for HTTP, 5986 for HTTPS.",
        },
        {
            "key": "winrm_auth",
            "label": "WinRM authentication",
            "type": "enum",
            "options": ["ntlm", "basic"],
            "default": "ntlm",
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
            "description": "CA certificate(s) that sign the WinRM listener's certificate, when HTTPS is used with a private CA.",
        },
        {
            "key": "wsus_port",
            "label": "WSUS administration port",
            "type": "int",
            "min": 0,
            "max": 65535,
            "default": 0,
            "description": "0 connects the on-server API with its own defaults. Set 8531 together with WSUS SSL for an SSL-only WSUS.",
        },
        {
            "key": "wsus_ssl",
            "label": "WSUS uses SSL",
            "type": "bool",
            "default": False,
            "description": "Set when the WSUS administration console itself requires SSL (port 8531).",
        },
        {
            "key": "include_downstream",
            "label": "Include downstream computers",
            "type": "bool",
            "default": True,
            "description": "Include computers rolled up from downstream WSUS servers in a hierarchy.",
        },
        {
            "key": "name_includes",
            "label": "Computer name filter",
            "type": "string",
            "required": False,
            "description": "Only import computers whose full domain name contains this substring. Letters, digits, dots, dashes, and underscores only.",
        },
        {
            "key": "import_missing_updates",
            "label": "Import missing updates as vulnerabilities",
            "type": "bool",
            "default": True,
            "description": "Emit one vulnerability per update a computer reports as not installed or failed.",
        },
        {
            "key": "security_only",
            "label": "Security classifications only",
            "type": "bool",
            "default": True,
            "description": "Restrict imported missing updates to the Security Updates and Critical Updates classifications.",
        },
        {
            "key": "max_updates_per_computer",
            "label": "Missing updates per computer",
            "type": "int",
            "min": 1,
            "max": 99,
            "default": 99,
            "description": "Cap on missing updates imported per computer. The total missing count is always recorded as an attribute.",
        },
        {
            "key": "page_size",
            "label": "Computers per WinRM call",
            "type": "int",
            "min": 1,
            "max": 2000,
            "default": 100,
            "description": "How many computers each remote PowerShell invocation collects. Lower this if a call times out or its output is truncated. Each invocation is a fresh process that re-reads the full computer list on the server before slicing its page, so on a very large WSUS prefer the largest value that stays under the timeout to keep the invocation count down.",
        },
        {
            "key": "timeout",
            "label": "WinRM call timeout (seconds)",
            "type": "int",
            "min": 30,
            "max": 600,
            "default": 300,
        },
    ],
}

load("runzero.types", "ImportAsset", "Software", "Vulnerability")
load("runzero.winrm", winrm_dial="dial")
load("kwargs", "require", "get_string", "get_int", "get_bool")
load("net", "network_interface", "routable_ip", "clean_hostname")
load("json", json_decode="decode")
load("time", "parse_ts")
load("re", re_sub="sub")
load("runzero.progress", progress_report="report")

# Launcher passed as the WinRM command line. The collection script itself
# arrives on stdin, because run_powershell delivers its script through
# -EncodedCommand and WinRM caps that command line at roughly 8K characters --
# far too small for the script below. Reading stdin to EOF has no such limit.
PS_LAUNCHER = ("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass " +
               "-Command \"$ProgressPreference='SilentlyContinue';" +
               "Invoke-Expression ([Console]::In.ReadToEnd())\"")

# Each record line the remote script prints ends with this marker before the
# newline. WinRM output is capped at 16 MiB per stream and truncated silently,
# so a line is only decoded once the marker proves it arrived whole; without
# this, a JSON object cut just after a nested closing brace could abort the
# run inside json_decode.
LINE_MARKER = "\t//rz"

# MSRC severity strings as WSUS reports them, mapped to runZero severity ranks
# (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical). "Unspecified" and empty are
# deliberately absent so non-security updates carry no invented severity.
MSRC_SEVERITY_RANKS = {
    "critical": 4,
    "important": 3,
    "moderate": 2,
    "low": 1,
}

# The remote collection script, parameterized by token replacement rather than
# .format because PowerShell hashtable syntax is full of braces. It prints one
# meta line first, then one line per computer, each line terminated by the
# marker above, and one rz_error line on any failure. Values that can be null
# on a computer that never reported are read through [string] casts, which
# yield '' instead of raising. Update metadata is cached per call so a KB
# missing from a thousand computers is fetched once, not a thousand times.
PS_COLLECT = """
$ErrorActionPreference = 'Stop'
function Emit([hashtable]$obj) {
  $line = ($obj | ConvertTo-Json -Depth 6 -Compress)
  [Console]::Out.WriteLine($line + "\t//rz")
}
function Stamp($t) {
  if ($null -eq $t) { return '' }
  $s = $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  if ($s.StartsWith('0001-')) { return '' }
  return $s
}
try {
  [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')
  $wsusPort = __WSUS_PORT__
  $wsusSsl = $__WSUS_SSL__
  if ($wsusPort -gt 0) {
    $srv = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer('localhost', $wsusSsl, $wsusPort)
  } else {
    $srv = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
  }
  $cs = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
  $cs.IncludeDownstreamComputerTargets = $__DOWNSTREAM__
  $nameFilter = '__NAME_INCLUDES__'
  if ($nameFilter -ne '') { $cs.NameIncludes = $nameFilter }
  $all = @($srv.GetComputerTargets($cs) | Sort-Object -Property Id)
  $total = $all.Count
  $offset = __OFFSET__
  $count = __COUNT__
  Emit @{ rz_meta = 1; total = $total; offset = $offset }
  if ($offset -lt $total) {
    $last = [Math]::Min($offset + $count, $total) - 1
    $page = $all[$offset..$last]
    $wantUpdates = $__WANT_UPDATES__
    $securityOnly = $__SECURITY_ONLY__
    $maxUpdates = __MAX_UPDATES__
    $us = New-Object Microsoft.UpdateServices.Administration.UpdateScope
    $us.IncludedInstallationStates =
      [Microsoft.UpdateServices.Administration.UpdateInstallationStates]::NotInstalled -bor
      [Microsoft.UpdateServices.Administration.UpdateInstallationStates]::Failed
    $updCache = @{}
    foreach ($c in $page) {
      $sum = $c.GetUpdateInstallationSummary()
      $missing = @()
      if ($wantUpdates) {
        foreach ($info in @($c.GetUpdateInstallationInfoPerUpdate($us))) {
          $uid = $info.UpdateId.ToString()
          if (-not $updCache.ContainsKey($uid)) {
            $u = $info.GetUpdate()
            $updCache[$uid] = @{
              title = [string]$u.Title
              kb = @($u.KnowledgebaseArticles)
              bulletins = @($u.SecurityBulletins)
              severity = [string]$u.MsrcSeverity
              classification = [string]$u.UpdateClassificationTitle
              declined = [bool]$u.IsDeclined
            }
          }
          $meta = $updCache[$uid]
          if ($meta.declined) { continue }
          if ($securityOnly -and
              $meta.classification -ne 'Security Updates' -and
              $meta.classification -ne 'Critical Updates') { continue }
          if ($missing.Count -ge $maxUpdates) { continue }
          $missing += @{
            update_id = $uid
            title = $meta.title
            kb = $meta.kb
            bulletins = $meta.bulletins
            severity = $meta.severity
            classification = $meta.classification
            state = $info.UpdateInstallationState.ToString()
          }
        }
      }
      $osver = ''
      if ($c.OSInfo -and $c.OSInfo.Version) {
        $v = $c.OSInfo.Version
        $osver = ('{0}.{1}.{2}' -f $v.Major, $v.Minor, $v.Build)
      }
      Emit @{
        rz_computer = 1
        id = [string]$c.Id
        fqdn = [string]$c.FullDomainName
        ip = [string]$c.IPAddress
        os = [string]$c.OSDescription
        os_version = $osver
        os_arch = [string]$c.OSArchitecture
        client_version = [string]$c.ClientVersion
        make = [string]$c.Make
        model = [string]$c.Model
        bios_version = [string]$c.BiosInfo.Version
        role = [string]$c.ComputerRole
        last_sync = Stamp $c.LastSyncTime
        last_reported = Stamp $c.LastReportedStatusTime
        not_installed = $sum.NotInstalledCount
        downloaded = $sum.DownloadedCount
        failed = $sum.FailedCount
        installed = $sum.InstalledCount
        pending_reboot = $sum.InstalledPendingRebootCount
        unknown = $sum.UnknownCount
        missing_updates = $missing
      }
    }
  }
} catch {
  Emit @{ rz_error = $_.Exception.Message }
}
"""


def sanitize_name_filter(value):
    """Restrict the NameIncludes filter to characters that cannot escape the
    single-quoted PowerShell string it is substituted into."""
    return re_sub(r"[^A-Za-z0-9._ -]", "", value)


def render_script(offset, count, wsus_port, wsus_ssl, downstream, name_includes,
                  want_updates, security_only, max_updates):
    """Substitute one page's parameters into the collection script."""
    def ps_bool(b):
        return "true" if b else "false"

    script = PS_COLLECT
    script = script.replace("__OFFSET__", str(offset))
    script = script.replace("__COUNT__", str(count))
    script = script.replace("__WSUS_PORT__", str(wsus_port))
    script = script.replace("__WSUS_SSL__", ps_bool(wsus_ssl))
    script = script.replace("__DOWNSTREAM__", ps_bool(downstream))
    script = script.replace("__NAME_INCLUDES__", sanitize_name_filter(name_includes))
    script = script.replace("__WANT_UPDATES__", ps_bool(want_updates))
    script = script.replace("__SECURITY_ONLY__", ps_bool(security_only))
    script = script.replace("__MAX_UPDATES__", str(max_updates))
    return script


def parse_page(stdout):
    """Decode one call's output into (meta, computers, error, truncated).

    Only lines carrying the end marker are decoded; anything after the last
    complete line is the truncation tail the WinRM output cap leaves behind.
    """
    meta = None
    computers = []
    error = ""
    truncated = False
    for line in stdout.split("\n"):
        line = line.strip("\r").strip()
        if not line:
            continue
        if not line.endswith(LINE_MARKER):
            truncated = True
            continue
        line = line[:-len(LINE_MARKER)]
        if not line.startswith("{") or not line.endswith("}"):
            truncated = True
            continue
        record = json_decode(line)
        if type(record) != "dict":
            continue
        if record.get("rz_error"):
            error = str(record.get("rz_error"))
        elif record.get("rz_meta"):
            meta = record
        elif record.get("rz_computer"):
            computers.append(record)
    return meta, computers, error, truncated


def build_interfaces(ip):
    """Return the interface list for the client's one self-reported address.

    routable_ip drops loopback, link-local, multicast, unspecified, and
    broadcast values, which covers the 255.255.255.255 a client that has never
    reported renders as (IPAddress.None).
    """
    ip = routable_ip(str(ip or ""))
    if not ip:
        return []
    nic = network_interface(mac=None, ips=[ip])
    return [nic] if nic else []


def build_vulnerabilities(record):
    """Convert one computer's missing-update list into Vulnerability objects."""
    vulns = []
    for upd in record.get("missing_updates", []) or []:
        if type(upd) != "dict":
            continue
        update_id = str(upd.get("update_id", "") or "")
        title = str(upd.get("title", "") or "")
        if not update_id and not title:
            continue
        kbs = [str(k) for k in upd.get("kb", []) or [] if k]
        bulletins = [str(b) for b in upd.get("bulletins", []) or [] if b]
        classification = str(upd.get("classification", "") or "")
        state = str(upd.get("state", "") or "")

        fallback_name = ("KB" + kbs[0]) if kbs else update_id
        vuln_args = {
            "id": "wsus-update:" + (update_id or title[:200]),
            "name": title[:256] or fallback_name,
            "description": title,
            "customAttributes": {
                "kb": ",".join(kbs),
                "securityBulletins": ",".join(bulletins),
                "classification": classification,
                "installationState": state,
            },
        }
        if kbs:
            vuln_args["solution"] = "Install the update described in Microsoft KB" + kbs[0]
        elif title:
            vuln_args["solution"] = "Install the update: " + title[:200]
        rank = MSRC_SEVERITY_RANKS.get(str(upd.get("severity", "") or "").lower())
        if rank != None:
            vuln_args["severityRank"] = rank
        vulns.append(Vulnerability(**vuln_args))
    return vulns


def build_asset(record, namespace, import_updates):
    """Build one ImportAsset from a WSUS computer target record."""
    target_id = str(record.get("id", "") or "")
    if not target_id:
        print("wsus: skipping computer with no target id: name=" + str(record.get("fqdn", "")))
        return None

    hostnames = []
    fqdn = clean_hostname(record.get("fqdn"))
    if fqdn:
        hostnames.append(fqdn)

    attrs = {
        "computerTargetId": target_id,
        "osArchitecture": str(record.get("os_arch", "") or ""),
        "clientVersion": str(record.get("client_version", "") or ""),
        "make": str(record.get("make", "") or ""),
        "model": str(record.get("model", "") or ""),
        "biosVersion": str(record.get("bios_version", "") or ""),
        "computerRole": str(record.get("role", "") or ""),
        "lastSyncTime": str(record.get("last_sync", "") or ""),
        "lastReportedStatusTime": str(record.get("last_reported", "") or ""),
        "updatesNotInstalled": str(record.get("not_installed", "")),
        "updatesDownloaded": str(record.get("downloaded", "")),
        "updatesFailed": str(record.get("failed", "")),
        "updatesInstalled": str(record.get("installed", "")),
        "updatesPendingReboot": str(record.get("pending_reboot", "")),
        "updatesUnknown": str(record.get("unknown", "")),
        "reportedIP": str(record.get("ip", "") or ""),
    }
    attrs = {k: v for k, v in attrs.items() if v}

    software = []
    client_version = str(record.get("client_version", "") or "")
    if client_version:
        software.append(Software(
            id="windows-update-agent",
            vendor="Microsoft",
            product="Windows Update Agent",
            version=client_version,
        ))

    asset_args = {
        "id": "wsus:{}:{}".format(namespace, target_id),
        "hostnames": hostnames,
        "networkInterfaces": build_interfaces(record.get("ip")),
        "os": str(record.get("os", "") or ""),
        "osVersion": str(record.get("os_version", "") or ""),
        "customAttributes": attrs,
        "software": software,
    }

    if import_updates:
        asset_args["vulnerabilities"] = build_vulnerabilities(record)

    # Only the unambiguous server signal sets a type; a WSUS "Workstation" can
    # be a desktop or a laptop and the record cannot say which.
    role = str(record.get("role", "") or "").lower()
    os_name = str(record.get("os", "") or "").lower()
    if role == "server" or "server" in os_name:
        asset_args["deviceType"] = "Server"

    asset = ImportAsset(**asset_args)
    last_seen = parse_ts(record.get("last_reported")) or parse_ts(record.get("last_sync"))
    if last_seen != None:
        asset.lastSeenTS = last_seen
    return asset


def main(**kwargs):
    require(kwargs, "host", "username", "password")
    host = get_string(kwargs, "host")
    username = get_string(kwargs, "username")
    password = get_string(kwargs, "password")
    https = get_bool(kwargs, "winrm_https", default=False)
    port = get_int(kwargs, "winrm_port", default=0)
    auth = get_string(kwargs, "winrm_auth", default="ntlm")
    insecure = get_bool(kwargs, "winrm_insecure", default=False)
    ca_cert = get_string(kwargs, "winrm_ca_cert", default="") or None
    wsus_port = get_int(kwargs, "wsus_port", default=0)
    wsus_ssl = get_bool(kwargs, "wsus_ssl", default=False)
    downstream = get_bool(kwargs, "include_downstream", default=True)
    name_includes = get_string(kwargs, "name_includes", default="")
    import_updates = get_bool(kwargs, "import_missing_updates", default=True)
    security_only = get_bool(kwargs, "security_only", default=True)
    max_updates = get_int(kwargs, "max_updates_per_computer", default=99)
    if max_updates < 1 or max_updates > 99:
        max_updates = 99
    page_size = get_int(kwargs, "page_size", default=100)
    if page_size < 1:
        page_size = 100
    timeout = get_int(kwargs, "timeout", default=300)

    namespace = host.lower()
    session = winrm_dial(
        host=host,
        username=username,
        password=password,
        port=port,
        https=https,
        insecure_skip_verify=insecure,
        ca_cert=ca_cert,
        auth=auth,
        timeout=timeout,
    )

    reported = 0
    offset = 0
    total = None
    # Set when the remote collection stops on an error rather than on its own
    # terms. The computers already streamed are kept and still summarised; the
    # task then ends in error, because a truncated read is not a smaller estate.
    walk_err = None
    p = pager("wsus-computers")
    while p.next():
        script = render_script(offset, page_size, wsus_port, wsus_ssl, downstream,
                               name_includes, import_updates, security_only, max_updates)
        stdout, stderr, exit_code = session.run(PS_LAUNCHER, stdin=script)
        if exit_code != 0:
            walk_err = "remote collection failed with exit code {}: {}".format(
                exit_code, stderr[:500])
            break

        meta, computers, error, truncated = parse_page(stdout)
        if error:
            walk_err = "remote collection error: {}".format(error[:500])
            break
        if meta == None:
            walk_err = "remote output carried no meta line; stderr: {}".format(stderr[:500])
            break
        if total == None:
            total = meta.get("total", 0)
            if type(total) != "int":
                total = 0
            print("wsus: server reports {} computer targets".format(total))

        for record in computers:
            reported += report_asset(build_asset(record, namespace, import_updates))

        if truncated and not computers:
            # Even a single computer overran the 16 MiB output cap, which no
            # smaller page can fix.
            print("wsus: output truncated with no complete records at offset {}; aborting".format(offset))
            break

        offset += len(computers)
        if truncated:
            # The cap cut this page short. Every complete record before the cut
            # was kept, so continue from where they ended with a smaller page.
            page_size = max(1, page_size // 2)
            print("wsus: output truncated; continuing at offset {} with page size {}".format(
                offset, page_size))
            continue
        if offset >= total or not computers:
            break
        if total > 0:
            progress_report(offset * 100 // total, "imported {}/{} computers".format(offset, total))

    session.close()
    print("wsus: reported {} assets".format(reported))
    if walk_err != None:
        fail("wsus: {}".format(walk_err))
    return None
