CONFIG = {
    "id": "runzero-exe-dev",
    "name": "exe.dev",
    "type": "inbound",
    "description": "Imports exe.dev virtual machines as runZero assets.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "url",
            "label": "exe.dev API URL",
            "type": "url",
            "required": False,
            "default": "https://exe.dev/exec",
            "placeholder": "https://exe.dev/exec",
            "description": "exe.dev's API endpoint. Override only for a regional or self-hosted deployment.",
        },
        {
            "key": "api_token",
            "label": "API token",
            "type": "secret",
            "required": True,
            "description": "Minimal-scope exe.dev token (exe1.…). See README for generation steps.",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}

load("runzero.types", "ImportAsset")
load("json", json_decode="decode")
load("http", "bearer", http_post="post")
load("kwargs", "get_string", "get_http_options")

# Used when the url parameter is unset. The endpoint stays configurable rather
# than compiled in, so a regional or self-hosted deployment can be reached
# without editing the script.
DEFAULT_EXE_DEV_API_URL = "https://exe.dev/exec"

# Every record 'ls' returns is an exe.dev virtual machine -- a hosted Linux host
# reached over SSH and published over HTTPS -- and the collection holds nothing
# else, so the role comes from the resource itself rather than being guessed
# from a name, a tag, or an attached integration. runZero types the equivalent
# cloud compute instances the same way.
VM_DEVICE_TYPE = "Server"


def _log(msg):
    print("exe-dev: " + msg)


def parse_hostname_from_url(url_str):
    if url_str == None or url_str == "":
        return ""
    host = url_str
    if host.startswith("https://"):
        host = host[8:]
    elif host.startswith("http://"):
        host = host[7:]
    if "/" in host:
        host = host.split("/")[0]
    if ":" in host:
        host = host.split(":")[0]
    return host


def run_exe_command(api_url, http_options, command):
    resp = http_post(api_url, body=bytes(command), **http_options)

    if resp == None:
        _log("no response from the API for command: " + command)
        return None
    if resp.status_code == 401:
        _log("unauthorized (401); check the API token")
        return None
    if resp.status_code == 403:
        _log("forbidden (403); the token lacks permission for: " + command)
        return None
    if resp.status_code == 429:
        _log("rate limited (429)")
        return None
    if resp.status_code != 200:
        _log("unexpected status " + str(resp.status_code) + " for: " + command)
        return None
    if resp.body == None:
        return None

    return json_decode(resp.body)


def fetch_custom_domains_map(api_url, http_options):
    """Returns dict vm_name -> [hostname, ...] for all custom domains.

    Requires 'domain ls' in token cmds. Degrades gracefully on 403.
    """
    domain_map = {}
    data = run_exe_command(api_url, http_options, "domain ls -a")
    if data == None:
        _log("custom domain enrichment unavailable; the token may lack the 'domain ls' permission")
        return domain_map
    for d in data.get("domains", []):
        vm_name = d.get("vm_name", "")
        domain_name = d.get("domain", "")
        if vm_name == "" or domain_name == "":
            continue
        host = parse_hostname_from_url(domain_name)
        if host == "":
            continue
        if vm_name not in domain_map:
            domain_map[vm_name] = []
        domain_map[vm_name].append(host)
    _log("retrieved " + str(len(domain_map)) + " VMs with custom domains")
    return domain_map


def fetch_share_map(api_url, http_options, vm_names):
    """Returns dict vm_name -> share info (public, email_enabled, port).

    Calls 'share show <vm>' per VM. Requires 'share show' in token cmds.
    Degrades gracefully on 403.
    """
    share_map = {}
    for vm_name in vm_names:
        data = run_exe_command(api_url, http_options, "share show " + vm_name)
        if data == None:
            _log("share enrichment unavailable; the token may lack the 'share show' permission")
            return share_map
        share_map[vm_name] = {
            "public": str(data.get("public", False)),
            "email_enabled": str(data.get("email_enabled", False)),
            "port": str(data.get("port", "")),
        }
    _log("retrieved share config for " + str(len(share_map)) + " VMs")
    return share_map


def fetch_integrations_map(api_url, http_options, vm_names, vm_tags_by_name):
    """Returns dict vm_name -> [integration, ...] for every attached integration.

    Resolves all three attachment patterns:
      vm:<name>   — attached to a specific VM
      tag:<tag>   — attached to all VMs carrying that tag
      auto:all    — attached to all VMs

    Requires 'integrations list' in token cmds. Degrades gracefully on 403.
    """
    result = {}
    for name in vm_names:
        result[name] = []

    data = run_exe_command(api_url, http_options, "integrations list")
    if data == None:
        _log("integration enrichment unavailable; the token may lack the 'integrations list' permission")
        return result

    total = 0
    for integration in data.get("integrations", []):
        for spec in integration.get("attached", []):
            if spec == "auto:all":
                for name in vm_names:
                    result[name].append(integration)
                    total += 1
            elif spec.startswith("vm:"):
                vm_name = spec[3:]
                if vm_name in result:
                    result[vm_name].append(integration)
                    total += 1
            elif spec.startswith("tag:"):
                tag = spec[4:]
                for name in vm_names:
                    if tag in vm_tags_by_name.get(name, []):
                        result[name].append(integration)
                        total += 1

    _log("mapped " + str(total) + " integration attachments across " + str(len(vm_names)) + " VMs")
    return result


def _summarise_integrations(integrations):
    """Derives attributes and tags from the list of integrations attached to one VM.

    Returns a dict with:
      attrs — custom attribute key/value pairs
      tags  — additional runZero tags to apply
    """
    names = []
    types = []
    github_repos = []
    http_targets = []
    extra_tags = []
    has_shelley = False

    for i in integrations:
        name  = i.get("name", "")
        itype = i.get("type", "")

        if name != "" and name not in names:
            names.append(name)
        if itype != "" and itype not in types:
            types.append(itype)

        if itype == "github":
            repo = i.get("repository", "")
            if repo != "" and repo not in github_repos:
                github_repos.append(repo)
            if "integration:github" not in extra_tags:
                extra_tags.append("integration:github")

        elif itype == "http-proxy":
            target = parse_hostname_from_url(i.get("target", ""))
            if target != "" and target not in http_targets:
                http_targets.append(target)
            if "integration:http-proxy" not in extra_tags:
                extra_tags.append("integration:http-proxy")

        elif itype == "shelley":
            has_shelley = True
            if "agent:shelley" not in extra_tags:
                extra_tags.append("agent:shelley")

    return {
        "attrs": {
            "exe_dev_integrations":        ", ".join(names),
            "exe_dev_integration_types":   ", ".join(types),
            "exe_dev_github_repos":        ", ".join(github_repos),
            "exe_dev_http_proxy_targets":  ", ".join(http_targets),
            "exe_dev_shelley":             str(has_shelley),
        },
        "tags": extra_tags,
    }


def build_asset(vm, custom_domains_map, share_map, integrations_map):
    """Build a single ImportAsset from a VM record plus enrichment maps."""
    vm_name = vm.get("vm_name", "")
    if vm_name == "":
        # vm_name is the whole identity here -- it is what the id is built from
        # and what every enrichment map is keyed on -- so a record without one
        # cannot be imported at all. There is no second field to fall back to,
        # which is why main reports the drop; it tallies rather than logging per
        # record, so a broken export cannot flood the run log.
        return None

    ssh_dest       = vm.get("ssh_dest", "")
    https_url      = vm.get("https_url", "")
    status         = vm.get("status", "")
    region         = vm.get("region", "")
    region_display = vm.get("region_display", "")
    comment        = vm.get("comment", "")
    vm_tags        = vm.get("tags", [])
    # ls -l may expose shelley status directly; fall back to False
    shelley_direct = vm.get("shelley", False)

    # ── Hostnames ─────────────────────────────────────────────────────────
    hostnames = []
    url_host = parse_hostname_from_url(https_url)
    if url_host != "" and url_host not in hostnames:
        hostnames.append(url_host)
    if ssh_dest != "" and ssh_dest not in hostnames:
        hostnames.append(ssh_dest)
    for custom_domain in custom_domains_map.get(vm_name, []):
        if custom_domain not in hostnames:
            hostnames.append(custom_domain)
    if vm_name not in hostnames:
        hostnames.append(vm_name)

    # ── Share / proxy ─────────────────────────────────────────────────────
    share = share_map.get(vm_name, {})

    # ── Integration summary ───────────────────────────────────────────────
    int_summary = _summarise_integrations(integrations_map.get(vm_name, []))

    # Shelley: detected via ls -l field OR integration type
    shelley = str(shelley_direct or int_summary["attrs"]["exe_dev_shelley"] == "True")

    # ── Tags ──────────────────────────────────────────────────────────────
    tags = ["exe.dev"]
    if status != "":
        tags.append("status:" + status)
    if region != "":
        tags.append("region:" + region)
    if share.get("public") == "True":
        tags.append("proxy:public")
    for t in vm_tags:
        tag_val = "tag:" + t
        if tag_val not in tags:
            tags.append(tag_val)
    for t in int_summary["tags"]:
        if t not in tags:
            tags.append(t)

    # ── Attributes ────────────────────────────────────────────────────────
    attrs = {
        "exe_dev_vm_name":           vm_name,
        "exe_dev_status":            status,
        "exe_dev_region":            region,
        "exe_dev_region_display":    region_display,
        "exe_dev_https_url":         https_url,
        "exe_dev_ssh_dest":          ssh_dest,
        "exe_dev_comment":           comment,
        "exe_dev_tags":              ", ".join(vm_tags),
        "exe_dev_custom_domains":    ", ".join(custom_domains_map.get(vm_name, [])),
        "exe_dev_proxy_public":      share.get("public", ""),
        "exe_dev_proxy_port":        share.get("port", ""),
        "exe_dev_email_enabled":     share.get("email_enabled", ""),
        "exe_dev_shelley":           shelley,
    }
    for k, v in int_summary["attrs"].items():
        attrs[k] = v
    # Reassert after merge: shelley=True if detected via ls -l OR integration type
    attrs["exe_dev_shelley"] = shelley

    return ImportAsset(
        id="exedev-" + vm_name,
        hostnames=hostnames,
        os="Linux",
        deviceType=VM_DEVICE_TYPE,
        tags=tags,
        customAttributes=attrs,
    )


def main(**kwargs):
        # The platform applies the CONFIG default, but fall back explicitly so the
    # script still works if it is invoked without one.
    base_url = (kwargs.get("url") or DEFAULT_EXE_DEV_API_URL).rstrip("/")

    token = get_string(kwargs, "api_token")
    if token == "":
        _log("api_token is required")
        return None

    http_options = get_http_options(kwargs, headers={
        "Authorization": bearer(token),
        "Content-Type": "text/plain",
    })

    # Use -l for detailed listing: tags, comment, and shelley status
    vms_data = run_exe_command(base_url, http_options, "ls -l")
    if vms_data == None:
        _log("no VM data retrieved")
        return None

    vms = vms_data.get("vms", [])
    _log("retrieved " + str(len(vms)) + " VMs")

    # Build lookup structures needed for integration resolution
    vm_names = [vm.get("vm_name", "") for vm in vms if vm.get("vm_name", "") != ""]
    vm_tags_by_name = {}
    for vm in vms:
        name = vm.get("vm_name", "")
        if name != "":
            vm_tags_by_name[name] = vm.get("tags", [])

    custom_domains_map = fetch_custom_domains_map(base_url, http_options)
    share_map          = fetch_share_map(base_url, http_options, vm_names)
    integrations_map   = fetch_integrations_map(base_url, http_options, vm_names, vm_tags_by_name)

    assets = []
    skipped = 0
    skipped_status = ""
    for vm in vms:
        asset = build_asset(vm, custom_domains_map, share_map, integrations_map)
        if asset == None:
            # One example carries the diagnosis; the rest are a count, so a
            # broken export does not turn into one log line per record.
            skipped += 1
            if skipped == 1:
                skipped_status = str(vm.get("status", ""))
            continue
        assets.append(asset)

    if skipped > 0:
        _log("skipped {} VMs with no vm_name (first status: {})".format(
            skipped, skipped_status))

    if assets:
        report_assets(assets)

    _log("reported " + str(len(assets)) + " assets")
    return None
