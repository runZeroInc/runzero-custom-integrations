# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-scan-passive-assets",
    "name": "Scan Passive Assets",
    "type": "internal",
    "description": "Schedules scans against passively-observed assets.",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
    "params": [
        {
            "key": "url",
            "label": "runZero URL",
            "type": "url",
            "required": True,
            "default": "https://console.runzero.com",
        },
        {
            "key": "site_id",
            "label": "Target site ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "org_api_token",
            "label": "runZero org API token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('requests', 'Session')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', 'url_encode')
load('kwargs', 'get_url_base', 'get_bool')

# -------------------------
# Global Configuration
# -------------------------
DELETE_ASSETS = True
ALLOW_LIST = ["10.0.0.0/8", "192.168.0.0/16"]

# -------------------------
# IP Filtering Functions
# -------------------------
def ip_to_int(ip):
    parts = ip.split('.')
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def cidr_to_netmask(bits):
    return ~((1 << (32 - bits)) - 1) & 0xFFFFFFFF

def ip_in_cidr(ip_str, cidr):
    ip_int = ip_to_int(ip_str)
    base, mask_bits = cidr.split('/')
    base_int = ip_to_int(base)
    mask = cidr_to_netmask(int(mask_bits))
    return (ip_int & mask) == (base_int & mask)

def is_ip_allowed(ip_str, allow_list):
    ip_obj = ip_address(ip_str)
    if ip_obj.version != 4:
        return False
    for cidr in allow_list:
        if ip_in_cidr(ip_str, cidr):
            return True
    return False

# -------------------------
# Entrypoint
# -------------------------
def main(*args, **kwargs):
    base_url = get_url_base(kwargs)
    site_id = kwargs["site_id"]
    org_token = kwargs["org_api_token"]
    insecure_allowed = get_bool(kwargs, "tls_disable_validation", False)

    session = Session(insecure_skip_verify=insecure_allowed)
    session.headers.set("Authorization", "Bearer {}".format(org_token))
    session.headers.set("Content-Type", "application/json")
    if kwargs.get("http_user_agent"):
        session.headers.set("User-Agent", kwargs.get("http_user_agent"))

    # Step 1: Export assets
    params = {"search": "source:sample source_count:1", "fields": "id,addresses,last_agent_id"}
    asset_url = base_url + "/api/v1.0/export/org/assets.json?{}".format(url_encode(params))
    response = session.get(asset_url, timeout=3600)

    if not response or response.status_code != 200:
        print("Failed to fetch assets")
        return []

    data = json_decode(response.body)

    # Step 2: Filter assets and group IPs by agent
    agent_ip_map = {}  # {agent_id: [ip, ip, ...]}
    asset_ids = []

    for asset in data:
        agent_id = asset.get("last_agent_id")
        if not agent_id:
            continue
        for ip in asset.get("addresses", []):
            print("Evaluating IP: {}".format(ip))
            if is_ip_allowed(ip, ALLOW_LIST):
                if not agent_ip_map.get(agent_id):
                    agent_ip_map[agent_id] = []
                agent_ip_map[agent_id].append(ip)
                if asset["id"] not in asset_ids: 
                    asset_ids.append(asset["id"])


    # Step 3: Create scan task per explorer/agent
    for agent_id, ips in agent_ip_map.items():
        scan_url = base_url + "/api/v1.0/org/sites/{}/scan".format(site_id)
        scan_payload = {
            "targets": "\n".join(ips),
            "scan-name": "Auto Scan Sample Only Assets",
            "scan-description": "This scan was automatically created to scan assets discovered by the 'sample' source only.",
            "scan-frequency": "once",
            "scan-start": "0",
            "scan-tags": "type=AUTOMATED",
            "scan-grace-period": "0",
            "agent": agent_id,
            "rate": "1000",
            "max-host-rate": "20",
            "passes": "3",
            "max-attempts": "3",
            "max-sockets": "500",
            "max-group-size": "4096",
            "max-ttl": "255",
            "screenshots": "true",
        }
        print(scan_payload)
        post = session.put(scan_url, json=scan_payload)
        if post and post.status_code == 200:
            print("Scan created for agent {}".format(agent_id))
        else:
            print("Scan failed for agent {}".format(agent_id))

    # Step 4: Optional asset deletion
    if DELETE_ASSETS and len(asset_ids) > 0:
        delete_url = base_url + "/api/v1.0/org/assets/bulk/delete"
        delete_payload = {"asset_ids": asset_ids}
        del_resp = session.post(delete_url, json=delete_payload)
        if del_resp and del_resp.status_code == 204:
            print("Deleted {} assets".format(len(asset_ids)))
        else:
            print("Asset deletion {} failed".format(del_resp.body))

    return []
