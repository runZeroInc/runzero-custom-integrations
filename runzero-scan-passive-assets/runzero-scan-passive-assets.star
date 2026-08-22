# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-scan-passive-assets",
    "name": "Scan Passive Assets",
    "type": "internal",
    "description": "Schedules scans against passively-observed assets.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
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
        {
            "key": "scan_wait_seconds",
            "label": "Seconds to wait for each scan to finish",
            "type": "int",
            "required": False,
            "default": 1800,
            "min": 0,
            "max": 86400,
            "description": "Passive assets are deleted only after the scan that supersedes them has completed. Set to 0 to queue the scans and never delete, making the cleanup a separate step.",
        },
        {
            "key": "scan_poll_seconds",
            "label": "Seconds between scan status checks",
            "type": "int",
            "required": False,
            "default": 15,
            "min": 1,
            "max": 3600,
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
load('kwargs', 'get_url_base', 'get_bool', 'get_int')
load('time', 'now', 'sleep')

# -------------------------
# Global Configuration
# -------------------------
DELETE_ASSETS = True
ALLOW_LIST = ["10.0.0.0/8", "192.168.0.0/16"]

# runZero task statuses, from models/task.go. The platform's own statusToCategory
# map (actions/tasks.go) is what these follow: `processed` and `completed` are
# the two it renders as completed, and `processed` is the one the cruncher sets
# once a scan's results have actually been ingested. Everything in FAILED is
# terminal but produced no scan data; anything in neither list is still running.
SCAN_SUCCEEDED_STATUSES = ["processed", "completed"]
SCAN_FAILED_STATUSES = ["error", "canceled", "cancelled", "stopped", "removed"]

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
# Scan completion
# -------------------------
def task_state(session, base_url, task_id):
    """One status check. Returns 'running', 'succeeded', or 'failed'.

    Anything unreadable answers 'running', never 'succeeded': the only thing
    this result is used for is whether an asset may be deleted, so an unknown
    status has to keep the asset rather than spend it.
    """
    response = session.get(base_url + "/api/v1.0/org/tasks/{}".format(task_id))
    if not response or response.status_code != 200:
        print("Could not read scan task {}: status {}".format(
            task_id, response.status_code if response else "no response"))
        return "running"
    # json_decode aborts the whole run on a body it cannot parse, and this one
    # arrives from an endpoint that answers HTML on some proxy errors.
    if not response.body or response.body[0:1] != "{":
        print("Scan task {} returned a non-JSON body".format(task_id))
        return "running"
    task = json_decode(response.body)
    if type(task) != "dict":
        print("Scan task {} returned an unexpected shape".format(task_id))
        return "running"
    status = task.get("status", "")
    if status in SCAN_SUCCEEDED_STATUSES:
        return "succeeded"
    if status in SCAN_FAILED_STATUSES:
        return "failed"
    return "running"

def wait_for_scans(session, base_url, task_agents, wait_seconds, poll_seconds):
    """Wait for the queued scans, bounded. Returns the agents whose scan finished.

    A queued scan is not a finished scan, and the passive assets are the only
    record that these hosts exist -- delete them on the strength of a `new` task
    and a host that is offline, unreachable, or whose scan errors is simply
    gone. So the delete waits here, and waits per Explorer: one Explorer's scan
    failing must not spend another Explorer's assets.
    """
    finished = []
    pending = [task_id for task_id in task_agents]
    started = now().unix
    while pending:
        still_pending = []
        for task_id in pending:
            state = task_state(session, base_url, task_id)
            if state == "succeeded":
                print("Scan task {} completed for agent {}".format(task_id, task_agents[task_id]))
                finished.append(task_agents[task_id])
            elif state == "failed":
                print("Scan task {} did not complete for agent {}; keeping its assets".format(
                    task_id, task_agents[task_id]))
            else:
                still_pending.append(task_id)
        pending = still_pending
        if not pending:
            break
        # Elapsed seconds rather than a deadline comparison: `.unix` is a plain
        # int, so this cannot be tripped up by time/duration arithmetic. The
        # check is after a round of polls, so wait_seconds=0 means "check once,
        # do not wait" rather than "skip the checks entirely".
        if now().unix - started >= wait_seconds:
            print("Gave up waiting for {} scan task(s) after {}s; keeping their assets for a later run".format(
                len(pending), wait_seconds))
            break
        sleep("{}s".format(poll_seconds))
    return finished

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
    # Asset ids are grouped by Explorer too, not kept in one flat list: an asset
    # may only be deleted once ITS scan has completed, and each Explorer's scan
    # completes (or fails) on its own.
    agent_asset_map = {}  # {agent_id: [asset_id, ...]}

    for asset in data:
        agent_id = asset.get("last_agent_id")
        if not agent_id:
            continue
        for ip in asset.get("addresses", []):
            print("Evaluating IP: {}".format(ip))
            if is_ip_allowed(ip, ALLOW_LIST):
                if not agent_ip_map.get(agent_id):
                    agent_ip_map[agent_id] = []
                    agent_asset_map[agent_id] = []
                agent_ip_map[agent_id].append(ip)
                if asset["id"] not in agent_asset_map[agent_id]:
                    agent_asset_map[agent_id].append(asset["id"])


    # Step 3: Create scan task per explorer/agent
    task_agents = {}  # {task_id: agent_id}
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
        post = session.put(scan_url, json=scan_payload)
        if post and post.status_code == 200:
            # The response is the task that was created, and its id is what the
            # completion check below is asked with. A scan whose id cannot be
            # read is still a queued scan -- it just cannot be followed, so its
            # assets are kept rather than deleted on faith.
            task_id = ""
            if post.body and post.body[0:1] == "{":
                task = json_decode(post.body)
                if type(task) == "dict":
                    task_id = task.get("id", "")
            if task_id:
                task_agents[task_id] = agent_id
                print("Scan created for agent {} as task {}".format(agent_id, task_id))
            else:
                print("Scan created for agent {} but the response carried no task id; its assets will be kept".format(agent_id))
        else:
            print("Scan failed for agent {}".format(agent_id))

    # Step 4: Optional asset deletion, and only for assets a FINISHED scan has
    # superseded. This used to fire the moment the scans were queued, which is
    # the one order that cannot be right: the passive record is the only
    # evidence the host exists, the scan that was supposed to replace it had not
    # run yet, and a host that was offline, unreachable, or whose scan errored
    # was simply erased. Waiting is what makes the delete a supersede rather
    # than a gamble.
    if not DELETE_ASSETS:
        print("DELETE_ASSETS is off; queued {} scan(s) and keeping every passive asset".format(len(task_agents)))
        return []

    if not task_agents:
        print("No scan task to follow; keeping every passive asset")
        return []

    completed_agents = wait_for_scans(
        session, base_url, task_agents,
        get_int(kwargs, "scan_wait_seconds", default=1800),
        get_int(kwargs, "scan_poll_seconds", default=15),
    )

    asset_ids = []
    for agent_id in completed_agents:
        for asset_id in agent_asset_map.get(agent_id, []):
            if asset_id not in asset_ids:
                asset_ids.append(asset_id)

    if len(asset_ids) > 0:
        delete_url = base_url + "/api/v1.0/org/assets/bulk/delete"
        delete_payload = {"asset_ids": asset_ids}
        del_resp = session.post(delete_url, json=delete_payload)
        if del_resp and del_resp.status_code == 204:
            print("Deleted {} assets".format(len(asset_ids)))
        else:
            print("Asset deletion failed for {} asset(s): status {}".format(
                len(asset_ids),
                del_resp.status_code if del_resp else "no response"))
    else:
        print("No scan completed in time; keeping every passive asset for a later run")

    return []
