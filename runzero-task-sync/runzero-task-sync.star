# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-task-sync",
    "name": "runZero Task Sync",
    # "internal", not "inbound". This script reports no assets: it copies task
    # data from one runZero instance into another through that instance's own
    # API, exactly as its peers runzero-scan-passive-assets and
    # runzero-vulnerability-workflow do, and both of those declare "internal".
    # An "inbound" integration is one whose main() yields ImportAssets for the
    # platform to merge, which this never does.
    "type": "internal",
    "description": "Mirrors tasks between two runZero instances (SaaS to self-hosted, etc.).",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "src_url",
            "label": "Source runZero URL",
            "type": "url",
            "required": False,
            "default": "https://console.runzero.com",
        },
        {
            "key": "src_org_id",
            "label": "Source org ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "src_task_search_filter",
            "label": "Source task search filter",
            "type": "string",
            "required": False,
            "default": "name:=\"test\"",
        },
        {
            "key": "dst_url",
            "label": "Destination runZero URL",
            "type": "url",
            "required": False,
            "default": "https://console.runzero.com",
        },
        {
            "key": "dst_org_id",
            "label": "Destination org ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "dst_site_id",
            "label": "Destination site ID",
            "type": "string",
            "required": True,
        },
        {
            "key": "hide_tasks_on_sync",
            "label": "Hide source tasks after sync",
            "type": "bool",
            "required": False,
            "default": False,
        },
        {
            "key": "src_api_token",
            "label": "Source API token",
            "type": "secret",
            "required": True,
            "description": "Account or org token for the source instance",
        },
        {
            "key": "dst_api_token",
            "label": "Destination API token",
            "type": "secret",
            "required": True,
            "description": "Account or org token for the destination instance",
        },
    ],
    "includes": {
        "src_tls_": OPTIONS_TLS,
        "dst_tls_": OPTIONS_TLS,
        "src_http_": OPTIONS_HTTP,
        "dst_http_": OPTIONS_HTTP,
    },
}
load('http', http_get='get', http_post='post', http_put='put', 'get_json', 'bearer', 'url_encode')
load('gzip', gzip_decompress='decompress', gzip_compress='compress')
load('kwargs', 'get_http_options', 'get_bool')

def get_tasks(src_url, src_org_id, src_task_search_filter, src_token, config_kwargs):
    params = {"_oid": src_org_id, "search": src_task_search_filter}
    url = "{}{}{}".format(src_url, "/api/v1.0/org/tasks?", url_encode(params))
    data, err = get_json(
        url,
        **get_http_options(config_kwargs, "src_http_", "src_tls_", {"Authorization": bearer(src_token)})
    )
    if err:
        # The task list IS the work list, so a failed read is the run and not a
        # source org with no matching tasks.
        fail("runzero-task-sync: failed to get tasks: {}".format(err))
    return data or []

def sync_task(task_id, src_token, dst_token, src_url, dst_url, src_org_id, dst_org_id, dst_site_id, hide_tasks_on_sync, config_kwargs):
    """Mirror one task. Returns "ok", "not_ready", or "failed".

    "not_ready" is kept apart from "failed" because the source search selects on
    name and type, never on status: a task still queued or running is listed and
    then 404s its data, which the next run picks up. Only a real failure is
    worth ending the task in error over.
    """
    # Download data from SaaS. The org id travels on this call too: with an
    # account-level token, the task list resolves against ?_oid= while a /data
    # call without it resolves against the token's default org and 404s, so
    # every task would print "Failed to download" and nothing would sync.
    print("Pulling task with ID {}".format(task_id))
    download_url = "{}/api/v1.0/org/tasks/{}/data?_oid={}".format(src_url, task_id, src_org_id)
    download = http_get(
        download_url,
        timeout=3600,
        **get_http_options(config_kwargs, "src_http_", "src_tls_", {"Authorization": bearer(src_token), "Accept": "application/octet-stream", "Content-Encoding": "gzip"}),
    )
    if download and download.status_code == 404:
        print("Task data is not available yet (still queued or running); it will sync on a later run:", task_id)
        return "not_ready"
    if not download or download.status_code != 200:
        print("Failed to download task:", task_id)
        return "failed"

    # Upload data to self-hosted
    print("Uploading task with ID {}".format(task_id))
    # The data endpoint redirects to object storage, and the platform presigns
    # the UNCOMPRESSED <type>_<task>_<site>.json object whenever the .gz one is
    # absent (models.Task.GetScanDataPresignedURL, still carrying its "remove
    # once all data and agents are migrated to gzip" TODO). Old tasks -- the
    # ones this integration exists to mirror -- therefore hand back plain
    # newline-delimited JSON, which always begins with "{". Starlark has no
    # exception handling, so calling gzip_decompress on that aborts the whole
    # run and every task after this one is silently never synced.
    unzipped = download.body
    if not unzipped:
        print("Task data was empty; skipping task:", task_id)
        return "failed"
    if unzipped[0:1] != "{":
        # Only a real gzip member (magic byte 0x1f) may reach gzip_decompress:
        # a 200 carrying an HTML proxy page or a truncated body would otherwise
        # raise, aborting the run and silently skipping every later task.
        if unzipped[0:1] != "\x1f":
            print("Task data was neither JSON nor gzip; skipping task:", task_id)
            return "failed"
        unzipped = gzip_decompress(unzipped)
    upload_url = "{}/api/v1.0/org/sites/{}/import?_oid={}".format(dst_url, dst_site_id, dst_org_id)
    upload = http_put(
        upload_url,
        body=gzip_compress(unzipped),
        timeout=3600,
        **get_http_options(config_kwargs, "dst_http_", "dst_tls_", {"Authorization": bearer(dst_token), "Content-Type": "application/octet-stream", "Content-Encoding": "gzip"}),
    )

    if not upload or upload.status_code != 200:
        print("Failed to upload task:", task_id)
        return "failed"

    print("Successfully synced task:", task_id)

    if hide_tasks_on_sync:
        hide_url = "{}/api/v1.0/org/tasks/{}/hide?_oid={}".format(src_url, task_id, src_org_id)
        hide = http_post(
            hide_url,
            **get_http_options(config_kwargs, "src_http_", "src_tls_", {"Authorization": bearer(src_token), "Content-Type": "application/json"}),
        )
        if hide and hide.status_code == 200:
            print("Task hidden:", task_id)
        else:
            # A silent hide failure re-syncs the same task on every run with
            # no visible cause, so the failure has to reach the log.
            print("Failed to hide task {}: status {}".format(
                task_id, hide.status_code if hide else "no response"))

    return "ok"

def main(**kwargs):
    src_url = kwargs.get("src_url", "https://console.runzero.com").rstrip("/")
    src_org_id = kwargs["src_org_id"]
    src_task_search_filter = kwargs.get("src_task_search_filter", 'name:="test"')
    dst_url = kwargs.get("dst_url", "https://console.runzero.com").rstrip("/")
    dst_org_id = kwargs["dst_org_id"]
    dst_site_id = kwargs["dst_site_id"]
    # get_bool, not kwargs.get: a bool arrives as the string "false" on some
    # paths, and `if "false":` is TRUE in Starlark -- which silently hid every
    # source task on a run that never asked for it.
    hide_tasks_on_sync = get_bool(kwargs, "hide_tasks_on_sync", default=False)

    src_token = kwargs["src_api_token"]
    dst_token = kwargs["dst_api_token"]

    tasks = get_tasks(src_url, src_org_id, src_task_search_filter, src_token, kwargs)
    print("Got {} task(s) to sync".format(len(tasks)))
    if not tasks:
        print("No tasks found.")
        return

    # Every task is attempted before the run is judged: one unreadable task
    # should not cost the rest of the batch. The count is what the task error
    # carries, so a partial sync is not filed as a complete one.
    failed = []
    not_ready = 0
    for task in tasks:
        task_id = task.get("id", "")
        if not task_id:
            continue
        status = sync_task(
            task_id,
            src_token,
            dst_token,
            src_url,
            dst_url,
            src_org_id,
            dst_org_id,
            dst_site_id,
            hide_tasks_on_sync,
            kwargs,
        )
        if status == "not_ready":
            not_ready += 1
        elif status != "ok":
            failed.append(task_id)

    if not_ready:
        print("{} task(s) had no data to sync yet".format(not_ready))
    if failed:
        fail("runzero-task-sync: {} of {} task(s) did not sync: {}".format(
            len(failed), len(tasks), ", ".join(failed[:10])))
    return None
