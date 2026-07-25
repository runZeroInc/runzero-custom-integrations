# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-task-sync",
    "name": "runZero Task Sync",
    "type": "inbound",
    "description": "Mirrors tasks between two runZero instances (SaaS to self-hosted, etc.).",
    "version": "26052700",
    "minVersion": "5.0.260723.0",
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
load('kwargs', 'get_http_options')

def get_tasks(src_url, src_org_id, src_task_search_filter, src_token, config_kwargs):
    params = {"_oid": src_org_id, "search": src_task_search_filter}
    url = "{}{}{}".format(src_url, "/api/v1.0/org/tasks?", url_encode(params))
    data, err = get_json(
        url,
        **get_http_options(config_kwargs, "src_http_", "src_tls_", {"Authorization": bearer(src_token)})
    )
    if err:
        print("Failed to get tasks:", err)
        return []
    return data or []

def sync_task(task_id, src_token, dst_token, src_url, dst_url, src_org_id, dst_org_id, dst_site_id, hide_tasks_on_sync, config_kwargs):
    # Download data from SaaS
    print("Pulling task with ID {}".format(task_id))
    download_url = "{}/api/v1.0/org/tasks/{}/data".format(src_url, task_id)
    download = http_get(
        download_url,
        timeout=3600,
        **get_http_options(config_kwargs, "src_http_", "src_tls_", {"Authorization": bearer(src_token), "Accept": "application/octet-stream", "Content-Encoding": "gzip"}),
    )
    if download.status_code != 200:
        print("Failed to download task:", task_id)
        return False

    # Upload data to self-hosted
    print("Uploading task with ID {}".format(task_id))
    unzipped = gzip_decompress(download.body)
    upload_url = "{}/api/v1.0/org/sites/{}/import?_oid={}".format(dst_url, dst_site_id, dst_org_id)
    upload = http_put(
        upload_url,
        body=gzip_compress(unzipped),
        timeout=3600,
        **get_http_options(config_kwargs, "dst_http_", "dst_tls_", {"Authorization": bearer(dst_token), "Content-Type": "application/octet-stream", "Content-Encoding": "gzip"}),
    )

    if upload.status_code != 200:
        print("Failed to upload task:", task_id)
        return False

    print("Successfully synced task:", task_id)

    if hide_tasks_on_sync:
        hide_url = "{}/api/v1.0/org/tasks/{}/hide?_oid={}".format(src_url, task_id, src_org_id)
        hide = http_post(
            hide_url,
            **get_http_options(config_kwargs, "src_http_", "src_tls_", {"Authorization": bearer(src_token), "Content-Type": "application/json"}),
        )
        if hide.status_code == 200:
            print("Task hidden:", task_id)

    return True

def main(**kwargs):
    src_url = kwargs.get("src_url", "https://console.runzero.com").rstrip("/")
    src_org_id = kwargs["src_org_id"]
    src_task_search_filter = kwargs.get("src_task_search_filter", 'name:="test"')
    dst_url = kwargs.get("dst_url", "https://console.runzero.com").rstrip("/")
    dst_org_id = kwargs["dst_org_id"]
    dst_site_id = kwargs["dst_site_id"]
    hide_tasks_on_sync = kwargs.get("hide_tasks_on_sync", False)

    src_token = kwargs["src_api_token"]
    dst_token = kwargs["dst_api_token"]

    tasks = get_tasks(src_url, src_org_id, src_task_search_filter, src_token, kwargs)
    print("Got {} task(s) to sync".format(len(tasks)))
    if not tasks:
        print("No tasks found.")
        return

    for task in tasks:
        task_id = task.get("id", "")
        if not task_id:
            continue
        success = sync_task(
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
        if not success:
            print("Sync failed for task:", task_id)

    return None
