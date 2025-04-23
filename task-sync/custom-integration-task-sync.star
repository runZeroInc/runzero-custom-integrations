load('http', http_get='get', http_post='post', http_put='put', 'url_encode')
load('json', json_decode='decode')

# Parameters from kwargs
SAAS_ORG_ID = "4ffe8ffb-18e7-451b-9aea-7c967ad07f8e"
SAAS_SITE_ID = "a7b2287e-51fa-47fc-bd00-6a68eed0786b"
SAAS_BASE_URL = "https://console.runzero.com"
SELF_ORG_ID = "e9004d87-e127-4863-aa5e-5c302e87694e"
SELF_SITE_ID = "0396debb-1874-41d2-933e-c2cf4f59a8e5"
SELF_BASE_URL = "https://console.runzero.com"
SAAS_TASK_SEARCH_FILTER = 'name:="test"'

# Flags
HIDE_TASKS_ON_SYNC = False

def get_tasks(saas_token):
    params = {"_oid": SAAS_ORG_ID, "search": SAAS_TASK_SEARCH_FILTER}
    url = "{}{}{}".format(SAAS_BASE_URL, "/api/v1.0/org/tasks?", url_encode(params))
    headers = {"Content-Type": "application/json", "Authorization": "Bearer {}".format(saas_token)}
    response = http_get(url, headers=headers)
    if response.status_code != 200:
        print("Failed to get tasks", response.status_code)
        return []
    return json_decode(response.body)

def sync_task(task_id, saas_token, self_token):
    # Download data from SaaS
    print("Pulling task with ID {}".format(task_id))
    download_url = "{}/api/v1.0/org/tasks/{}/data".format(SAAS_BASE_URL, task_id)
    download = http_get(download_url, headers={"Authorization": "Bearer {}".format(saas_token), "Accept": "application/octet-stream", "Content-Encoding": "gzip"}, timeout=3600)
    print(type(download.body))
    if download.status_code != 200:
        print("Failed to download task:", task_id)
        return False

    # Upload data to self-hosted
    print("Uploading task with ID {}".format(task_id))
    upload_url = "{}/api/v1.0/org/sites/{}/import?_oid={}".format(SELF_BASE_URL, SELF_SITE_ID, SELF_ORG_ID)
    upload = http_put(upload_url, headers={"Authorization": "Bearer {}".format(self_token), "Content-Type": "application/octet-stream", "Content-Encoding": "gzip"}, body=bytes(download.body), timeout=3600)

    if upload.status_code != 200:
        print("Failed to upload task:", task_id)
        return False

    print("Successfully synced task:", task_id)

    if HIDE_TASKS_ON_SYNC:
        hide_url = "{}/api/v1.0/org/tasks/{}/hide?_oid={}".format(SAAS_BASE_URL, task_id, SAAS_ORG_ID)
        hide = http_post(hide_url, headers={"Authorization": "Bearer {}".format(saas_token), "Content-Type": "application/json"})
        if hide.status_code == 200:
            print("Task hidden:", task_id)

    return True

def main(**kwargs):
    saas_token = kwargs["access_key"]       # SaaS token
    self_token = kwargs["access_secret"]    # Self-hosted token

    tasks = get_tasks(saas_token)
    print("Got {} task(s) to sync".format(len(tasks)))
    if not tasks:
        print("No tasks found.")
        return

    for task in tasks:
        task_id = task.get("id", "")
        if not task_id:
            continue
        success = sync_task(task_id, saas_token, self_token)
        if not success:
            print("Sync failed for task:", task_id)

    return None