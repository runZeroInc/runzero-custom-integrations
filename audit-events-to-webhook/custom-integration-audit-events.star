load('http', http_post='post', http_get='get', 'url_encode')
load('json', json_encode='encode', json_decode='decode')
load('time', 'parse_time')

def send_events_to_webhook(events, webhook, headers):
    print("Sending {} events to Webhook".format(len(events)))
    batchsize = 500
    if len(events) > 0:
        for i in range(0, len(events), batchsize):
            batch = events[i:i+batchsize]
            tmp = ""
            for a in batch:
                tmp = tmp + "{}\n".format(json_encode(a))
            post_to_webhook = http_post(url=webhook, headers=headers, body=bytes(tmp))
            print("Response code from Webhook: {}".format(post_to_webhook.status_code))
    else:
        print("No events found")

def main(*args, **kwargs):
    """
    Export runZero events from the last hour and send to a webhook.
    Credentials dict passed as:
    {"webhook_url":"URL","external_api_key":"bearer-auth-token","rz_export_token":"runzero-export-token"}
    """

    creds = kwargs.get('access_secret')  # runZero passes this as JSON string or dict
    if type(creds) == 'string':
        creds = json_decode(creds)

    webhook_url = creds.get('webhook_url')
    external_api_key = creds.get('external_api_key')
    rz_token = creds.get('rz_account_token')

    # We'll assume search query supports time filters (e.g. "timestamp > now-1h")
    search_query = "created:<1h"

    # Request headers for runZero export
    headers = {
        "Accept": "application/json"
    }

    if external_api_key:
        headers["Authorization"] = "Bearer {}".format(external_api_key)

    # Build runZero API URL
    base_url = "https://console.runzero.com/api/v1.0"
    events_url = "https://console.runzero.com/api/v1.0/account/events.json"

    # Fetch events
    response = http_get(events_url, headers=headers, params={"search": search_query})

    if not response or response.status_code != 200:
        print("Failed to fetch events from runZero. Status: {}".format(response.body))
        return []

    events = json_decode(response.body)

    # Send to Webhook
    headers = {
        "Content-Type": "application/json"
    }
    if external_api_key:
        headers["Authorization"] = "Bearer {}".format(external_api_key)

    send_events_to_webhook(events, webhook_url, headers)

    return []
