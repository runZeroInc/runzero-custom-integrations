# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-audit-log-to-webhook",
    "name": "Audit Log to Webhook",
    "type": "outbound",
    "description": "Forwards runZero audit events to an external webhook.",
    "version": "26052700",
    "minVersion": "5.1.0",
    "params": [
        {
            "key": "src_url",
            "label": "runZero source URL",
            "type": "url",
            "required": False,
            "default": "https://console.runzero.com",
            "group": "Source",
        },
        {
            "key": "dst_url",
            "label": "Webhook URL",
            "type": "url",
            "required": True,
            "group": "Destination",
            "description": "Where to POST audit events",
        },
        {
            "key": "external_api_key",
            "label": "Webhook API key",
            "type": "secret",
            "required": False,
            "group": "Destination",
            "description": "Optional bearer token sent to the webhook",
        },
        {
            "key": "rz_account_token",
            "label": "runZero account token",
            "type": "secret",
            "required": True,
            "group": "Source",
            "description": "Account-scoped token used to read the audit log",
        },
        {
            "key": "legacy_credentials",
            "label": "Legacy JSON credential",
            "type": "secret",
            "required": False,
            "group": "Legacy",
            "description": "Back-compat JSON with webhook_url, external_api_key, rz_account_token",
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('http', http_post='post', 'get_json', 'bearer')
load('json', json_encode='encode', json_decode='decode')
load('kwargs', 'get_http_options', 'get_http_tls')

def send_events_to_webhook(events, webhook, http_options):
    print("Sending {} events to Webhook".format(len(events)))
    batchsize = 500
    if len(events) > 0:
        for i in range(0, len(events), batchsize):
            batch = events[i:i+batchsize]
            tmp = ""
            for a in batch:
                tmp = tmp + "{}\n".format(json_encode(a))
            post_to_webhook = http_post(url=webhook, body=bytes(tmp), **http_options)
            print("Response code from Webhook: {}".format(post_to_webhook.status_code))
    else:
        print("No events found")

def main(*args, **kwargs):
    """
    Export runZero events from the last hour and send to a webhook.
    Credentials dict passed as:
    {"webhook_url":"URL","external_api_key":"bearer-auth-token","rz_export_token":"runzero-export-token"}
    """

    creds = kwargs.get('legacy_credentials')  # Legacy JSON path
    if type(creds) == 'string':
        creds = json_decode(creds)
    if type(creds) != 'dict':
        creds = {}

    src_url = kwargs.get('src_url') or creds.get('src_url') or 'https://console.runzero.com'
    webhook_url = kwargs.get('dst_url') or creds.get('dst_url') or creds.get('webhook_url')
    external_api_key = kwargs.get('external_api_key') or creds.get('external_api_key')
    rz_token = kwargs.get('rz_account_token') or creds.get('rz_account_token')

    if not webhook_url:
        print("Missing destination webhook URL.")
        return []
    if not rz_token:
        print("Missing runZero account token.")
        return []

    # We'll assume search query supports time filters (e.g. "timestamp > now-1h")
    search_query = "created:<1h"

    # Request headers for runZero export
    headers = {
        "Accept": "application/json",
        "Authorization": bearer(rz_token),
    }

    events_url = src_url.rstrip('/') + "/api/v1.0/account/events.json"
    tls = get_http_tls(kwargs)
    if creds.get('tls_disable_validation', False):
        tls["insecure"] = True
    src_options = get_http_options(kwargs, headers=headers)
    src_options["tls"] = tls

    # Fetch events
    events, err = get_json(
        events_url,
        params={"search": search_query},
        **src_options
    )

    if err:
        print("Failed to fetch events from runZero:", err)
        return []

    # Send to Webhook
    headers = {
        "Content-Type": "application/json"
    }
    if external_api_key:
        headers["Authorization"] = "Bearer {}".format(external_api_key)
    dst_options = get_http_options(kwargs, headers=headers)
    dst_options["tls"] = tls

    send_events_to_webhook(events, webhook_url, dst_options)

    return []
