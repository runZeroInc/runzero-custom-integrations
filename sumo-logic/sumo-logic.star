# This is a runZero Custom Integration, please see https://github.com/runZeroInc/runzero-custom-integrations for details.

CONFIG = {
    "id": "runzero-sumo-logic",
    "name": "Sumo Logic",
    "type": "outbound",
    "description": "Exports runZero assets into Sumo Logic.",
    "version": "1",
    "maturity": "beta",
    "minVersion": "5.1.260818.0",
    "params": [
        {
            "key": "src_url",
            "label": "runZero source URL",
            "type": "url",
            "required": True,
            "default": "https://console.runzero.com",
        },
        {
            "key": "dst_url",
            "label": "Sumo HTTP endpoint",
            "type": "url",
            "required": True,
        },
        {
            "key": "runzero_export_token",
            "label": "runZero export token",
            "type": "secret",
            "required": True,
        },
    ],
    "includes": {
        "tls_": OPTIONS_TLS,
        "http_": OPTIONS_HTTP,
    },
}
load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode')
load('net', 'ip_address')
load('http', http_post='post', 'get_json', 'bearer', 'url_encode')
load('kwargs', 'get_url_base', 'get_string', 'get_http_options')

SEARCH = "alive:t"

def get_assets(base_url, http_options):
    # get assets to upload to sumo
    assets = []
    url = base_url + "/api/v1.0/export/org/assets.json?{}".format(url_encode({"search": SEARCH}))
    assets_json, err = get_json(url=url, timeout=600, **http_options)
    if err:
        print("runZero export failed:", err)
        return None
    if assets_json and len(assets_json) > 0:
        print("Got {} assets".format(len(assets_json)))
        return assets_json
    else:
        print("runZero did not return any assets")
        return None

def sync_to_sumo(dst_url, assets, http_options):
    """POST the assets in batches. Returns the number NOT accepted by Sumo."""
    print("Sending {} assets to Sumo Logic".format(len(assets)))
    batchsize = 500
    sent = 0
    rejected = 0
    if len(assets) > 0:
        for i in range(0, len(assets), batchsize):
            batch = assets[i:i+batchsize]
            tmp = ""
            for a in batch:
                tmp = tmp + "{}\n".format(json_encode(a))
            post_to_sumo = http_post(url=dst_url, body=bytes(tmp), **http_options)

            # An HTTP source is write-only: the status code is the ONLY
            # acknowledgement Sumo gives, and it answers 200 on success. Leaving
            # it unread -- as this did -- makes a revoked collector code, a wrong
            # source address, or a batch over the source's size limit look
            # exactly like an accepted upload. http_post aborts the run by itself
            # on a transport failure, so a response here always has a status.
            if not post_to_sumo or post_to_sumo.status_code != 200:
                rejected += len(batch)
                print("Sumo Logic rejected a batch of {} assets with status {}: {}".format(
                    len(batch),
                    post_to_sumo.status_code if post_to_sumo else "no response",
                    str(post_to_sumo.body)[:200] if post_to_sumo else ""))
                # Keep going rather than returning: the remaining batches are
                # independent uploads, and a size-limit rejection affects only
                # the batch that hit it.
                continue
            sent += len(batch)
        print("Uploaded {} of {} assets to Sumo Logic".format(sent, len(assets)))
    else:
        print("No assets found")
    return rejected


def main(*args, **kwargs):
    # The two URLs are read differently on purpose. src_url is a console the
    # script appends its own /api/v1.0/... paths to, so a scheme+host base is
    # what it wants. dst_url is posted to verbatim: a Sumo HTTP Source Address
    # carries its unique collector code as the LAST PATH SEGMENT, so
    # get_url_base() would drop exactly the part that identifies the source and
    # every upload would 404 against the bare host.
    src_url = get_url_base(kwargs, "src_url")
    dst_url = get_string(kwargs, "dst_url")
    rz_export_token = kwargs['runzero_export_token']
    headers = {"Authorization": "Bearer {}".format(rz_export_token)}
    assets = get_assets(base_url=src_url, http_options=get_http_options(kwargs, headers=headers))
    if assets:
        rejected = sync_to_sumo(dst_url=dst_url, assets=assets, http_options=get_http_options(kwargs))
        # This integration emits no assets, so the task's own outcome is the only
        # thing an operator sees. A run that exported the estate and then had it
        # refused must not finish green: the receiver has a hole in it, and the
        # next run overwrites nothing and repairs nothing. fail() is what makes
        # the task record the failure.
        if rejected > 0:
            fail("Sumo Logic did not accept {} of {} assets".format(rejected, len(assets)))