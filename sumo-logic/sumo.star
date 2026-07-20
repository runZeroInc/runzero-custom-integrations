# Copyright 2026 runZero, Inc. Available under the MIT License

CONFIG = {
    "id": "runzero-sumo-logic",
    "name": "Sumo Logic",
    "type": "outbound",
    "description": "Exports runZero assets into Sumo Logic.",
    "version": "26052700",
    "minVersion": "5.1.0",
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
load('kwargs', 'get_url_base', 'get_http_options')

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
    print("Sending {} assets to Sumo Logic".format(len(assets)))
    batchsize = 500
    if len(assets) > 0:
        for i in range(0, len(assets), batchsize):
            batch = assets[i:i+batchsize]
            tmp = ""
            for a in batch:
                tmp = tmp + "{}\n".format(json_encode(a))
            post_to_sumo = http_post(url=dst_url, body=bytes(tmp), **http_options)
    else:
        print("No assets found")


def main(*args, **kwargs):
    src_url = get_url_base(kwargs, "src_url")
    dst_url = get_url_base(kwargs, "dst_url")
    rz_export_token = kwargs['runzero_export_token']
    headers = {"Authorization": "Bearer {}".format(rz_export_token)}
    assets = get_assets(base_url=src_url, http_options=get_http_options(kwargs, headers=headers))
    if assets:
        sync_to_sumo(dst_url=dst_url, assets=assets, http_options=get_http_options(kwargs))