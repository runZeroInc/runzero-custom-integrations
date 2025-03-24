load('runzero.types', 'ImportAsset', 'NetworkInterface')
load('json', json_encode='encode', json_decode='decode')
load('net', 'ip_address')
load('http', http_post='post', http_get='get', http_delete='delete', 'url_encode')

BASE_URL = "https://console.runZero.com/api/v1.0"
SEARCH = "alive:f"

def get_delete_ids(headers):
    # get assets to delete 
    assets = []
    url = BASE_URL + "/export/org/assets.json?" + url_encode({"search": SEARCH, "fields": "id"})
    get_assets = http_get(url=url, headers=headers, timeout=3600)
    assets_json = json_decode(get_assets.body)

    # if you got assets, return them as a list of asset IDs 
    if get_assets.status_code == 200:
        assets = []
        for a in assets_json:
            assets.append(a.get("id", ""))
        print(assets)
        return assets
    else:
        return None


def delete_assets(assets, headers):
    
    # delete assets
    url = BASE_URL + "/org/assets/bulk/delete"
    print("Deleting assets with these IDs: ".format(assets))
    delete = http_delete(url, headers=headers, body=bytes(json_encode({"asset_ids": assets})), timeout=3600)
    
    # verify the delete worked 
    if delete.status_code == 204:
        print("Deleted all assets matching this search: {}".format(SEARCH))
    else:
        print("Failed to delete assets. Please try again.")


def main(*args, **kwargs):
    rz_org_token = kwargs['access_secret']
    headers = {"Authorization": "Bearer {}".format(rz_org_token), "Content-Type": "application/json"}
    assets = get_delete_ids(headers=headers)
    if assets:
        delete_assets(assets=assets, headers=headers)