# Custom Integration: Snipe-IT

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

## Snipe-IT requirements

- **API Bearer Token** for **Snipe-IT** API authentication
- **Snipe-IT Base URL** (depends on local install)

## Snipe-IT API Docs

- [Snipe-IT API Reference](https://snipe-it.readme.io/reference/api-overview)
- [Snipe-IT Docs](https://snipe-it.readme.io/docs)

## Steps

### Snipe-IT configuration

1. [Generate an API bearer token](https://snipe-it.readme.io/reference/generating-api-tokens) in the **Snipe-IT** console
2. Find your base URL for the **Snipe-IT** API
    - This will be the hostname or host:port of the **Snipe-IT** server
    - example: `https://my.snipe.org`
    - example: `https://192.168.5.64:8443`
3. Update `SNIPE_BASE_URL` variable in the script (line 8)
    - Do not place a trailing `/` at the end of the URL; this formatting is handled in the script when completing the API URL

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment
    - runZero requires at least one common field to merge assets with. The default **Snipe-IT** fieldset "Asset with MAC address"
    tracks MAC addresses and this is the minimum field needed for runZero asset merging to take effect (though this field may not
    always be available with runZero scanned assets)
    - The base script will map Snipe's "category" to runZero's asset "type"; maintaining category naming conventions consistent to runZero's type values would be beneficial
    - "Model" and "Manufacturer" fields in Snipe are also mapped to the corresponding "Model" and "Manufacturer" attributes in runZero
    - Add additional custom fields that are configured in **Snipe-IT**
        - **Snipe-IT** is highly configurable and many custom fields and fieldsets can be created for assets
        - Tracking additional fields such as os, os version, and hostname could be beneficial for merging. If adding these custom fields to fieldset then map them in 
        the custom integration script accordingly
        - Any additional custom fields tracked in **Snipe-IT** that do not correspond to runZero's [ImportAsset](https://runzeroinc.github.io/runzero-sdk-py/autoapi/runzero/types/_data_models_gen/index.html#runzero.types._data_models_gen.ImportAsset) data model can be mapped to custom attributes following the pattern in the script 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - Input the **Snipe-IT** bearer token in the `api_token` field.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon (e.g. snipeit)
        - The name given to the custom integration will correspond to the custom_integration value when creating queries
    - Toggle `Enable custom integration script` to input your finalized script
    - Click `Validate` to ensure it has valide syntax
    - Click `Save` to create the Custom Integration 
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created in steps 2 and 3
    - Update the task schedule to recur at the desired timeframes
    - Select the Explorer you'd like the Custom Integration to run from
    - Click `Save` to kick off the first task 


### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration 
- The task will update the existing assets with the data pulled from the Custom Integration source 
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, etc)
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:snipeit`