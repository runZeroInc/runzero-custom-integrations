# Custom Integration: Bitsight

Import assets and associated findings/vulnerabilities by Company ID.

## Getting Started

- Clone this repository

```
git clone https://github.com/runZeroInc/runzero-custom-integrations.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  Bitsight requirements

**Instance URL** - The domain or IP of the Bitsight web server e.g. "https://<url of Bitsight console>" (defined within the starlark script as `BITSIGHT_BASE_URL`)

`client_secret` - A valid API token with the necessary permissions to retrieve data from the Bitsight platform (configured in Credentials section of runZero)

## Bitsight API Docs

[Bitsight API](https://help.bitsighttech.com/hc/en-us/categories/360005934253-Bitsight-API)

[Bitsight API Docs](https://bitsight.stoplight.io/docs/v1-schema/b9g1t0y9f9g2x-overview)

## Steps

### Bitsight configuration

1. Determine the proper Bitsight URL:
    - Assign the URL to `BITSIGHT_BASE_URL` within the starlark script. This field is already populated with the commonly used URL.
2. Create an API token for API access (Company or User token): 
    - Copy the API token to the value for `api_token` when creating the Custom Integration credentials in the runZero console (see below)

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
      - Bitsight classifies a few asset types (IP, CIDR, Domain). The default behavior of the script is to import only IP-based assets as these are easily merged with existing assets. In testing it also appeared that many domain-based assets are subdomains belonging to IP-based assets, ultimately, creating duplicates of little value. If a user wishes to import all assets types as opposed to just IP-based see the comment on line 224 of the script.
    - Modify datapoints uploaded to runZero as needed 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - Both `company_id` and `api_token` are required
    - `company_id` corresponds to the Bitsight company ID
    - `api_token` corresponds to the Company or User API token created in Bitsight
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon 
    - Toggle `Enable custom integration script` to input your finalized script
    - Make any modifications to the script for the desired output.
    -- By default, the script will return all Bitsight assets including IP address-based assets and domain-based assets. If preferred, the script can return only IP-based assets by uncommenting the optional query parameters in the get_assets function (Noted by a comment in the script.)
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:<INSERT_NAME_HERE>`