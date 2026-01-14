# Custom Integration: SolarWinds Orion - SolarWinds Information Service (SWIS) 

## Getting Started

- Clone this repository

```
git clone https://github.com/runZeroInc/runzero-custom-integrations.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  SolarWinds SWIS requirements

**SWIS Instance URL** - The domain or IP of the Snow Atlas web server and the port number e.g. "https://my.solarwinds.instance:17774" (defined within the starlark script as `SWIS_BASE_URL`)

**username** - account username for Solarwinds access (configured in Credentials section of runZero)

**password** - account password (configured in Credentials section of runZero)

## SolarWinds SWIS API Docs

- [SWIS Cortex.Orion.Node Schema Reference](https://solarwinds.github.io/OrionSDK/schema/Cortex.Orion.Node.html)

- [Orion SDK SWIS Docs](https://github.com/solarwinds/OrionSDK/wiki/About-SWIS)

## Steps

### Solarwinds configuration

1. Determine the proper Solarwinds URL and port:
    - Common Solarwinds ports are 17774 (default since v2024) and 17778 (the default in v2023 and prior).
    - Assign the URL to `SWIS_BASE_URL` within the starlark script 
    - Determine proper username and password credentials for access. These will be configured in the Custom Integration credentials section within the runZero console.

### runZero configuration

1. (Make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
     >- Determine the proper SWQL query needed to return the data set to import to runZero
     >- Add this query to the integration script in the 'params' variable within the 'get_assets' function.
    - Modify attribute mapping based on the data returned by the SWQL query as needed
        >- The integration script outlines some common example attributes that could be brought in from Solarwinds but the attributes that are actually retrieved will be determined by the SWQL query passed in the API call params
        >- Modify the asset attributes and custom attributes to match the data provided by the SWQL query following the pattern outlined in the script
        >- For a list of "core" attributes that runZero maps, reference the Custom SDK documentation [here](https://runzeroinc.github.io/runzero-sdk-py/autoapi/runzero/types/_data_models_gen/index.html#runzero.types._data_models_gen.ImportAsset). All other attributes provided by Solarwinds should be mapped within 'Custom Attributes'
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type **Custom Integration Script Secrets**
    - Both **access_key** and **access_secret** are required
    - **access_key** corresponds to the username to access Solarwinds
    -  **access_secret** corresponds to the password to access Solarwinds
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name (e.g. solarwinds) and Icon 
    - Toggle **Enable custom integration script** to input your finalized script
    - Click **Validate** to ensure it has valide syntax
    - Click **Save** to create the Custom Integration 
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/)
    - Select the Credential and Custom Integration created in steps 2 and 3
    - Update the task schedule to recur at the desired timeframes
    - Select the Explorer you'd like the Custom Integration to run from
    - Click **Save** to start the task 


### What's next?

- You will see the task initilize on the [tasks](https://console.runzero.com/tasks) page like other integration tasks 
- The task will update the existing assets with the data pulled from the Custom Integration source 
- The task will create new assets for when there are no existing assets that meet merge criteria (hostname, MAC, IP, etc)
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:<INSERT_NAME_HERE>`