# Custom Integration: Snow License Manager

## Getting Started

- Clone this repository

```
git clone https://github.com/TechnoSavage/runZero.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  Snow License Manager requirements

**License Manager Instance URL** - The domain or IP of the Snow Atlas web server (defined within the starlark script as `SNOW_BASE_URL`)

`Snow customer ID` - Numeric customer ID for asset retrieval. Found in `https://<snow license manager URL>/api/customers/` API endpoint. (defined within the starlark script as `SNOW_CUSTOMER_ID`)

`username` - username for API basic auth (configured in Credentials section of runZero)

`password` - password for API basic auth (configured in Credentials section of runZero)

## Snow License Manager API Docs

NA

## Steps

### Snow License Manager configuration

1. Determine the proper Snow License Manager URL:
    - Identify the url for your Snow License Manager instance.
    - Assign the URL to `SNOW_BASE_URL` within the starlark script
    - Identify the Customer ID to use for asset retrieval
    - Assign the Customer ID to `SNOW_CUSTOMER_ID` within the starlark script (multiple scripts can be created to import from different Customer IDs)
2. Create a valid username:password login to be used to authenticate to the API endpoints
    - Copy the username; this will be used as the value for `access_key` when creating the Custom Integration credentials in the runZero console (see below)
    - Copy the password; this will be used as the value for `access_secret` when creating the Custom Integration credentials in the runZero console (see below)

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
    - Modify datapoints uploaded to runZero as needed 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - Both `access_key` and `access_secret` are required
    - `access_key` corresponds to the username for the Snow License Manager credentials
    -  `access_secret` corresponds to the password for the Snow License Manager credentials
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new)
    - Add a Name and Icon 
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
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:<INSERT_NAME_HERE>`