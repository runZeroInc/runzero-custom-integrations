# Custom Integration: Akamai Guardicore Centra

## Getting Started

- Clone this repository

```
git clone https://github.com/TechnoSavage/runZero.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  Guardicore Centra requirements

**Instance URL** - The domain or IP of the Guardicore Centra web server e.g. "https://<url of guardicore centra console>" (defined within the starlark script as `CENTRA_BASE_URL`)

`client_id` - login username for authentication to retrieve JWT token (configured in Credentials section of runZero)

`client_secret` - login password for authentication to retrieve JWT token (configured in Credentials section of runZero)

## Guardicore Centra API Docs

- requires customer account

## Steps

### Guardicore Centra configuration

1. Determine the proper Guardicore Centra URL:
    - Assign the URL to `CENTRA_BASE_URL` within the starlark script 
2. Create login credentials with necessary, read-only access to retrieve JWT token for API access: 
    - Copy the username to the value for `access_key` when creating the Custom Integration credentials in the runZero console (see below)
    - Copy the password to the the value for `access_secret` when creating the Custom Integration credentials in the runZero console (see below)

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
    >- The script is configured to return assets with a status of 'On' and 'Off' by default.
    >- Assets with a Status of 'Deleted' are ignored (Centra retains these records indefinitely)
    >- If status 'Off" assets are not desired the user can remove the while loop in the get_assets function as indicated by the comment.
    >- If a user wants to import all assets, including deleted assets:
    >>- Remove the second while loop as above
    >>- Remove the "'status': 'on'" parameter from the GET request in the remaining while loop
    - Modify datapoints uploaded to runZero as needed 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - Both `access_key` and `access_secret` are required
    - `access_key` corresponds to the Client ID provided when creating the Guardicore Centra Application Registration
    -  `access_secret` corresponds to the Client secret provided when creating the Guardicore Centra Application Registration
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