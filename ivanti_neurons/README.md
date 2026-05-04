# Custom Integration: Ivanti Neurons - device inventory

Retrieve devices from Ivanti Neurons API "People and Devices" API endpoint (https://<hostname>/api/apigatewaydataservices/v1/devices) to enrich asset inventory in runZero.

## Getting Started

- Clone this repository

```
git clone https://github.com/TechnoSavage/runZero.git
``` 

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero

##  Ivanti Neurons requirements

**Instance URL** - The Neurons Auth URL provided upon creating an app registration in the Neurons console e.g. "https://<url of Neurons server>" (defined within the starlark script as `NEURONS_AUTH_URL`)

`client_id` - Client ID provided upon creating an app registration in the Neurons console. Used for authentication to retrieve JWT token (configure this value in the Credentials section of the runZero console)

`client_secret` - Client Secret provided upon creating an app registration in the Neurons console. Used for authentication to retrieve JWT token(configure this value in Credentials section of the runZero console)

`Tenant ID` - The tenant ID of the Neurons instance provided with the Auth URL upon a new app registration. Used in request headers when authenticating to the "People and Devices" API endpoint. (defined within the starlark script as `NEURONS_TENANT_ID`)
`
The URL scheme is `https://<NEURONS_AUTH_URL>/<NEURONS_TENANT_ID>/`

## Ivanti Neurons API Docs

- [Ivanti Neurons API](https://help.ivanti.com/ht/help/en_US/CLOUD/api/Shared-Content/welcome.htm)
- [Ivanti Product API Hub](https://www.ivanti.com/support/api)

## Steps

### Ivanti Neurons configuration

**Create a new app registration in the Neurons Console:**
1. In Ivanti Neurons, navigate to Admin > App Registrations.
2. Select New registration to open the New app registration panel.
3. From the drop-down, select Custom App.
4. Click Continue.
5. In the Custom App panel, optionally enter a Description for the registration e.g. "runZero integration"
6. Click Register to generate the authentication settings.
7. In the Complete this registration panel, the authentication settings, required to complete the registration, are provided:
   - *Neurons Auth URL* - Copy this to the value for the `NEURONS_AUTH_URL` variable in the custom integration script.
   - *Client ID* - Copy the Client ID to the value for `access_key` when creating the Custom Integration credentials in the runZero console (see below).
   - *Client secret* - Copy the Client secret to the the value for `access_secret` when creating the Custom Integration credentials in the runZero console (see below)

***Warning***: For security reasons, the Client Secret will not be visible again once you close this panel, so make sure you copy it before clicking 

8. Finish and close.
9. After completing the App Registration process, you will get the tenant hostname and tenant ID from the Auth URL. Copy the tenant ID to the value for the `NEURONS_TENANT_ID` variable in the custom integration script.

[How to authenticate to Neurons API](https://help.ivanti.com/ht/help/en_US/CLOUD/api/Shared-Content/authenticate_api.htm)

### runZero configuration

1. (OPTIONAL) - make any neccessary changes to the script to align with your environment. 
    - Modify API calls as needed to filter assets
    - Modify datapoints uploaded to runZero as needed 
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials)
    - Select the type `Custom Integration Script Secrets`
    - Both `access_key` and `access_secret` are required
    - `access_key` corresponds to the Client ID provided when creating the app registration in the Neurons Console.
    -  `access_secret` corresponds to the Client secret provided when creating the app registration in the Neurons Console.

Paste the parameters to pass on the field below as described in documentation.

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