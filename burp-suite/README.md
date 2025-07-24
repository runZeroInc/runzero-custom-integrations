# Custom Integration: Burp Suite DAST

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Burp Suite DAST requirements

- API key with appropriate permissions.
- Burp Suite API URL (e.g. `https://<your-app-server>:8443/graphql/v1`).

## Steps

### Burp Suite DAST configuration

1. Create an API user for Burp Suite and copy the API key.
   a. Login to the Burp Suite web console.
   b. Navigate to Team > Add a new user
   c. Enter a Name, Username and Email
   d. For **Choose a login type**, select API key
   e. Select the **Scan viewers** and **Sites maintainers** roles. 
2. Note down the API URL: `https://<your-app-server>:8443/graphql/v1`.

### runZero configuration

1. (OPTIONAL) - Make any necessary changes to the script to align with your environment.
    - Set the BURP_API_URL variable in the integration script.
    - If appropriate, modify GraphQL queries to fetch additional data points.
    - If updating GraphQL queries, update build functions to include additional data points.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
    - Select the type `Custom Integration Script Secrets`.
    - For the `access_key`, enter a random value or leave the field blank. This attribute will not be used.
    - For the `access_secret`, input your Burp Suite API key.
3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
    - Add a Name and Icon for the integration (e.g., "burp").
    - Upload an image file for the Burp Suite icon.
        - Download a Burp Suite icon from their [website](https://portswigger.net) or [social media](https://www.linkedin.com/company/portswigger/).
        - Resize selected icon to be 256px by 256px
        - Upload resized icon file
    - Toggle `Enable custom integration script` to input the finalized script.
    - Click `Validate` to ensure it has valid syntax.
    - Click `Save` to create the Custom Integration.
4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
    - Select the Credential and Custom Integration created in steps 2 and 3.
    - Update the task schedule to recur at the desired timeframes.
    - Select the Explorer you'd like the Custom Integration to run from.
    - Click `Save` to kick off the first task.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update the existing assets with the data pulled from the Custom Integration source.
- The task will create new assets for when there are no existing assets that meet merge criteria (e.g hostname).
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:burp`.

### Additional Resources

- [Burp Suite DAST API documentation](https://portswigger.net/burp/documentation/dast/user-guide/api-documentation/graphql-api/getting-started)