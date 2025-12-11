# Custom Integration: Moysle

## runZero Requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Moysle Requirements

- Moysle API token (`access_key`).
- Moysle admin account email and password, combined as `email:password` in the `access_secret` field.
- Account must have permission to access device inventory.

## Steps

### Moysle Configuration

1. Gather your Moysle API credentials:
   - Obtain your **API token** from the Moysle admin portal.
   - Use a valid Moysle admin email and password.

2. Test your credentials:
   - Use a tool like Postman or curl to confirm login is working.
   - Example request (token returned in the `Authorization` response header):
     ```bash
     curl -i -X POST "https://managerapi.mosyle.com/v2/login" \
     -H "Content-Type: application/json" \
     -d '{
       "accessToken": "<API_TOKEN>",
       "email": "<EMAIL>",
       "password": "<PASSWORD>"
     }'
     ```
   - Copy the bearer token from the `Authorization: Bearer <token>` response header.

3. Verify device access:
   - Use the bearer token and include the access token in the request body:
     ```bash
     curl -X POST "https://managerapi.mosyle.com/v2/listdevices" \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "accessToken": "<API_TOKEN>",
       "options": {
         "os": "all",
         "page": 0
       }
     }'
     ```

### runZero Configuration

1. (OPTIONAL) - Modify the Starlark script to match your desired filtering, pagination, or attribute mapping.

2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - Use the `access_key` field for your API token.
   - Use the `access_secret` field as JSON or a dict with keys: `{"email": "<EMAIL>", "password": "<PASSWORD>"}` (or `username` in place of `email`). You can optionally include a pre-issued bearer token as `bearer`/`token` to skip login parsing.

3. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., `moysle`).
   - Toggle `Enable custom integration script` to paste in the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.

4. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 2 and 3.
   - Set the task schedule to run as needed.
   - Select the hosted Explorer to run the integration from.
   - Click `Save` to activate the task.

### What's Next?

- The task will appear on the [Tasks](https://console.runzero.com/tasks) page and run like any other integration.
- It will update existing assets or create new ones based on device merge criteria (hostname, MAC, etc.).
- You can filter assets imported via this integration using:`custom_integration:moysle`
