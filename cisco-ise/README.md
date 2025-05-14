# Custom Integration: Cisco ISE

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Cisco ISE requirements

- API user with access to the Cisco ISE **Monitoring Node API**.
- Base URL of your Cisco ISE instance (e.g., `https://ise.company.com`).
- Base64-encoded API credentials (`username:password`).

## Steps

### Cisco ISE configuration

1. **Verify API access**:
   - Log in to your Cisco ISE Monitoring Node.
   - Navigate to **Administration > System > Admin Access > Admin Groups** and ensure API users are granted access to the `Session/ActiveList` API.
   - Test access to:  
     `https://<ISE-HOST>/admin/API/mnt/Session/ActiveList`  
     using Basic Auth in a REST client (e.g., Postman).

2. **Base64 encode credentials**:
   - Encode `username:password` using Base64. You can use a terminal:
     ```bash
     echo -n 'username:password' | base64
     ```

### runZero configuration

1. Modify the script if needed:
   - Update the `CISCO_ISE_HOST` constant to point to your ISE Monitoring Node URL.
   - You may adjust parsing logic to capture additional session fields from the XML.

2. **Create a Credential for the Custom Integration**:
   - Go to [runZero Credentials](https://console.runzero.com/credentials).
   - Select `Custom Integration Script Secrets`.
   - Input the Base64-encoded string in the `access_secret` field.
   - Use a placeholder like `foo` for `access_key` (unused).

3. **Create the Custom Integration**:
   - Go to [runZero Custom Integrations](https://console.runzero.com/custom-integrations/new).
   - Add a name (e.g., `cisco-ise`) and icon for the integration.
   - Toggle **Enable custom integration script** and paste in the script.
   - Click `Validate`, then `Save`.

4. **Schedule the Integration Task**:
   - Go to [runZero Ingest](https://console.runzero.com/ingest/custom/).
   - Select the credential and custom integration you created.
   - Set a schedule for recurring updates.
   - Choose the Explorer instance to run the integration.
   - Click `Save`.

### What's next?

- The integration will retrieve active sessions from Cisco ISE.
- Device IP and MAC addresses will be mapped to runZero assets.
- You can find enriched assets using the runZero search query: *custom_integration:cisco_ise*


### Notes

- The integration extracts fields like `device_ip_address`, `calling_station_id` (MAC), and `user_name` (hostname).
- If `device_ip_address` is missing, it falls back to `framed_ip_address`.
- All ISE session IDs and NAS information are stored as `customAttributes`.
- You can customize the `build_assets()` function to include more session fields if needed.
