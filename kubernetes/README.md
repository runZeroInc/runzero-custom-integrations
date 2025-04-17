# Custom Integration: Kubernetes

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.

## Kubernetes requirements

- `kubectl` installed and configured to interact with your Kubernetes cluster.
- Cluster admin privileges to retrieve node, pod, and cluster metadata.
- A Kubernetes service account with the necessary permissions to query the API.
- A **Bearer Token** for API authentication.
- An active `kubectl proxy` session to securely interact with the cluster API.

## Steps

### Kubernetes configuration

1. **Create a Service Account and Bind Permissions**  
   Run the following commands to create a service account, bind it to the `cluster-reader` role, and retrieve the bearer token:

   ```sh
   kubectl create serviceaccount rz-integration
   kubectl create clusterrolebinding rz-integration-binding --clusterrole=view --serviceaccount=default:rz-integration
   ```

2. **Retrieve the Bearer Token**
   ```sh
   kubectl create token rz-integration --duration=48h
   ```

   Copy and securely store this token, as it will be used to authenticate API requests.

3. **Start the Kubernetes API Proxy**
   ```sh
   kubectl proxy --port=8001
   ```

   This will make the Kubernetes API available at `http://127.0.0.1:8001` on your local machine. This is required since the API calls require a valid certificate.

4. **Test API Access**  
   Validate that your token works and that the API is accessible:

   ```sh
   curl -H "Authorization: Bearer YOUR_K8S_BEARER_TOKEN" -H "Accept: application/json" http://127.0.0.1:8001/api/v1/nodes
   ```

   You should receive a JSON response containing details about your cluster nodes.

---

### runZero configuration

1. **(OPTIONAL) - Customize the script**  
   - Modify API calls as needed to adjust asset metadata.
   - Edit which attributes are ingested into runZero.

2. **[Create a Credential for the Custom Integration](https://console.runzero.com/credentials)**  
   - Select **Custom Integration Script Secrets** as the credential type.
   - Use the `access_key` field for **your Kubernetes API URL** (`http://127.0.0.1:8001`).
   - Use the `access_secret` field for **your Bearer Token** (retrieved in step 2).

3. **[Create the Custom Integration](https://console.runzero.com/custom-integrations/new)**  
   - Name the integration (e.g., **"Kubernetes"**).
   - Add an icon if desired.
   - Toggle **Enable custom integration script** and paste the finalized script.
   - Click **Validate** to check for syntax errors.
   - Click **Save** to store the integration.

4. **[Create the Custom Integration task](https://console.runzero.com/ingest/custom/)**  
   - Select the Credential and Custom Integration from steps 2 and 3.
   - Set up the task schedule for periodic asset ingestion.
   - Choose the runZero Explorer where the integration should execute.
   - Click **Save** to start the first ingestion task.

---

### What's next?

- The task will appear on the [tasks](https://console.runzero.com/tasks) page and run according to schedule.
- The integration will update existing assets or create new ones based on Kubernetes metadata.
- You can search for Kubernetes assets in runZero using:

  ```
  custom_integration:Kubernetes
  ```

- Use runZero's asset search to filter by node roles, pod namespaces, or other collected metadata.

---

🚀 **Your Kubernetes assets are now being ingested into runZero!** 🚀
