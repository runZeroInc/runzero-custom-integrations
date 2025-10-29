# runZero Custom Integration: Audit Events to Webhook

This custom integration for runZero exports audit events from your runZero account and sends them to a specified webhook. This allows you to integrate runZero's audit trail with other systems, such as a SIEM or a custom security monitoring tool.

## How it Works

The integration is a Starlark script that performs the following actions:

1.  **Fetches Audit Events:** The script queries the runZero API to retrieve audit events created in the last hour.
2.  **Formats Events:** The events are formatted as JSON.
3.  **Sends to Webhook:** The formatted events are sent to a pre-configured webhook URL via an HTTP POST request.

## Configuration

To use this integration, you will need to configure a new custom integration in your runZero account.

1.  **Create a new Custom Integration:** In your runZero console, navigate to `Account > Custom Integrations` and create a new custom integration.
2.  **Copy the Script:** Copy the contents of the `custom-integration-audit-events.star` file and paste it into the script editor for your new custom integration.
3.  **Set up Credentials:** The script requires the following credentials to be configured in the custom integration's `access_secret` field as a JSON object:

    *   `webhook_url`: The URL of the webhook to which the audit events will be sent.
    *   `rz_account_token`: A runZero account token.
    *   `external_api_key`: An *optional* bearer token for authenticating with the webhook endpoint.

    **Example JSON:**

    ```json
    {
      "webhook_url": "https://your-webhook-url.com/endpoint",
      "external_api_key": "your-bearer-auth-token",
      "rz_account_token": "your-runzero-export-token"
    }
    ```

4.  **Schedule the Integration:** Configure the integration to run on a schedule that meets your needs. The script is designed to fetch events from the last hour, so running it hourly is a good starting point.

## Script Details

The `custom-integration-audit-events.star` script is written in Starlark and uses the built-in `http` and `json` modules to interact with the runZero API and the destination webhook.

### `main` function

The `main` function is the entry point for the script. It retrieves the necessary credentials from the `access_secret`, fetches the latest audit events from the runZero API, and then calls the `send_events_to_webhook` function to send the events to the configured webhook.

### `send_events_to_webhook` function

This function takes a list of events, the webhook URL, and the authentication headers as input. It batches the events into groups of 500 and sends them to the webhook as a series of HTTP POST requests.
