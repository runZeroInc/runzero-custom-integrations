# runZero Custom Integration: Audit Events to Webhook

This custom integration for runZero exports audit events from your runZero account and sends them to a specified webhook. This allows you to integrate runZero's audit trail with other systems, such as a SIEM or a custom security monitoring tool.

It is an **outbound** integration (`"type": "outbound"`). It reads from runZero
and writes to somewhere else. It imports nothing, creates no assets, and
reports no vulnerabilities — `main` returns an empty list on every path,
including the successful one. Nothing will appear on the assets page as a
result of running it, and there is no `custom_integration:` search that finds
its output. The only evidence it worked is on the receiving end.

## How it Works

The integration is a Starlark script that performs the following actions:

1.  **Fetches Audit Events:** The script queries the runZero API to retrieve audit events created in the last hour.
2.  **Formats Events:** The events are formatted as JSON.
3.  **Sends to Webhook:** The formatted events are sent to a pre-configured webhook URL via an HTTP POST request.

Concretely, it issues one `GET` against
`{src_url}/api/v1.0/account/events.json` with the search `created:<1h` and an
`Authorization: Bearer` header carrying the runZero account token, then POSTs
the results to `dst_url` in batches of 500.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An **Account API token**. The Account API — everything under `/api/v1.0/account/`, which includes the system event log this integration reads — is not reachable with an organization token, an export token, or a download token. runZero documents the Account API as requiring a Platform license; on a Starter account the endpoint will not authorize.
- An Explorer with outbound network access to your webhook endpoint, and to the runZero console URL. On a self-hosted console, set `src_url` accordingly; it defaults to `https://console.runzero.com`.

## Destination requirements

There is no source product to configure here. The thing you have to prepare is
the **receiver**. Before configuring anything in runZero, know the following
about your destination:

- **It must accept an HTTP `POST` of newline-delimited JSON.** The body is one runZero event object per line, each terminated by `\n` — *not* a JSON array, and not a single event. The header says `Content-Type: application/json` even so, because receivers key their routing off it; a receiver that parses the whole body as one JSON document will fail on the second line. This is asserted by `tests/fixtures/happy.json`, which pins the `}\n{` separator, so the shape above is what the script sends rather than what it ought to send.
- **It must tolerate batching.** Events are sent 500 at a time, as several independent POSTs. A busy hour produces several requests; a quiet hour produces one, or one with an empty array. There is no batch header, no sequence number, and no completion marker, so a receiver that needs to know where a run ends has to infer it.
- **It must tolerate repeats.** The window is a fixed "created in the last hour" search, not a cursor. If the task is scheduled more often than hourly, or a run is retried, the same event is delivered again. Deduplicate on the event's own ID at the receiver.
- **Authentication, if any, must be a bearer token.** The optional `external_api_key` is sent verbatim as `Authorization: Bearer <value>`. There is no HMAC signature, no basic auth, no custom header name, and no shared-secret query parameter. A receiver that requires any of those cannot be used without editing the script.
- **TLS is verified by default.** The `tls_` options apply to *both* legs — the call to runZero and the call to your webhook — because a single TLS configuration is built and reused. You cannot relax verification for an internal webhook without also relaxing it for the console call.

Common destinations and what they need:

| Destination | What to create there | Notes |
|---|---|---|
| Splunk HTTP Event Collector | An HEC token and a data input | HEC expects `Authorization: Splunk <token>`, **not** `Bearer`. Front it with a proxy that rewrites the header, or use a different receiver. |
| Elastic / OpenSearch | An ingest endpoint or a Logstash `http` input | Set the `http` input's codec to `json_lines`; the default `plain` codec treats the whole batch as one event. |
| A generic SIEM webhook | The webhook URL and its bearer token | Confirm newline-delimited JSON is acceptable, not just a JSON array. |
| Your own service | Any endpoint that reads a line at a time | The simplest option, and the one this script was written against. |

### Creating the runZero account token

1. Sign in to the runZero console as a **superuser**. Only a superuser sees the account-level settings.
2. Go to the [Account settings page](https://console.runzero.com/account).
3. Use the **Generate API Key** button in the Account API keys section. runZero calls this an **Account API token**; the value is prefixed `CT`.
4. Copy the value. Treat it as a high-value secret — an account token carries read *and* write access to account-level endpoints, which is considerably more than this integration needs. runZero does not publish a narrower token type that can read the event log, so there is no least-privilege option to recommend here; scope it by rotating it rather than by restricting it.

If you run a self-hosted console, generate the token on your own console and
set `src_url` to that console's base URL.

## Configuration

To use this integration, you will need to configure a new custom integration in your runZero account.

1.  **Create a new Custom Integration:** In your runZero console, navigate to `Account > Custom Integrations` and create a new custom integration.
2.  **Copy the Script:** Copy the contents of the `audit-events-to-webhook.star` file and paste it into the script editor for your new custom integration.
3.  **Set up Credentials:** Create a `Custom Integration Script Secrets` credential with the following parameters:

    *   `src_url` — runZero source URL. Optional; defaults to `https://console.runzero.com`. Set it for a self-hosted console.
    *   `dst_url` — **required.** The URL of the webhook to which the audit events will be POSTed.
    *   `rz_account_token` — **required.** The Account API token from the previous section.
    *   `external_api_key` — *optional* bearer token for authenticating with the webhook endpoint.
    *   `tls_*` — optional TLS options. Applied to both the console call and the webhook call.

4.  **Schedule the Integration:** Configure the integration to run on a schedule that meets your needs. The script fetches events from the last hour, so running it **hourly** is not just a good starting point — it is the only schedule that neither drops events nor duplicates them. Running less often loses everything older than an hour; running more often re-sends.

### The legacy JSON credential

Earlier versions of this integration took a single JSON blob instead of named
parameters. That path still works, through the `legacy_credentials` parameter,
and is read only when the named parameter is absent:

```json
{
  "webhook_url": "https://your-webhook-url.com/endpoint",
  "external_api_key": "your-bearer-auth-token",
  "rz_account_token": "your-runzero-export-token"
}
```

Note that the legacy key is `webhook_url` while the current parameter is
`dst_url`; both are accepted, with `dst_url` winning. The legacy blob also
accepts `tls_disable_validation`, which has no equivalent named parameter — it
is the one thing the legacy path can express that the parameter form cannot.
New deployments should use the named parameters.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
prove the account token works and that your receiver accepts the body shape.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename audit-events-to-webhook/audit-events-to-webhook.star \
  --kwargs src_url=https://console.runzero.com \
  --kwargs rz_account_token=CT7f3a91c4e0b84d26a5c8f1e7d09b3a42 \
  --kwargs dst_url=https://siem.example.com/hooks/runzero-audit \
  --kwargs external_api_key=whk_2b6d40f9ac1e47f0 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./audit-webhook-run
```

**This run really sends.** Unlike the inbound integrations in this repository,
a command-line run here has an external side effect: it POSTs to `dst_url`.
Point it at a request-capture endpoint you control the first time, not at
production.

`--output` is close to useless for this integration — the script returns no
assets, so the directory is written but has nothing interesting in it. Use
`--verbose` instead; the request log is the only real feedback. The scanner
also refuses an `--output` directory that already exists unless `--overwrite`
is passed.

To check the `CONFIG` block and the HTTP and TLS wiring without touching either
the console or your webhook:

```bash
runzero script --filename audit-events-to-webhook/audit-events-to-webhook.star --validate
```

Validation generates placeholder parameter values and answers from a local
dummy server, so it proves the script initializes, declares its parameters
correctly, and issues a request. It does not prove the account token is valid,
that the event search returns anything, or that your webhook accepted a single
byte.

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat audit-events-to-webhook/audit-events-to-webhook.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'dst_url=https://siem.example.com/hooks/runzero-audit,rz_account_token=CT7f3a91c4e0b84d26a5c8f1e7d09b3a42' \
  --output ./audit-webhook-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a
value containing a comma cannot be passed this way — which matters here because
`legacy_credentials` is a JSON object and JSON is full of commas. The legacy
blob cannot be supplied through either CLI path; use named parameters on the
command line and keep the JSON form for the console credential.

## Script Details

The `audit-events-to-webhook.star` script is written in Starlark and uses the built-in `http` and `json` modules to interact with the runZero API and the destination webhook.

### `main` function

The `main` function is the entry point for the script. It resolves each setting from the named parameter first and the `legacy_credentials` JSON second, fetches the latest audit events from the runZero API, and then calls the `send_events_to_webhook` function to send the events to the configured webhook. It returns an empty list in every case: on a missing webhook URL, on a missing account token, on a failed fetch, and on success.

### `send_events_to_webhook` function

This function takes a list of events, the webhook URL, and the authentication headers as input. It batches the events into groups of 500 and sends them to the webhook as a series of HTTP POST requests.

## Asset identity

**This integration has no asset identity, because it creates no assets.**

- Target entity: none. `CONFIG["type"]` is `outbound`, the script never loads `runzero.types`, never constructs an `ImportAsset`, and never calls `report_assets`. `main` returns `[]` on every path, including success.
- Source ID field: not applicable. The runZero event objects it forwards carry their own ids, but they are passed through to the webhook verbatim and are never turned into a foreign id.
- Match behavior: not applicable. `matchBehavior` is a top-level `CONFIG` key governing how imported assets reconcile, and this integration imports none.
- Verdict: **not an identity-bearing integration.** Nothing merges, nothing forks, and no `custom_integration:` search returns anything as a result of running it. The section is recorded rather than omitted so that the absence is a stated finding rather than a gap in the documentation.

The corollary matters operationally: **deduplication is the receiver's job, not runZero's.** With no asset identity there is no merge step to collapse a repeated delivery, and the fixed `created:<1h` window re-sends every event when a run is retried or the schedule is tighter than hourly. Key on the event's own id at the destination.

## Future

- **A cursor instead of a fixed window — the one change worth making first.** The script issues a single `GET {src_url}/api/v1.0/account/events.json` with `search=created:<1h` and forwards whatever comes back. There is no paging and no high-water mark, so the delivery guarantee is neither at-least-once nor at-most-once: an hour that produces more events than one response carries is silently truncated, and an hour that is polled twice is duplicated. Recording the highest event timestamp seen and searching forward from it would make the feed incremental. **The blocker is that this integration has nowhere to keep that mark** — a custom integration script gets no persistent state between runs, so the high-water mark would have to be recovered from the destination (query the receiver for its newest runZero event) or accepted as an overlap-and-deduplicate design. That constraint is why the current script is written the way it is.
- **Narrow the search instead of forwarding everything.** `search` takes runZero's ordinary search syntax, so the fixed `created:<1h` could be composed with a filter supplied as a parameter — forwarding only credential and user-management events to a SIEM, for example, rather than every task start and finish. This is a one-line change in the script and the cheapest way to cut receiver volume; it is called out here because the parameter to expose it does not exist yet.
- **The account token is the least-privilege problem, and it may not be solvable.** The Account API requires an account-scoped token, which carries read *and* write across account-level endpoints — far more than reading an event log needs. Whether runZero publishes an organization-scoped equivalent of `events.json` that an Export API key could read **could not be determined** from this repository: the other integrations here reach runZero through `/api/v1.0/export/org/assets.json` and `/api/v1.0/export/org/vulnerabilities.json` with an export token, and through `/api/v1.0/org/tasks` and `/api/v1.0/org/assets/{id}/tags` with an organization token, but none of them reads an event log. If an org-scoped event endpoint exists, switching to it would be a strict security improvement.
- **Other runZero data this same pattern could stream.** The exporter shape here — read runZero, POST elsewhere — generalizes to endpoints already proven by other integrations in this repository: `/api/v1.0/org/tasks` and `/api/v1.0/org/tasks/{id}/data` would forward task outcomes and scan results to a pipeline, and `/api/v1.0/export/org/vulnerabilities.json` would push findings into a ticketing system. Each is a different destination contract, so each is a separate integration rather than a parameter on this one.
- **Richer destination authentication.** The webhook leg supports exactly one scheme: `Authorization: Bearer <external_api_key>`. Splunk HEC needs `Authorization: Splunk <token>`, AWS endpoints need SigV4, and most webhook receivers want an HMAC signature over the body so they can verify the sender rather than trust a static token. Supporting a configurable header name would cover Splunk and most SIEMs for the cost of one parameter; HMAC signing needs `crypto.hmac_sha256`, which is available to Starlark scripts here, plus a shared-secret parameter. Neither exists today, and the table above documents the workaround (a header-rewriting proxy) because of it.
- **Delivery failures are logged, not retried.** `send_events_to_webhook` prints the response code from each POST and moves on, so a receiver that answers `500` loses that batch permanently — the next run's window has already moved past it. The runZero-side fetch does get the shared helper's retry budget; the webhook POST uses raw `http.post`, which takes no `retries` argument at all, so it cannot opt in without being rewritten around a helper that can.
