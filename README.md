# runZero Custom Integrations

👋 Welcome to the runZero Custom Integration library!

runZero is a total attack surface and exposure management platform that combines [active scanning](https://help.runzero.com/docs/discovering-assets/), [passive discovery](https://help.runzero.com/docs/traffic-sampling/), and API integrations to deliver complete visibility into managed and unmanaged assets across IT, OT, IoT, cloud, mobile, and remote environments. runZero can be used as a hosted service (SaaS) or managed on-premise. The runZero stack consists of one more Consoles, linked Explorers that run as light-weight services on network points-of-presence, and a command-line tool that can be used for offline data collection. runZero can be managed through the web interface, via API, or for self-hosted customers, on the command line.

If you are not a runZero user today, [sign up](https://www.runzero.com/try) for a trial that can be converted to our free Community Edition.

This repository includes **custom integrations** that run in the context of a runZero Explorer. These integrations are written in Starlark, a language similar to Python.

To create a custom integration within runZero, you will need a user account with `superuser` privileges.

You can find detailed documentation about Starlark-based integrations on the [runZero help portal](https://help.runzero.com/docs/custom-integration-scripts/).

# Getting Help

If you need help setting up a custom integration, you can create an [issue](https://github.com/runZeroInc/runzero-custom-integrations/issues/new) on this GitHub repo, and our team will work with you. If you have a Customer Success Engineer, you can also work with them directly. 

# Existing Integrations 

## Import to runZero 
- [Akamai Guardicore Centra](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/akamai-guardicore-centra/)
- [Automox](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/automox/)
- [Bitsight](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/bitsight/)
- [Carbon Black](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/carbon-black/)
- [Cisco ISE](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/cisco-ise/)
- [Cortex XDR](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/cortex-xdr/)
- [Cyberint](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/cyberint/)
- [Device42](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/device42/)
- [Digital Ocean](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/digital-ocean/)
- [Drata](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/drata/)
- [exe.dev](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/exe-dev/)
- [Extreme Networks CloudIQ](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/extreme-cloud-iq/)
- [Ghost Security](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/ghost/)
- [Greenbone (GMP) Import](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/greenbone/)
- [Halcyon](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/halycon/)
- [Ivanti Neurons](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/ivanti_neurons/)
- [JAMF](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/jamf/)
- [Kandji](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/kandji/)
- [Kubernetes](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/kubernetes/)
- [LimaCharlie](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/lima-charlie/)
- [Linux via SSH](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/linux-ssh/)
- [ManageEngine Endpoint Central](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/manage-engine-endpoint-central/)
- [Maze](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/maze-security/)
- [Microsoft SQL Server databases](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/mssql-databases/)
- [Mosyle](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/moysle/)
- [Netskope](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/netskope/)
- [Nexthink](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/nexthink/)
- [NinjaOne](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/ninjaone/)
- [pfSense](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/pfsense/)
- [Proxmox](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/proxmox/)
- [runZero Task Sync](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/runzero-task-sync/)
- [Scale Computing](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/scale-computing/)
- [Snipe-IT](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/snipe-it/)
- [Snow License Manager](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/snow-license-manager/)
- [SolarWinds Information Service](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/solarwinds-information-service/)
- [Stairwell](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/stairwell/)
- [Tailscale](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/tailscale/)
- [Tanium](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/tanium/)
- [Ubiquiti UniFi Network](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/ubiquiti-unifi-network/)
- [Wazuh](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/wazuh/)
- [Windows SMB shares](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/windows-smb-shares/)
- [Windows WMI](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/windows-wmi/)
## Export from runZero 
- [Audit Log to Webhook](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/audit-events-to-webhook/)
- [Sumo Logic](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/sumo-logic/)
## Internal Integrations
- [Greenbone (GMP) Scan Launch](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/greenbone-scan/)
- [Scan Passive Assets](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/runzero-scan-passive-assets/)
- [Vulnerability Workflow](https://github.com/runZeroInc/runzero-custom-integrations/blob/main/runzero-vulnerability-workflow/)
## The boilerplate folder has examples to follow

1. Sample [README.md](./boilerplate/README.md) for contributing
2. Sample [script](./boilerplate/boilerplate.star) that shows how to use all of the supported libraries
3. Embedded `CONFIG` metadata in each script that gives context on the integration for automations to reference

## Create an integration with an AI coding agent

This repository includes the `/create-custom-integration` skill. Invoke it with
a vendor documentation link and a short statement of the data to import:

```text
/create-custom-integration https://vendor.example/api/docs -- import managed devices, network interfaces, OS details, and installed software
```

The workflow blocks implementation until it identifies whether the vendor's
foreign ID is stable, unique in a documented scope, and one-to-one with the
asset being imported. It does not permit random ID fallbacks that would create
duplicate assets on later polls.

## Asset IDs and match behavior

Asset reconciliation is configurable per imported record. runZero does not
automatically choose or rewrite a custom integration's identity policy; the
script author selects `matchBehavior` when the default is not appropriate.

Every `ImportAsset` you return needs an `id` value. runZero uses that
foreign id as the primary key when correlating subsequent runs of the
same integration with the asset graph, so the value you choose has a
direct impact on whether records merge cleanly, fork into duplicates,
or collapse two unrelated devices into one.

### Pick an id that is stable AND unique

A good foreign id is:

- **Stable across runs.** The same physical asset should produce the
  same id every time the script runs. Tomorrow's poll must agree with
  today's poll, even across reboots, IP changes, agent reinstalls,
  hostname renames, etc.
- **Unique across the dataset.** Two distinct assets must never share
  the same id. If the upstream API recycles ids when devices are
  decommissioned, namespace them (e.g. `vendor-{tenant}-{id}`).
- **Opaque.** Prefer vendor-issued UUIDs, serial numbers, or hardware
  ids over derived values like hostnames or IPs (those drift).

If the upstream source does not expose anything that meets both
criteria, that is the signal to relax matching (see below) — do
**not** invent a random id with `new_uuid()` per run, because the
same device will appear as a new asset on every poll.

### Tuning matching with `matchBehavior`

`ImportAsset` accepts an optional `matchBehavior` string. The default
behavior matches and breaks on all four dimensions (id, MAC, IP, name)
which is correct when the integration owns a strong id. When the id
is weak or absent, use one of the knobs below to tell the cruncher
which dimensions are unreliable for **matching** (finding the right
existing asset to merge into) and which are unreliable for
**breaking** (refusing a merge that would otherwise happen because
one dimension conflicts).

Flags:

| Flag             | Effect                                                                 |
|------------------|------------------------------------------------------------------------|
| `no-id-match`    | Do not use the foreign id to find candidate assets to merge with.      |
| `no-id-break`    | Allow a merge even when the foreign id differs from the existing asset.|
| `no-mac-match`   | Do not use MAC addresses to find merge candidates.                     |
| `no-mac-break`   | Allow a merge even when MAC addresses conflict.                        |
| `no-ip-match`    | Do not use IP addresses to find merge candidates.                      |
| `no-ip-break`    | Allow a merge even when IP addresses conflict.                         |
| `no-name-match`  | Do not use hostnames to find merge candidates.                         |
| `no-name-break`  | Allow a merge even when hostnames conflict.                            |

Combine flags with spaces. Recommended presets:

- **Strong, stable foreign id (most cloud / EDR / MDM APIs):** leave
  `matchBehavior` unset. The default uses every signal.

- **Strong id, but the source also reports churny MAC/IP/hostnames
  (e.g. ephemeral cloud workloads, VPN clients):**
  ```python
  matchBehavior="no-mac-break no-ip-break no-name-break"
  ```
  Keeps id-based merging authoritative, but stops drift in the other
  dimensions from blocking a legitimate merge.

- **No stable id at all (the source only emits per-run / ephemeral
  ids):**
  ```python
  matchBehavior="no-id-match no-id-break"
  ```
  Falls back to MAC / IP / name matching. Pair this with
  `id=new_uuid()` or `id="vendor-" + hashlib.sha256(stable_attrs)` so
  the row still has a unique key but the cruncher ignores it for
  correlation.

- **Two-stage enrichment where one integration owns "identity" and
  another only contributes attributes:** use `no-id-match no-id-break`
  on the enrichment-only integration so it always merges into the
  primary asset by MAC/IP/name rather than creating a parallel record.

A short rule of thumb: if the upstream id is **not both stable and
unique**, you must relax id matching. If MAC / IP / hostname are
known to be unreliable for this data source, relax the corresponding
`-break` flags so a conflict on those fields doesn't fragment one
real asset into many.

## Contributing

We welcome contributions to this repository! Whether you're fixing a bug, adding a new feature, or improving documentation, your efforts make a difference. To ensure a smooth process, please follow these guidelines:

1. **Fork the Repository**: Start by forking this repository to your GitHub account.

2. **Create a Branch**: Create a feature branch for your changes. Use a descriptive name like `feature/new-integration` or `fix/bug-description`.

3. **Make Your Changes**: Implement your changes and test thoroughly. Ensure your code adheres to our coding standards and is well-documented.

4. **Commit Your Changes**: Write clear and concise commit messages that describe what you changed and why.

5. **Open a Pull Request (PR)**: 
   - Go to the original repository and open a pull request from your fork.
   - Provide a detailed description of your changes, including the problem your contribution solves and how it was tested.

6. **Code Review**: Collaborate with the maintainers during the review process. Be open to feedback and iterate on your changes if necessary.

7. **Merge**: Once approved, your PR will be merged by a maintainer.

## Authoring with external LLM tools

External tools such as Gemini CLI, OpenAI Codex, and Claude Code can help draft integrations. runZero does not run an LLM in the Console, Explorer, or integration sandbox. These tools produce source that must pass the same review and validation as hand-written `.star` files.

There is an [AGENTS.md](./AGENTS.md) file to give your LLM of choice best practices and guidance will building the integrations. 

Existing v1 integrations remain supported. See the [v1 to v2 migration guide](./docs/migration-v1-to-v2.md) when moving metadata into `CONFIG`, adopting standard helpers, streaming assets, or tuning match behavior.

---

## License

This repository is licensed under the [MIT License](./LICENSE). By contributing to this project, you agree that your contributions will be licensed under the same terms.
