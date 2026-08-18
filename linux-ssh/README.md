# Linux via SSH

Inbound integration that authenticates to a Linux/Unix host over SSH,
collects basic identification facts, and reports the system as a single
runZero asset.

This is not an HTTP integration. There is no API, no token, and no vendor
console — the credential is an ordinary SSH login, and the setup work is the
same work you would do to give any automation account shell access.

## runZero requirements

- Superuser access to the [Custom Integrations configuration](https://console.runzero.com/custom-integrations) in runZero.
- An Explorer that can reach the target host on its SSH port (22 by default).

## What it collects

- Fully qualified hostname (`hostname -f`)
- OS distribution and version (`/etc/os-release`)
- Kernel release (`uname -r`)
- `/etc/machine-id` for stable asset identity
- IPv4 / IPv6 addresses and MAC addresses for every interface
  reported by `ip link` / `ip addr`
- SMBIOS chassis type (`/sys/class/dmi/id/chassis_type`, falling back to
  `dmidecode -s chassis-type`), which sets the asset's **device type**

The chassis type is the only form-factor signal a Linux host offers, and the
sysfs file is preferred because it is world-readable and needs no root. Values
that name a form factor become **Desktop**, **Laptop**, **Tablet**, or
**Server**; "Other" and "Unknown" — which is what most virtual machines and ARM
boards report — leave the device type unset so runZero's own fingerprinting
decides, as does a host with no DMI table at all. The raw value is kept as the
`chassis_type` custom attribute so you can see why a host was or was not typed.

## Authentication

Provide **either** a password **or** an OpenSSH private key (PEM format).
You may also supply a passphrase for an encrypted key.

The `host_key` field accepts the server's public key in
`authorized_keys` format (e.g. `ssh-ed25519 AAAA…`). When supplied, the
script pins the host key and refuses to connect to any other key. If
left blank, the host key is not verified — only use that mode in
trusted networks where the SSH endpoint identity is otherwise enforced.

## Required tools on the target

- `bash`, `cat`, `hostname`, `uname`
- `ip` (from `iproute2`) for interface enumeration

If the target image does not provide `iproute2`, the network interfaces
list will be empty but the asset will still be reported.

`dmidecode` is optional. It is only consulted when
`/sys/class/dmi/id/chassis_type` is absent, and it reads `/dev/mem`, so it
needs root; without it a host that exposes no sysfs DMI simply reports no
chassis type.

## Steps

### Linux target configuration

Every command this integration runs is a read: `hostname -f`, `uname -r`,
`cat /etc/os-release`, `cat /etc/machine-id`, and `ip link` / `ip addr`. None
of them need root, and none of them need `sudo`. Give the account the least
privilege that gets a shell.

1. **Create an unprivileged account on each target.** A dedicated account is
   better than reusing a person's login, because the key you are about to
   install is stored in the runZero credential and rotating a shared human
   account is painful.

   ```bash
   sudo useradd --create-home --shell /bin/bash runzero
   ```

   Do not add it to `sudo`, `wheel`, or any admin group. Nothing here
   escalates.

2. **Generate a dedicated key pair** on a machine you control — not on the
   target. Ed25519 keys are shorter and are accepted by every OpenSSH release
   that is still supported.

   ```bash
   ssh-keygen -t ed25519 -C "runzero-linux-ssh" -f ~/.ssh/runzero_linux
   ```

   Leave the passphrase empty, or set one and put it in the
   `private_key_passphrase` parameter. An unattended integration cannot be
   prompted, so the passphrase has to be stored either way; the only thing it
   buys you is that the key file alone is not enough.

3. **Install the public key** on each target:

   ```bash
   ssh-copy-id -i ~/.ssh/runzero_linux.pub runzero@target.example.com
   ```

   Or append `~/.ssh/runzero_linux.pub` to `/home/runzero/.ssh/authorized_keys`
   by hand, with mode `600` on the file and `700` on the directory.

4. **Optionally restrict what the key may do.** OpenSSH lets you prefix the
   `authorized_keys` entry with restrictions, which is worth doing because
   this integration never needs a TTY, a port forward, or an X11 channel:

   ```
   restrict,from="10.10.0.5" ssh-ed25519 AAAA… runzero-linux-ssh
   ```

   `restrict` implies `no-port-forwarding`, `no-agent-forwarding`,
   `no-X11-forwarding`, `no-pty`, and `no-user-rc`. Set `from=` to the
   Explorer's address. Do **not** add a `command=` restriction: the
   integration runs several different commands over one session and a forced
   command would break all of them.

   The private key you feed to the integration is the matching
   `~/.ssh/runzero_linux` file, complete with its
   `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END` lines. Paste the whole
   file.

5. **Capture the host key.** This integration does not read a `known_hosts`
   file and has no trust-on-first-use cache — the `host_key` parameter is the
   entire host-verification story, and leaving it blank means the connection
   is unauthenticated in the server-to-client direction. Read the key from the
   target's own console, where you can trust it:

   ```bash
   # on the target
   ssh-keyscan -t ed25519 localhost | cut -d' ' -f2-
   # or, without the network at all:
   cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Paste the result — the `ssh-ed25519 AAAA…` pair, with or without the
   trailing comment — into `host_key`. Reading it with `ssh-keyscan` from the
   Explorer instead is convenient and proves nothing: an attacker who can
   answer that scan can answer the integration's connection too.

   Because the pin is a single key, one credential covers one host. This
   integration takes one `host` per run by design.

6. **Confirm the login from the Explorer host** before configuring anything in
   runZero:

   ```bash
   ssh -i ~/.ssh/runzero_linux -o IdentitiesOnly=yes runzero@target.example.com \
     'hostname -f; uname -r; cat /etc/machine-id; ip -o addr'
   ```

   If `/etc/machine-id` is empty or missing, the asset falls back to a
   `<username>@<host>` identity, which is an address and moves when the address
   does. `systemd-machine-id-setup` populates it on a systemd host;
   `/var/lib/dbus/machine-id` is read as a fallback.

### runZero configuration

1. [Create the Custom Integration](https://console.runzero.com/custom-integrations/new).
   - Add a Name and Icon for the integration (e.g., "Linux via SSH").
   - Toggle `Enable custom integration script` to input the finalized script.
   - Click `Validate` to ensure it has valid syntax.
   - Click `Save` to create the Custom Integration.
2. [Create the Credential for the Custom Integration](https://console.runzero.com/credentials).
   - Select the type `Custom Integration Script Secrets`.
   - **Target host** (`host`): hostname or address of the system to collect.
   - **SSH port** (`port`): optional, default 22.
   - **Username** (`username`): the unprivileged account created above.
   - **Password** (`password`): only if you are not using a key.
   - **Private key (PEM)** (`private_key`): the full private key file, including the BEGIN and END lines.
   - **Private key passphrase** (`private_key_passphrase`): only if the key is encrypted.
   - **Expected host public key** (`host_key`): the target's public host key in `authorized_keys` format. Strongly recommended.
   - **Connection timeout (seconds)** (`timeout`): optional, default 30.
3. [Create the Custom Integration task](https://console.runzero.com/ingest/custom/).
   - Select the Credential and Custom Integration created in steps 1 and 2.
   - Update the task schedule to recur at the desired timeframes.
   - Select the Explorer you would like the Custom Integration to run from. It must be able to reach the target on the SSH port.
   - Click `Save` to kick off the first task.

### Running it from the command line

The runZero Explorer binary runs a script directly, which is the fastest way to
confirm a key and see what the host reports before scheduling anything.
`--kwargs` is repeated once per parameter:

```bash
runzero script --filename linux-ssh/linux-ssh.star \
  --kwargs host=target.example.com \
  --kwargs port=22 \
  --kwargs username=runzero \
  --kwargs private_key="$(cat ~/.ssh/runzero_linux)" \
  --kwargs host_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExAmPLefAkEhOsTkEy0000000000000000000' \
  --kwargs timeout=30 \
  --custom-integration-id 1f2e3d4c-5b6a-7988-9a0b-1c2d3e4f5a6b \
  --output ./linux-ssh-run
```

`--output` writes the asset the run produced, and `--overwrite` replaces a
directory from a previous run — the scanner refuses an `--output` directory that
already exists otherwise. Add `--verbose` for the command-by-command log. Omit
`--output` to see only the log lines.

Two things about `--kwargs` and this integration in particular:

- **A multi-line private key is awkward on a command line.** Command
  substitution as shown above works in `bash` and `zsh`. If your shell mangles
  it, use `password=` for the ad-hoc test and configure the key through the
  console credential form for the real task.
- **`--kwargs` only splits on commas when the value also contains a second
  `=`.** With exactly one `=` in the whole argument the value is passed
  verbatim, commas included. That is worth knowing here because a PEM private
  key is full of base64 `=` padding, which *does* flip the flag into
  comma-separated parsing — but a PEM body contains no commas, so it still
  arrives intact as a single field. The damage case is a value carrying both
  characters, which is cut at the first comma; the remainder either becomes a
  fabricated second parameter or aborts the run with `must be formatted as
  key=value`. A password containing both needs a second pair of quotes around
  the whole argument, or configure it through the console instead.

To check that the `CONFIG` block compiles and the parameters are declared
correctly:

```bash
runzero script --filename linux-ssh/linux-ssh.star --validate
```

This integration declares `"validationMode": "compile"` because it speaks SSH,
not HTTP, so there is no request for the local dummy server to answer.
Validation proves the script loads and its parameters are well formed. It does
not open a connection, does not test the credential, and never parses a real
host.

The same script also runs under the `scan` command, which is what the platform
itself invokes for a scheduled task:

```bash
runzero scan --custom-integration-script-source "$(cat linux-ssh/linux-ssh.star)" \
  --custom-integration-id <uuid-from-the-console> \
  --custom-integration-script-kwargs 'host=target.example.com,username=runzero,password=<password>' \
  --output ./linux-ssh-scan
```

`--custom-integration-id` is the UUID the console shows on the integration's
page. `--custom-integration-entry-function-name` defaults to `main`. Note that
`--custom-integration-script-kwargs` takes one comma-separated string, so a PEM
private key — which contains newlines — is not practical to pass this way at
all; use `script --kwargs` for ad-hoc runs and the console credential for real
ones.

### What's next?

- You will see the task kick off on the [tasks](https://console.runzero.com/tasks) page like any other integration.
- The task will update an existing asset when the machine ID, MAC, or hostname matches one runZero already knows.
- The task will create a new asset when nothing meets merge criteria.
- You can search for assets enriched by this custom integration with the runZero search `custom_integration:linux-ssh`.
- The collected kernel release and machine ID are searchable as the custom attributes `kernel` and `machine_id`, the SMBIOS chassis type as `chassis_type`, and the connection target as `ssh.target`.

## Asset identity

- Target entity: **one Linux or Unix host**, reached over SSH. Exactly one asset is produced per run, because exactly one host is configured.
- Source ID field: the contents of `/etc/machine-id`, falling back to `/var/lib/dbus/machine-id`, falling back to the composed value `<username>@<host>`.
- Documentation evidence: `machine-id` is specified by systemd as a 128-bit host identifier, generated at first boot and intended to stay constant for the lifetime of the installation — the same value `hostnamectl` reports as the Machine ID. It is the closest thing a Linux host has to a durable identity that survives renaming and re-addressing, and it needs no privilege to read.
- Uniqueness scope: intended to be globally unique, since it is generated randomly at install time rather than assigned by a registry. **The composed fallback has no such property** — see below.
- Cardinality: one asset per run, by construction.
- Stability: survives rename, address change, reboot, kernel and distribution upgrade. It does **not** survive a reinstall of the operating system, which generates a new one.
- **The known failure mode is cloning, and it is common enough to plan for.** A machine deployed from a golden image, a VM template, or a container image carries the *same* `machine-id` as its source unless the file was truncated before capture — this is the single most frequent cause of duplicate machine IDs in the wild, and it is why cloud-init and most image-preparation guides truncate `/etc/machine-id` explicitly. Every clone that keeps it therefore composes the **same foreign id**, and because `matchBehavior` is left at the default those hosts merge onto **one** runZero asset. A foreign-id match can never be vetoed by a conflicting MAC, hostname, or address, so no `no-*-break` flag prevents this. If a set of hosts is collapsing onto a single asset, compare their `machine_id` custom attribute values first — the value is imported precisely so this is diagnosable.
- **The `<username>@<host>` fallback is address-derived and much weaker.** It fires when neither machine-id file is readable, which is normal on non-systemd systems, on minimal container images, and on non-Linux Unix. Two different machines reached at the same DNS name at different times — a rebuilt server, a DHCP name, a NAT'd jump target — compose the same id, and the same machine reached by two different credentials composes two ids. It also changes if the target is reconfigured from an address to a name, or the username is changed.
- Reuse behavior: none for machine-id; guaranteed for the fallback, as described.
- Presence: `machine-id` is present on any systemd-based distribution. The fallback means there is never a missing id and never a skip path.
- Final runZero ID: the raw machine-id string, or `<username>@<host>`.
- Missing-ID behavior: not applicable; the fallback always produces a value.
- Match behavior: **not set** — the platform default, all match and break dimensions on.
- Verdict: **authoritative for an operating-system installation, with the cloning caveat above; not authoritative when the fallback fires.** The default setting is right for the machine-id case and wrong for the fallback case, and one flag set cannot express both — which is an argument for detecting the fallback and declining to use it for matching, not for changing `matchBehavior` globally.

This asset also carries the real hardware correlation signals that the identity does not depend on: a network interface per adapter, each with its own MAC and its own addresses, parsed from `ip link` and `ip addr`. Those are what merge this host with what runZero discovers by scanning, and they are per-interface rather than pooled — a genuine improvement over the sources in this repository that publish one flattened address list.

## Future

There is no vendor API here — the "API" is a shell on the target, so everything below is a command that could be run and a mapping for what it returns. The constraint is not what is reachable but what can be justified: each addition is another command executed on a production host by an automation account.

- **One host per credential is the limiting design decision.** `CONFIG` declares a single `host`, so an estate of five hundred Linux servers needs five hundred credentials and five hundred tasks. That is the first thing to change, and there are two shapes for it: a list of targets as a parameter, or — following the pattern `greenbone-scan/` already uses — reading the target list from runZero itself through `/api/v1.0/export/org/assets.csv` with a search filter, so the collector follows runZero's own discovery. The second is strictly better, because it means newly discovered Linux hosts are collected without anyone editing a credential.
- **Installed packages as `Software` records.** `dpkg-query -W -f='${Package}\t${Version}\n'`, `rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'`, and `apk info -v` cover the common distributions and need no privilege. This is the single largest gap: a package inventory is the main thing an authenticated collector can produce that a network scan cannot, and it is what makes patch-state questions answerable.
- **Listening sockets as `Service` records.** `ss -tlnp` (or `ss -tln` without privilege, losing the process name) enumerates what the host is actually listening on, including services bound to loopback or to interfaces an Explorer cannot reach. That is genuinely complementary to runZero's own scanning rather than duplicative of it.
- **Hardware identity without root.** `/sys/class/dmi/id/sys_vendor`, `product_name`, and `product_serial` are readable alongside the `chassis_type` file this integration already uses, and would populate the asset's manufacturer, model, and serial. `product_uuid` is root-only, so it is not a candidate for identity here — but `sys_vendor` and `product_name` are free, and a serial number is the field most likely to reconcile this host against a CMDB entry.
- **Distinguish physical, virtual, and container — which is also how the cloning hazard gets managed.** `systemd-detect-virt` reports the hypervisor or container runtime, and it is exactly the signal that says "this machine-id is likely to be shared with its siblings". Collected as an attribute it makes the duplicate-identity case diagnosable in advance rather than after the assets have already merged.
- **Security posture.** `getenforce` for SELinux, `aa-status` for AppArmor, the firewall's rule count, and `sshd -T` for the effective SSH configuration are all cheap, read-only, and directly answer questions a network scan can only guess at. Modelled as tags they make "every Linux host on this segment with password authentication enabled" a runZero search.
- **Users and access.** `getent passwd` for local accounts, `who` for current sessions, and the authorized-keys files for who can log in. This is where the privilege and privacy trade-offs start to bite, so it belongs behind an explicit opt-in rather than in the default collection.
- **`Vulnerability` records are not directly producible, and this is worth stating plainly.** A Linux host publishes no CVE feed about itself. What a package inventory plus the distribution and version gives you is the *join key* against the distribution's own security data — which is a separate lookup service, not something this collector can do on its own. Anything claiming otherwise would be inventing findings.
- **Non-Linux Unix is unsupported in practice.** Interface enumeration depends on `ip` from `iproute2`, so BSD, Solaris, and macOS targets connect, authenticate, report a hostname and kernel, and then contribute **no network interfaces at all** — which for those hosts also means falling back to the `<username>@<host>` identity described above, since they have no `/etc/machine-id` either. An `ifconfig` fallback would fix both problems at once.
- **There is no privilege escalation and no `sudo` handling**, which is a deliberate and correct default: every command this integration runs works as an unprivileged user. Any future addition should be held to the same standard, and anything that genuinely needs root should be opt-in and separately documented rather than quietly widening what the automation account must be allowed to do.
