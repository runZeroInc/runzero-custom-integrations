import os
import json
import ast
from datetime import datetime, timezone

# --- Config ---
BLOCK_LIST = {".github", "boilerplate", "docs", "scripts", "LICENSE", "README.md"}
BASE_REPO_URL = "https://github.com/runZeroInc/runzero-custom-integrations/blob/main"

integration_details = []

OPTION_SET_IDENTIFIERS = {"OPTIONS_TLS", "OPTIONS_HTTP"}


def find_matching_brace(text, open_idx):
    depth = 0
    quote = None
    escape = False
    comment = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        # A `#` comment runs to the end of the line, and an apostrophe inside one
        # ("the account's handle") is prose, not the start of a string literal.
        # Without this the scan would treat the rest of the file as one string,
        # never find the closing brace, and silently drop the integration's
        # metadata from the catalog.
        if comment:
            if ch == "\n":
                comment = False
            continue
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch == "#":
            comment = True
        elif ch in {"'", '"'}:
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def load_embedded_config(script_path):
    with open(script_path) as sf:
        text = sf.read()

    marker = "CONFIG"
    marker_idx = text.find(marker)
    if marker_idx == -1:
        return {}
    equals_idx = text.find("=", marker_idx + len(marker))
    open_idx = text.find("{", equals_idx)
    if equals_idx == -1 or open_idx == -1:
        return {}
    close_idx = find_matching_brace(text, open_idx)
    if close_idx == -1:
        return {}

    literal = text[open_idx : close_idx + 1]
    for identifier in OPTION_SET_IDENTIFIERS:
        literal = literal.replace(identifier, repr(identifier))
    return ast.literal_eval(literal)

for entry in sorted(os.listdir(".")):
    if entry in BLOCK_LIST or not os.path.isdir(entry):
        continue

    folder_path = os.path.join(".", entry)
    readme_path = os.path.join(folder_path, "README.md")
    integration_files = sorted(f for f in os.listdir(folder_path) if f.endswith(".star"))
    # A directory may contain multiple API versions. Prefer the latest filename
    # deterministically until each version has its own catalog entry.
    integration_file = integration_files[-1] if integration_files else None

    # Skip if required files are missing
    if not (os.path.isfile(readme_path) and integration_file):
        continue

    # Defaults
    friendly_name = entry
    integration_type = "inbound"
    maturity = "alpha"

    try:
        config = load_embedded_config(os.path.join(folder_path, integration_file))
        friendly_name = config.get("name", entry)
        integration_type = config.get("type", "inbound")
        # Absent maturity means the script predates the field; treat it as the
        # least-proven value rather than implying a promotion nobody made.
        maturity = str(config.get("maturity", "alpha")).lower()
    except Exception as e:
        print(f"⚠️  Failed to read embedded CONFIG in {entry}: {e}")

    if not integration_type:
        integration_type = "inbound"
    integration_type = str(integration_type).lower()

    if integration_type not in {"inbound", "outbound", "internal"}:
        print(
            f"⚠️  Unknown integration type '{integration_type}' in {entry}, defaulting to inbound."
        )
        integration_type = "inbound"

    if maturity not in {"alpha", "beta", "stable"}:
        print(
            f"⚠️  Unknown maturity '{maturity}' in {entry}, defaulting to alpha."
        )
        maturity = "alpha"

    integration_details.append(
        {
            "name": friendly_name,
            "type": integration_type,
            "maturity": maturity,
            "readme": f"{BASE_REPO_URL}/{entry}/README.md",
            "integration": f"{BASE_REPO_URL}/{entry}/{integration_file}",
        }
    )

# --- Save JSON ---
integration_details.sort(key=lambda item: (item["name"].lower(), item["integration"]))
output_path = "docs/integrations.json"
previous = {}
try:
    with open(output_path) as f:
        previous = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

unchanged = previous.get("integrationDetails") == integration_details
output = {
    "lastUpdated": previous.get("lastUpdated") if unchanged else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "totalIntegrations": len(integration_details),
    "integrationDetails": integration_details,
}

with open(output_path, "w") as f:
    json.dump(output, f, indent=2)

print("✅ integrations.json created.")

# --- Update README.md ---
readme_path = "README.md"

try:
    with open(readme_path, "r") as f:
        lines = f.readlines()
except FileNotFoundError:
    print("❌ README.md not found.")
    exit(1)

new_lines = []
in_inbound_section = False
in_outbound_section = False
in_internal_section = False

# Prepare the new sections
inbound_links = []
outbound_links = []
internal_links = []

for integration in sorted(integration_details, key=lambda x: x["name"].lower()):
    link = (
        f"- [{integration['name']}]({integration['readme'].replace('/README.md', '/')})"
    )
    if integration["type"] == "outbound":
        outbound_links.append(link)
    elif integration["type"] == "internal":
        internal_links.append(link)
    else:
        inbound_links.append(link)

# Rewrite README content
for line in lines:
    stripped = line.strip()
    if stripped == "## Import to runZero":
        new_lines.append(line)
        new_lines.extend([f"{link}\n" for link in inbound_links])
        in_inbound_section = True
        continue
    elif stripped == "## Export from runZero":
        new_lines.append(line)
        new_lines.extend([f"{link}\n" for link in outbound_links])
        in_outbound_section = True
        continue
    elif stripped == "## Internal Integrations":
        new_lines.append(line)
        new_lines.extend([f"{link}\n" for link in internal_links])
        in_internal_section = True
        continue
    elif stripped.startswith("## ") and (
        in_inbound_section or in_outbound_section or in_internal_section
    ):
        in_inbound_section = in_outbound_section = in_internal_section = False

    if not in_inbound_section and not in_outbound_section and not in_internal_section:
        new_lines.append(line)

with open(readme_path, "w") as f:
    f.writelines(new_lines)

print("✅ README.md updated.")
