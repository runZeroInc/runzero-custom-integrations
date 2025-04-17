import os
import json
from datetime import datetime

# --- Config ---
BLOCK_LIST = {".github", "boilerplate", "LICENSE", "README.md"}
BASE_REPO_URL = "https://github.com/runZeroInc/runzero-custom-integrations/blob/main"

integration_details = []

for entry in os.listdir("."):
    if entry in BLOCK_LIST or not os.path.isdir(entry):
        continue

    folder_path = os.path.join(".", entry)
    readme_path = os.path.join(folder_path, "README.md")
    config_path = os.path.join(folder_path, "config.json")
    integration_file = None

    # Look for the first .star file
    for f in os.listdir(folder_path):
        if f.endswith(".star"):
            integration_file = f
            break

    # Skip if required files are missing
    if not (os.path.isfile(readme_path) and integration_file):
        continue

    # Defaults
    friendly_name = entry
    integration_type = "inbound"

    # Override with config.json if available
    if os.path.isfile(config_path):
        try:
            with open(config_path) as cf:
                config = json.load(cf)
                friendly_name = config.get("name", entry)
                integration_type = config.get("type", "inbound")
        except Exception as e:
            print(f"⚠️  Failed to read config.json in {entry}: {e}")

    integration_details.append(
        {
            "name": friendly_name,
            "type": integration_type,
            "readme": f"{BASE_REPO_URL}/{entry}/README.md",
            "integration": f"{BASE_REPO_URL}/{entry}/{integration_file}",
        }
    )

# --- Save JSON ---
output = {
    "lastUpdated": datetime.utcnow().isoformat() + "Z",
    "totalIntegrations": len(integration_details),
    "integrationDetails": integration_details,
}

with open("docs/integrations.json", "w") as f:
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
in_section = None

# Prepare the new sections
inbound_links = []
outbound_links = []

for integration in sorted(integration_details, key=lambda x: x["name"].lower()):
    link = (
        f"- [{integration['name']}]({integration['readme'].replace('/README.md', '/')})"
    )
    if integration["type"] == "outbound":
        outbound_links.append(link)
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
    elif stripped.startswith("## ") and (in_inbound_section or in_outbound_section):
        in_inbound_section = in_outbound_section = False

    if not in_inbound_section and not in_outbound_section:
        new_lines.append(line)

with open(readme_path, "w") as f:
    f.writelines(new_lines)

print("✅ README.md updated.")
