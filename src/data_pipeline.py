from mitreattack.stix20 import MitreAttackData
import requests
import json
import os
import re

def download_mitre_data():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    filepath = "data/mitre/enterprise-attack.json"
    os.makedirs("data/mitre", exist_ok=True)

    if os.path.exists(filepath):
        print("MITRE data already downloaded. Skipping.")
        return filepath

    print("Downloading MITRE ATT&CK data (~80MB, please wait)...")
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with open(filepath, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    print("Download complete.")
    return filepath

def clean_text(text):
    """
    Removes markdown links and citation markers from MITRE descriptions.
    Example: [APT28](https://attack.mitre.org/groups/G0007) -> APT28
    """
   
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    
    text = re.sub(r'\(Citation:[^\)]+\)', '', text)
    
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def load_mitre_data(filepath):
    print("Loading MITRE ATT&CK data...")
    mitre = MitreAttackData(filepath)
    print("Loaded successfully.")
    return mitre

def extract_groups(mitre):
    groups = mitre.get_groups()
    group_list = []

    for group in groups:
        entry = {
            "id": group.get("id", ""),
            "name": group.get("name", ""),
            "aliases": group.get("aliases", []),
            "description": clean_text(group.get("description", "")),
        }
        group_list.append(entry)

    print(f"Extracted {len(group_list)} threat actor groups.")
    return group_list

def extract_group_ttps(mitre, groups):
    """
    For each group, extracts ATT&CK techniques using the
    correct object structure returned by the library.
    Each technique entry has 'object' and 'relationships' keys.
    """
    print("Extracting TTPs for each group...")

    for group in groups:
        group_stix_id = group["id"]
        ttp_list = []

        try:
            techniques = mitre.get_techniques_used_by_group(group_stix_id)

            for entry in techniques:
             
                technique = entry.get("object", {})

              
                technique_id = ""
                ext_refs = technique.get("external_references", [])
                for ref in ext_refs:
                    if ref.get("source_name") == "mitre-attack":
                        technique_id = ref.get("external_id", "")
                        break

              
                technique_name = technique.get("name", "")

              
                tactics = [
                    phase.get("phase_name", "")
                    for phase in technique.get("kill_chain_phases", [])
                ]

              
                description = clean_text(technique.get("description", ""))

                if technique_id:
                    ttp_list.append({
                        "technique_id": technique_id,
                        "technique_name": technique_name,
                        "tactics": tactics,
                        "description": description[:300]  # First 300 chars only
                    })

        except Exception as e:
            print(f"Error processing {group['name']}: {e}")

        group["ttps"] = ttp_list
        group["ttp_count"] = len(ttp_list)

    groups_with_ttps = [g for g in groups if g["ttp_count"] > 0]
    print(f"TTP extraction complete.")
    print(f"Groups with TTPs: {len(groups_with_ttps)} out of {len(groups)}")
    return groups

if __name__ == "__main__":
    filepath = download_mitre_data()
    mitre = load_mitre_data(filepath)
    groups = extract_groups(mitre)
    groups = extract_group_ttps(mitre, groups)

    # Save enriched data
    with open("data/mitre/groups.json", "w") as f:
        json.dump(groups, f, indent=2)

    print("Saved to data/mitre/groups.json")

    # Show a sample
    sample = next(g for g in groups if g["ttp_count"] > 0)
    print(f"\nSample group: {sample['name']}")
    print(f"TTPs: {sample['ttp_count']}")
    print(f"First TTP: {sample['ttps'][0]['technique_id']} - {sample['ttps'][0]['technique_name']}")
    print(f"Tactics: {sample['ttps'][0]['tactics']}")