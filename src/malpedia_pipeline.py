from mitreattack.stix20 import MitreAttackData
import json
import os
import re

def clean_text(text):
    text = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', text)
    text = re.sub(r'\(Citation:[^\)]+\)', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def build_malware_actor_mapping():
   
    print("Loading MITRE ATT&CK data...")
    mitre = MitreAttackData("data/mitre/enterprise-attack.json")

    print("Extracting software entries...")
    software_list = mitre.get_software()

    print(f"Found {len(software_list)} software entries.")

    malware_actor_index = {}
    software_profiles = []

    for software in software_list:
        
        name = software.get("name", "")
        aliases = software.get("x_mitre_aliases", [])
        description = clean_text(software.get("description", ""))
        software_type = software.get("x_mitre_type", "")
        stix_id = software.get("id", "")

        
        try:
            groups = mitre.get_groups_using_software(stix_id)
            actor_names = []

            for entry in groups:
                group = entry.get("object", {})
                group_name = group.get("name", "")
                if group_name:
                    actor_names.append(group_name)

        except Exception:
            actor_names = []

        # Build profile
        profile = {
            "name": name,
            "aliases": aliases,
            "type": software_type,
            "description": description[:300],
            "actors": actor_names,
            "source": "MITRE ATT&CK"
        }
        software_profiles.append(profile)

       
        if actor_names:
            # Index by primary name
            if name:
                malware_actor_index[name.lower().strip()] = actor_names

            # Index by all aliases
            for alias in aliases:
                if alias and alias.lower() != name.lower():
                    malware_actor_index[alias.lower().strip()] = actor_names

    return malware_actor_index, software_profiles

if __name__ == "__main__":
    os.makedirs("data/malpedia", exist_ok=True)

    malware_actor_index, software_profiles = build_malware_actor_mapping()

    # Save full software profiles
    with open("data/malpedia/software_profiles.json", "w") as f:
        json.dump(software_profiles, f, indent=2)

    # Save malware-actor index
    with open("data/malpedia/malware_actor_index.json", "w") as f:
        json.dump(malware_actor_index, f, indent=2)

    print(f"\nMalware-actor index: {len(malware_actor_index)} entries")
    print(f"Software profiles: {len(software_profiles)} total")

    # Show stats
    with_actors = [s for s in software_profiles if s["actors"]]
    print(f"Software with actor associations: {len(with_actors)}")

    # Show some examples
    print("\nSample mappings:")
    count = 0
    for name, actors in malware_actor_index.items():
        if count >= 5:
            break
        print(f"  {name} → {actors}")
        count += 1

    # Verify specific tools
    print("\nVerification checks:")
    checks = ["masepie", "steelhook", "x-agent", "mimikatz",
              "cobalt strike", "wannacry"]
    for tool in checks:
        actors = malware_actor_index.get(tool, [])
        print(f"  {tool} → {actors if actors else 'not found'}")