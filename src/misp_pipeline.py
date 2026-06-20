#Pull and structure MISP Galaxy threat actor data

import requests
import json
import os

print("Script started")

def download_misp_galaxy():
    """Downloads MISP Galaxy threat actor cluster"""

    url="https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
    filepath="data/misp/threat-actor.json"

    os.makedirs("data/misp", exist_ok=True)

    if os.path.exists(filepath):
        print("MISP Galaxy data already downloaded. Skipping")
        return filepath
    
    print("Downloading MISP Galaxy threat actor data..")
    response=requests.get(url, stream=True)
    response.raise_for_status()

    with open(filepath, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)

    
    print("Download Complete")
    return filepath

def parse_misp_galaxy(filepath):
    """Parses MISP Galaxy threat actor cluster.
    Returns list of actor dictionaries"""

    with open(filepath, "r", encoding="utf-8") as f:
        data=json.load(f)
    
    actors=[]
    values=data.get("values", [])
    for entry in values:
        meta=entry.get("meta", {})
        actor = {
            "name": entry.get("value", ""),
            "description": entry.get("description", ""),
            "aliases": meta.get("synonyms", []),
            "country": meta.get("country", ""),
            "motivation": meta.get("cfr-suspected-state-sponsor", ""),
            "target_sectors": meta.get("cfr-target-category", []),
            "target_countries": meta.get("cfr-suspected-victims", []),
            "first_seen": meta.get("first-seen", ""),
            "last_seen": meta.get("last-seen", ""),
            "source": "MISP Galaxy"
        }

        actors.append(actor)

    print(f"Prsed {len(actors)} actors from MISP Galaxy")
    return actors
    
if __name__=="__main__":
    filepath=download_misp_galaxy()
    actors=parse_misp_galaxy(filepath)

    os.makedirs("data/misp", exist_ok=True)
    with open("data/misp/actors.json", "w") as f:
        json.dump(actors, f, indent=2)

    print("Saved to data/misp/actors.json")
    print(f"\nSample actor: {actors[0]['name']}")
    print(f"Aliases: {actors[0]['aliases']}")
    print(f"Country: {actors[0]['country']}")
    print(f"Target sectors: {actors[0]['target_sectors']}")