#Pull and Structure ETDA Threat Group Cards data

import requests
import json
import os

def download_etda_data():
    """Downloads ETDA APT Groups data from their API"""

    url = "https://apt.etda.or.th/cgi-bin/getcard.cgi?g=all&o=json"
    filepath="data/etda/actors.json"

    os.makedirs("data/etda", exist_ok=True)

    if os.path.exists(filepath):
        print("ETDA data already downloaded. Skipping")
        return filepath
    
    print("Downloading ETDA Threat Group Cards data...")

    headers = {
        "User-Agent" : "Mozilla/5.0 (Research Project - QUB MSc Cybersecurity)"
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(response.text)

    print("Download complete")
    return filepath

def parse_etda_data(filepath):
    """Parses ETDA threat actor data.
    Returns list of actor dictionaries."""

    with open(filepath, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Actors are in the 'values' key
    values = raw.get("values", [])
    actors = []

    for entry in values:
        # Extract alias names from the names list
        aliases = [n.get("name", "") for n in entry.get("names", [])]

        actor = {
            "name": entry.get("actor", ""),
            "aliases": aliases,
            "country": entry.get("country", []),
            "description": entry.get("description", ""),
            "motivation": entry.get("motivation", []),
            "target_sectors": entry.get("target-category", []),
            "target_countries": entry.get("target-country", []),
            "first_seen": entry.get("first-seen", ""),
            "last_seen": entry.get("last-seen", ""),
            "tools": entry.get("tools", []),
            "source": "ETDA"
        }
        actors.append(actor)

    print(f"Parsed {len(actors)} actors from ETDA.")
    return actors

if __name__ == "__main__":
    filepath = download_etda_data()
    actors = parse_etda_data(filepath)

    with open("data/etda/actors_parsed.json", "w") as f:
        json.dump(actors, f, indent=2)

    print("Saved to data/etda/actors_parsed.json")

    if actors:
        print(f"\nSample actor: {actors[0]['name']}")
        print(f"Country: {actors[0]['country']}")
        print(f"Aliases: {actors[0]['aliases']}")
        print(f"Target sectors: {actors[0]['target_sectors']}")