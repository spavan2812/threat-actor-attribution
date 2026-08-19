import json
import os
from entity_extractor import SECTOR_KEYWORDS, MOTIVATION_KEYWORDS, extract_sectors

def normalize_sectors(raw_sectors):
    
    canonical = set()
    for raw in raw_sectors:
        if not raw:
            continue
        raw_lower = raw.lower()
        matched_any = False
        for keyword, sector in SECTOR_KEYWORDS.items():
            if keyword in raw_lower:
                canonical.add(sector)
                matched_any = True
        if not matched_any:
            canonical.add(raw.strip().title())
    return sorted(canonical)



KNOWN_BAD_MOTIVATION_VALUES = {
    "iran (islamic republic of)", "china", "russia", "north korea",
    "united states", "iran", "russian federation",
}


def normalize_motivation(raw_motivations):
    
    canonical = set()
    for raw in raw_motivations:
        if not raw:
            continue
        raw_lower = raw.strip().lower()
        if raw_lower in KNOWN_BAD_MOTIVATION_VALUES:
            continue
        matched_any = False
        for keyword, motivation in MOTIVATION_KEYWORDS.items():
            if keyword in raw_lower:
                canonical.add(motivation)
                matched_any = True
        if not matched_any:
            canonical.add(raw.strip().title())
    return sorted(canonical)

def load_all_sources():
    """Load data from all three sources."""
    with open("data/mitre/groups.json", "r") as f:
        mitre = json.load(f)
    with open("data/misp/actors.json", "r") as f:
        misp = json.load(f)
    with open("data/etda/actors_parsed.json", "r") as f:
        etda = json.load(f)
    
    print(f"Loaded: {len(mitre)} MITRE, {len(misp)} MISP, {len(etda)} ETDA actors")
    return mitre, misp, etda

def build_alias_index(actors, name_field="name", alias_field="aliases"):
    """
    Builds a dictionary mapping every known name and alias
    to the actor's primary name. Used for cross-source matching.
    """
    index = {}
    for actor in actors:
        primary = actor.get(name_field, "").lower().strip()
        if primary:
            index[primary] = actor
        
        for alias in actor.get(alias_field, []):
            if isinstance(alias, str):
                alias_clean = alias.lower().strip()
                if alias_clean and alias_clean not in index:
                    index[alias_clean] = actor
    
    return index

def find_match(actor_name, aliases, index):
    """
    Tries to find a matching actor in an index using
    primary name or any alias.
    Returns matched actor or None.
    """
    
    if actor_name.lower().strip() in index:
        return index[actor_name.lower().strip()]
    
    # Try each alias
    for alias in aliases:
        if isinstance(alias, str):
            if alias.lower().strip() in index:
                return index[alias.lower().strip()]
    
    return None

def merge_knowledge_base(mitre, misp, etda):
    """
    Merges three sources into unified actor profiles.
    MITRE is the primary source — every MITRE actor gets a profile.
    MISP and ETDA data is merged in where matches are found.
    """
    print("Building alias indices...")
    misp_index = build_alias_index(misp)
    etda_index = build_alias_index(etda)
    
    unified = []
    misp_matches = 0
    etda_matches = 0

    for actor in mitre:
        # Start with MITRE data
        profile = {
            "name": actor["name"],
            "aliases": list(set(actor.get("aliases", []))),
            "description": actor.get("description", ""),
            "ttps": actor.get("ttps", []),
            "ttp_count": actor.get("ttp_count", 0),
            "country": [],
            "motivation": [],
            "target_sectors": [],
            "target_countries": [],
            "first_seen": "",
            "last_seen": "",
            "tools": [],
            "malware_families": [],
            "sources": ["MITRE"]
        }

        
        misp_match = find_match(actor["name"], actor.get("aliases", []), misp_index)
        if misp_match:
            misp_matches += 1
            profile["sources"].append("MISP")
            
            # Merge aliases
            misp_aliases = misp_match.get("aliases", [])
            all_aliases = list(set(profile["aliases"] + misp_aliases))
            profile["aliases"] = all_aliases

            # Add MISP metadata if not already present
            if not profile["country"]:
                country = misp_match.get("country", "")
                profile["country"] = [country] if country else []
            
            if not profile["motivation"]:
                motivation = misp_match.get("motivation", "")
                if motivation:
                    profile["motivation"] = normalize_motivation([motivation])
            
            if not profile["target_sectors"]:
                misp_sectors = misp_match.get("target_sectors", [])
                if misp_sectors:
                    profile["target_sectors"] = normalize_sectors(misp_sectors)
            
            if not profile["target_countries"]:
                profile["target_countries"] = misp_match.get("target_countries", [])
            
            if not profile["first_seen"]:
                profile["first_seen"] = misp_match.get("first_seen", "")
            
            if not profile["last_seen"]:
                profile["last_seen"] = misp_match.get("last_seen", "")

            
            misp_desc = misp_match.get("description", "")
            

        # Try to find matching ETDA entry
        etda_match = find_match(actor["name"], actor.get("aliases", []), etda_index)
        if etda_match:
            etda_matches += 1
            profile["sources"].append("ETDA")

            # ETDA has richer country and sector data — prefer it
            if etda_match.get("country"):
                profile["country"] = etda_match["country"]
            
            if etda_match.get("motivation"):
                profile["motivation"] = normalize_motivation(etda_match["motivation"])
            
            if etda_match.get("target_sectors"):
                profile["target_sectors"] = normalize_sectors(etda_match["target_sectors"])
            
            if etda_match.get("target_countries"):
                profile["target_countries"] = etda_match["target_countries"]
            
            if etda_match.get("first_seen"):
                profile["first_seen"] = etda_match["first_seen"]
            
            if etda_match.get("last_seen"):
                profile["last_seen"] = etda_match["last_seen"]
            
            if etda_match.get("tools"):
                profile["tools"] = etda_match["tools"]

            
            etda_desc = etda_match.get("description", "")
           
            etda_aliases = [
                n if isinstance(n, str) else n.get("name", "")
                for n in etda_match.get("aliases", [])
            ]
            profile["aliases"] = list(set(profile["aliases"] + etda_aliases))

        unified.append(profile)

    print(f"\nMerge complete:")
    print(f"Total profiles: {len(unified)}")
    print(f"MISP matches: {misp_matches}")
    print(f"ETDA matches: {etda_matches}")
    print(f"Multi-source profiles: {len([a for a in unified if len(a['sources']) > 1])}")
    
    return unified



CONFIRMED_SAFE_MERGES = {
    "APT34": "OilRig",
    "UNC2452": "APT29",
    "Charming Kitten": "Magic Hound",
}


def merge_duplicate_actors(unified, merges=None):
    
    if merges is None:
        merges = CONFIRMED_SAFE_MERGES

    by_name = {a["name"]: a for a in unified}
    removed = []

    for duplicate_name, canonical_name in merges.items():
        dup = by_name.get(duplicate_name)
        canon = by_name.get(canonical_name)
        if dup is None or canon is None:
            print(f"  Skipping {duplicate_name} -> {canonical_name}: "
                  f"one or both profiles not found")
            continue

        canon["aliases"] = sorted(set(canon.get("aliases", []))
                                  | set(dup.get("aliases", []))
                                  | {duplicate_name})

        existing_ids = {t["technique_id"] for t in canon.get("ttps", [])}
        for t in dup.get("ttps", []):
            if t["technique_id"] not in existing_ids:
                canon.setdefault("ttps", []).append(t)
                existing_ids.add(t["technique_id"])
        canon["ttp_count"] = len(canon.get("ttps", []))

        canon["tools"] = sorted(set(canon.get("tools", []))
                                | set(dup.get("tools", [])))
        canon["target_sectors"] = sorted(set(canon.get("target_sectors", []))
                                         | set(dup.get("target_sectors", [])))
        canon["motivation"] = sorted(set(canon.get("motivation", []))
                                     | set(dup.get("motivation", [])))
        canon["country"] = sorted(set(canon.get("country", []))
                                  | set(dup.get("country", [])))
        canon["sources"] = sorted(set(canon.get("sources", []))
                                  | set(dup.get("sources", [])))

        removed.append(duplicate_name)
        print(f"  Merged {duplicate_name} into {canonical_name} "
              f"(now {canon['ttp_count']} TTPs, "
              f"{len(canon['aliases'])} aliases)")

    result = [a for a in unified if a["name"] not in removed]
    print(f"\nMerged {len(removed)} confirmed-duplicate profiles. "
          f"Total actors: {len(unified)} -> {len(result)}")
    print("REMEMBER: regenerate embeddings before evaluating -- "
          "merged profiles' text has changed.")
    return result


def backfill_sectors_from_description(unified):
    
    backfilled = 0
    for actor in unified:
        if not actor.get("target_sectors"):
            extracted = extract_sectors(actor.get("description", ""))
            if extracted:
                actor["target_sectors"] = sorted(extracted)
                backfilled += 1

    print(f"Backfilled sector data for {backfilled} actors using "
          f"MITRE description text (previously had none from "
          f"structured MISP/ETDA data).")
    return unified


if __name__ == "__main__":
    mitre, misp, etda = load_all_sources()
    unified = merge_knowledge_base(mitre, misp, etda)

    print("\nApplying confirmed-safe duplicate merges...")
    unified = merge_duplicate_actors(unified)

   

    os.makedirs("data/unified", exist_ok=True)
    with open("data/unified/knowledge_base.json", "w") as f:
        json.dump(unified, f, indent=2)

    print("\nSaved to data/unified/knowledge_base.json")

    # Show a rich example
    rich = next((a for a in unified if len(a["sources"]) >= 2 
                 and a["ttp_count"] > 0 
                 and a["country"]), None)
    if rich:
        print(f"\nExample multi-source profile: {rich['name']}")
        print(f"Sources: {rich['sources']}")
        print(f"Country: {rich['country']}")
        print(f"Motivation: {rich['motivation']}")
        print(f"Target sectors: {rich['target_sectors']}")
        print(f"TTPs: {rich['ttp_count']}")
        print(f"Aliases: {rich['aliases'][:5]}")
        print(f"First seen: {rich['first_seen']}")