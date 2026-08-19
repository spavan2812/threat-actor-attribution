import os, sys, json
sys.path.insert(0, "src")
from entity_extractor import extract_entities

malware_index = {}
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))

for fname in ["ChromeExtention.txt", "Academia.txt"]:
    fpath = os.path.join("guru_dataset/threat_actors_added_data/Kimsuky", fname)
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read().strip()
    entities = extract_entities(text, malware_index)
    print(f"--- {fname} ---")
    print("tools found:", entities["tools"])
    print("direct_actor_signals:", entities["direct_actor_signals"])
    print()
