import json

with open("data/malpedia/malpedia.json", "r", encoding="utf-8") as f:
    raw = json.load(f)

values = raw.get("values", [])

# Find first entry that has any actor-related data
for entry in values[:20]:
    meta = entry.get("meta", {})
    print(f"Name: {entry.get('value', '')}")
    print(f"Meta keys: {list(meta.keys())}")
    print(f"Related: {entry.get('related', [])[:2]}")
    print("---")