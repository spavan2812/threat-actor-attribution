import json
from collections import Counter

kb = json.load(open("data/unified/knowledge_base.json"))

sector_sets = {}
for a in kb:
    key = frozenset(a.get("target_sectors", []))
    if key:
        sector_sets.setdefault(key, []).append(a["name"])

groups = sorted(
    [(k, v) for k, v in sector_sets.items() if len(v) > 1],
    key=lambda x: -len(x[1])
)

for sectors, names in groups:
    print(f"\n=== {len(names)} actors, sectors={sorted(sectors)} ===")
    print(names)
