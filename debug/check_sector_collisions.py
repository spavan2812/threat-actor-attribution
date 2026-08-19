import json
from collections import Counter

kb = json.load(open("data/unified/knowledge_base.json"))
n = len(kb)

sector_counts = Counter()
sector_counts_per_actor = []
for a in kb:
    sectors = set(a.get("target_sectors", []))
    sector_counts_per_actor.append(len(sectors))
    for s in sectors:
        sector_counts[s] += 1

print(f"Total actors: {n}")
print(f"Actors with ZERO sector data: {sum(1 for c in sector_counts_per_actor if c == 0)}")
print(f"Average sectors per actor (excluding zero): "
      f"{sum(c for c in sector_counts_per_actor if c > 0) / max(1, sum(1 for c in sector_counts_per_actor if c > 0)):.1f}")
print()
print(f"{'Sector':<25} {'# actors':>10} {'% of KB':>10}")
print("-" * 47)
for sector, count in sector_counts.most_common(20):
    print(f"{sector:<25} {count:>10} {count/n*100:>9.1f}%")

print()
# How many actors have IDENTICAL full sector sets to at least one other actor
# (a genuine, hard tie -- not just sharing one common tag)
sector_sets = {}
for a in kb:
    key = frozenset(a.get("target_sectors", []))
    if key:
        sector_sets.setdefault(key, []).append(a["name"])

exact_tie_groups = [names for names in sector_sets.values() if len(names) > 1]
total_actors_in_ties = sum(len(g) for g in exact_tie_groups)
print(f"Actors sharing an IDENTICAL full sector set with >=1 other actor: "
      f"{total_actors_in_ties}/{n}")
print(f"Number of distinct tie-groups: {len(exact_tie_groups)}")
print(f"Largest tie-group size: {max((len(g) for g in exact_tie_groups), default=0)}")
