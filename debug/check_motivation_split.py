import json
from collections import Counter

kb = json.load(open("data/unified/knowledge_base.json"))
by_name = {a["name"]: a for a in kb}

tied_20 = ['Dragonfly', 'Lazarus Group', 'Inception', 'Kimsuky', 'Sandworm Team',
           'APT29', 'APT38', 'Leviathan', 'menuPass', 'APT37', 'Dragonfly 2.0',
           'Threat Group-3390', 'Moonstone Sleet', 'APT12', 'Putter Panda',
           'APT1', 'Naikon', 'Mofang', 'Cleaver', 'AppleJeus']

print(f"{'Actor':<20} {'Motivation':<40} {'Country':<15}")
print("-" * 78)
motivation_combo_counts = Counter()
for name in tied_20:
    a = by_name.get(name, {})
    mot = sorted(a.get("motivation", []))
    country = a.get("country", [])
    print(f"{name:<20} {str(mot):<40} {str(country):<15}")
    motivation_combo_counts[tuple(mot)] += 1

print()
print("Breakdown by motivation combination:")
for combo, count in motivation_combo_counts.most_common():
    print(f"  {combo}: {count} actors")
