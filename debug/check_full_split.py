import json
from collections import Counter

kb = json.load(open("data/unified/knowledge_base.json"))
by_name = {a["name"]: a for a in kb}

tied_20 = ['Dragonfly', 'Lazarus Group', 'Inception', 'Kimsuky', 'Sandworm Team',
           'APT29', 'APT38', 'Leviathan', 'menuPass', 'APT37', 'Dragonfly 2.0',
           'Threat Group-3390', 'Moonstone Sleet', 'APT12', 'Putter Panda',
           'APT1', 'Naikon', 'Mofang', 'Cleaver', 'AppleJeus']

combo_groups = {}
for name in tied_20:
    a = by_name.get(name, {})
    mot = tuple(sorted(a.get("motivation", [])))
    country = tuple(sorted(a.get("country", [])))
    key = (mot, country)
    combo_groups.setdefault(key, []).append(name)

print("Sector + Motivation + Country breakdown of the 20-actor tie group:")
print("-" * 70)
for (mot, country), names in sorted(combo_groups.items(), key=lambda x: -len(x[1])):
    print(f"\n{len(names)} actors: motivation={mot} country={country}")
    print(f"  {names}")
