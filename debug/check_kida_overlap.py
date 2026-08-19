import json
kb = json.load(open("data/unified/knowledge_base.json"))
kb_names = {}
for a in kb:
    for n in [a["name"]] + a.get("aliases", []):
        kb_names[n.lower().strip()] = a["name"]

kida_actors = ["APT1", "APT10", "APT19", "APT21", "APT28", "APT29",
               "APT30", "DarkHotel", "Energetic Bear", "Equation Group",
               "Gorgon Group", "Winnti"]

print("Kida & Olukoya (2023) 12-group dataset vs real knowledge base:")
print("-" * 60)
for name in kida_actors:
    match = kb_names.get(name.lower().strip())
    print(f"  {name:<18} -> {match if match else 'NOT FOUND'}")
