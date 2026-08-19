import json
kb = json.load(open("data/unified/knowledge_base.json"))
for a in kb:
    if a.get("name") in ("Lazarus Group", "Gamaredon Group"):
        print(f"--- {a['name']} ---")
        print("aliases:", a.get("aliases", []))
        print("bare name in aliases?:", "lazarus" in [x.lower() for x in a.get("aliases",[])] or "gamaredon" in [x.lower() for x in a.get("aliases",[])])
        print()
