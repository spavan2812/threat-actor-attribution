import json

kb = json.load(open("data/unified/knowledge_base.json"))
for a in kb:
    if a.get("name") in ("Lazarus Group", "AppleJeus"):
        print(f"--- {a['name']} ---")
        print("aliases:", a.get("aliases", []))
        print()
