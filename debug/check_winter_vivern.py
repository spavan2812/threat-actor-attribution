import json
kb = json.load(open("data/unified/knowledge_base.json"))
for a in kb:
    if a.get("name") == "Winter Vivern":
        desc = a.get("description", "")
        print("description length:", len(desc))
        print("sources:", a.get("sources"))
        print("first 400 chars:", desc[:400])
