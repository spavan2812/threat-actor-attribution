import os, json

BASE_PATH = "guru_dataset/threat_actors_added_data"

kb = json.load(open("data/unified/knowledge_base.json"))
kb_names = {}
for a in kb:
    for n in [a["name"]] + a.get("aliases", []):
        kb_names[n.lower().strip()] = a["name"]

# Real folder names = Guru et al.'s actual actor set, taken directly
# from the downloaded dataset, not assumed or reconstructed from memory
guru_actors = sorted(os.listdir(BASE_PATH))
guru_actors = [a for a in guru_actors if os.path.isdir(os.path.join(BASE_PATH, a))]

print(f"Real actor folders found in Guru et al. dataset: {len(guru_actors)}\n")

confirmed = []
not_found = []
for actor in guru_actors:
    match = kb_names.get(actor.lower().strip())
    if match:
        confirmed.append((actor, match))
        print(f"  {actor:<20} -> {match}")
    else:
        not_found.append(actor)
        print(f"  {actor:<20} -> NOT FOUND in TRACE KB")

print(f"\nConfirmed real overlap: {len(confirmed)}/{len(guru_actors)}")
print(f"Not in TRACE's knowledge base: {not_found}")