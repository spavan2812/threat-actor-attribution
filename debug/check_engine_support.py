import sys, json
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index

NAME_CORRECTIONS = {"lazarus": "Lazarus Group", "gamaredon": "Gamaredon Group"}
kb = json.load(open("data/unified/knowledge_base.json"))
kb_names = {}
for a in kb:
    for n in [a["name"]] + a.get("aliases", []):
        kb_names[n.lower().strip()] = a["name"]

merged = json.load(open("cti_taa_merged.json"))

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

import os
malware_index = {}
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))

# Compare "engine support" for high-confidence CORRECT vs high-confidence WRONG cases
def count_supporting_engines(r):
    # An engine "supports" the winner if it gave a real (>0) score,
    # excluding semantic (the one we suspect is doing the misleading
    # here) so we isolate NON-semantic corroboration specifically.
    keys = ["keyword_score", "tool_score", "sector_score",
            "motivation_score", "country_score", "ioc_score"]
    return sum(1 for k in keys if r.get(k, 0) > 0)

correct_support, wrong_support = [], []

for row in merged:
    raw_gt = row["GT"].strip()
    gt = kb_names.get(raw_gt.lower().strip()) or NAME_CORRECTIONS.get(raw_gt.lower().strip())
    if not gt:
        continue
    results = hybrid_attribute(
        query_text=row["Text"], model=model, embeddings=embeddings,
        semantic_profiles=semantic_profiles, groups=groups,
        malware_index=malware_index, ioc_index=ioc_index, top_n=5
    )
    if not results or results[0]["attribution_confidence"] != "high":
        continue
    support = count_supporting_engines(results[0])
    if results[0]["name"] == gt:
        correct_support.append(support)
    else:
        wrong_support.append(support)

print("High-confidence CORRECT cases -- non-semantic engine support:", correct_support)
print("Average:", sum(correct_support)/len(correct_support) if correct_support else 0)
print()
print("High-confidence WRONG cases -- non-semantic engine support:", wrong_support)
print("Average:", sum(wrong_support)/len(wrong_support) if wrong_support else 0)
