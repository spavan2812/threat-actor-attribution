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

matrix = {"high_correct": 0, "high_wrong": 0, "low_correct": 0, "low_wrong": 0}
high_wrong_cases = []

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
    if not results:
        continue

    got = results[0]["name"]
    correct = got == gt
    conf = results[0]["attribution_confidence"]

    key = f"{conf}_{'correct' if correct else 'wrong'}"
    matrix[key] += 1
    if key == "high_wrong":
        high_wrong_cases.append((gt, got))

n = sum(matrix.values())
print(f"Total cases: {n}\n")
print(f"High confidence + correct: {matrix['high_correct']}")
print(f"High confidence + WRONG:   {matrix['high_wrong']}  <-- critical safety metric")
print(f"Low confidence + correct:  {matrix['low_correct']}")
print(f"Low confidence + wrong:    {matrix['low_wrong']}")
print()
if high_wrong_cases:
    print("High-confidence WRONG cases (expected -> got):")
    for gt, got in high_wrong_cases:
        print(f"  {gt} -> {got}")
else:
    print("No high-confidence wrong cases found.")
