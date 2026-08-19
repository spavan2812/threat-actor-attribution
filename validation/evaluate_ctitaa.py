import json
import sys
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from entity_extractor import extract_iocs, extract_explicit_ttps

NAME_CORRECTIONS = {
    "lazarus": "Lazarus Group",
    "gamaredon": "Gamaredon Group",
}

kb = json.load(open("data/unified/knowledge_base.json"))
kb_names = {}
for a in kb:
    for n in [a["name"]] + a.get("aliases", []):
        kb_names[n.lower().strip()] = a["name"]

merged = json.load(open("cti_taa_merged.json"))

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

malware_index = {}
import os
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))

print(f"\n{'ID':<4} {'GT':<15} {'Got':<15} {'Top1':>6} {'Top3':>6} "
      f"{'Engines used'}")
print("-" * 100)

top1_correct = 0
top3_correct = 0
n_tested = 0
ioc_only_fired = 0
ioc_only_correct = 0

for row in merged:
    raw_gt = row["GT"].strip()
    gt = kb_names.get(raw_gt.lower().strip()) or NAME_CORRECTIONS.get(raw_gt.lower().strip())
    if not gt:
        continue
    n_tested += 1

    text = row["Text"]

    
    results = hybrid_attribute(
        query_text=text, model=model, embeddings=embeddings,
        semantic_profiles=semantic_profiles, groups=groups,
        malware_index=malware_index, ioc_index=ioc_index, top_n=10
    )
    names = [r["name"] for r in results]
    top1 = names[0] == gt if names else False
    top3 = gt in names[:3]
    engines = results[0]["engines_used"] if results else []

    if top1:
        top1_correct += 1
    if top3:
        top3_correct += 1

    mark = "correct" if top1 else "wrong"
    print(f"{n_tested:<4} {gt:<15} "
          f"{names[0] if names else 'None':<15} {mark:>7} "
          f"{'yes' if top3 else 'no':>6}  {engines}")

    
    real_iocs = extract_iocs(text)
    all_iocs = set(real_iocs["ips"]) | set(real_iocs["domains"]) | set(real_iocs["hashes"])
    if all_iocs:
        ioc_only_fired += 1
        ioc_results = hybrid_attribute(
            query_text=None, model=model, embeddings=embeddings,
            semantic_profiles=semantic_profiles, groups=groups,
            malware_index=malware_index, ioc_index=ioc_index,
            direct_iocs=all_iocs, top_n=10
        )
        ioc_names = [r["name"] for r in ioc_results]
        if ioc_names and ioc_names[0] == gt:
            ioc_only_correct += 1

print("\n" + "=" * 70)
print("CTI-TAA FULL-TEXT EVALUATION SUMMARY")
print("=" * 70)
print(f"Total cases tested (confirmed KB overlap): {n_tested}")
print(f"Top-1 Accuracy: {top1_correct/n_tested*100:.1f}% ({top1_correct}/{n_tested})")
print(f"Top-3 Accuracy: {top3_correct/n_tested*100:.1f}% ({top3_correct}/{n_tested})")

print("\n" + "=" * 70)
print("CTI-TAA REAL-IOC-ONLY STRUCTURED TEST (no free text)")
print("=" * 70)
if ioc_only_fired:
    print(f"Cases with extractable real IoCs: {ioc_only_fired}/{n_tested}")
    print(f"Top-1 Accuracy on those: {ioc_only_correct/ioc_only_fired*100:.1f}% "
          f"({ioc_only_correct}/{ioc_only_fired})")
else:
    print("No cases had extractable real IoCs in the report text.")