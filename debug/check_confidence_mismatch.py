import sys, json, os
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
malware_index = {}
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))

def count_supporting_engines(r):
    keys = ["keyword_score", "tool_score", "sector_score", "motivation_score", "country_score", "ioc_score"]
    return sum(1 for k in keys if r.get(k, 0) > 0)

mismatch_cases = []
for row in merged:
    raw_gt = row["GT"].strip()
    gt = kb_names.get(raw_gt.lower().strip()) or NAME_CORRECTIONS.get(raw_gt.lower().strip())
    if not gt:
        continue
    results = hybrid_attribute(
        query_text=row["Text"], model=model, embeddings=embeddings,
        semantic_profiles=semantic_profiles, groups=groups,
        malware_index=malware_index, ioc_index=ioc_index, top_n=10
    )
    if not results:
        continue
    top = results[0]
    n_in_cluster = sum(1 for r in results if r.get("in_top_cluster"))
    manual_isolated = top.get("in_top_cluster", False) and n_in_cluster == 1
    manual_support = count_supporting_engines(top)
    manual_high_conf = manual_isolated and manual_support >= 4

    internal_conf = top.get("attribution_confidence")
    internal_high_conf = internal_conf == "high"

    if manual_high_conf != internal_high_conf:
        mismatch_cases.append({
            "gt": gt, "got": top["name"],
            "manual_isolated": manual_isolated, "manual_support": manual_support,
            "manual_high_conf": manual_high_conf,
            "internal_confidence": internal_conf,
        })

print(f"Total mismatches between manual re-derivation and internal field: {len(mismatch_cases)}")
for m in mismatch_cases:
    print(m)
