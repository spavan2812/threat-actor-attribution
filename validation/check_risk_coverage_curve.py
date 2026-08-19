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
    keys = ["keyword_score", "tool_score", "sector_score",
            "motivation_score", "country_score", "ioc_score"]
    return sum(1 for k in keys if r.get(k, 0) > 0)


case_data = []  # (correct, isolated, support_count)

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
    correct = top["name"] == gt
    n_in_cluster = sum(1 for r in results if r.get("in_top_cluster"))
    isolated = top.get("in_top_cluster", False) and n_in_cluster == 1
    support = count_supporting_engines(top)
    case_data.append((correct, isolated, support))

print(f"Total real cases: {len(case_data)}\n")
print("RISK-COVERAGE CURVE (varying required supporting-engine count,")
print("isolation condition held fixed)\n")
print(f"{'Threshold':<11} {'Coverage':>10} {'n':>4} {'Correct':>9} {'Wrong':>7} {'Cond. Error':>13}")
print("-" * 60)

for threshold in range(0, 7):
    accepted = [c for c in case_data if c[1] and c[2] >= threshold]
    n_accepted = len(accepted)
    n_correct = sum(1 for c in accepted if c[0])
    n_wrong = n_accepted - n_correct
    coverage = n_accepted / len(case_data) * 100
    cond_error = (n_wrong / n_accepted * 100) if n_accepted > 0 else float("nan")
    err_str = f"{cond_error:.1f}%" if n_accepted > 0 else "n/a (0 cases)"
    print(f">={threshold:<9} {coverage:>9.1f}% {n_accepted:>4} {n_correct:>9} "
          f"{n_wrong:>7} {err_str:>13}")

print("\nCurrent deployed threshold is >=4.")
print("A genuinely useful confidence mechanism should show conditional")
print("error trending DOWN as the threshold rises (stricter acceptance")
print("= safer predictions), not a flat or inconsistent pattern.")