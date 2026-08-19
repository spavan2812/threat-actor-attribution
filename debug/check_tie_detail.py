import sys, json
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()

by_name = {g["name"]: g for g in groups}
sectors = set(by_name["Winnti Group"].get("target_sectors", []))

results = hybrid_attribute(
    query_text=None, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    direct_sectors=sectors, top_n=5
)
for r in results:
    print(json.dumps(r, indent=2))
