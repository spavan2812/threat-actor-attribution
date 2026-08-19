import sys
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()

by_name = {g["name"]: g for g in groups}

for actor_name in ["APT41", "Winnti Group"]:
    sectors = set(by_name[actor_name].get("target_sectors", []))
    print(f"\n=== {actor_name}  sectors={sectors} ===")
    for run in range(2):
        results = hybrid_attribute(
            query_text=None, model=model, embeddings=embeddings,
            semantic_profiles=semantic_profiles, groups=groups,
            direct_sectors=sectors, top_n=3
        )
        names = [r["name"] for r in results]
        print(f"  run {run+1}: {names}")
