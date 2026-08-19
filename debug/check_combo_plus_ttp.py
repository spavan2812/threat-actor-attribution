import sys, random
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()
by_name = {g["name"]: g for g in groups}
rng = random.Random(42)

failures = ["Lazarus Group", "Sandworm Team", "Kimsuky", "Winnti Group"]

for expected in failures:
    a = by_name[expected]
    real_sectors = set(a.get("target_sectors", []))
    real_motivation = set(a.get("motivation", []))
    real_countries = set(a.get("country", []))
    real_ttps = [t["technique_id"] for t in a.get("ttps", [])]
    sampled_ttps = set(rng.sample(real_ttps, min(5, len(real_ttps)))) if real_ttps else set()

    results = hybrid_attribute(
        query_text=None, model=model, embeddings=embeddings,
        semantic_profiles=semantic_profiles, groups=groups,
        ioc_index=ioc_index,
        direct_sectors=real_sectors, direct_motivation=real_motivation,
        direct_countries=real_countries, direct_ttps=sampled_ttps,
        top_n=3
    )
    names = [r["name"] for r in results]
    hit = "CORRECT" if names and names[0] == expected else "WRONG"
    print(f"{expected:<16} -> top3={names}  [{hit}]")
