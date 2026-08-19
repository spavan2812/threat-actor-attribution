import sys, json
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

# Same input as EU6 (expected APT29, country=Russia, motivation=Espionage, no sector)
results = hybrid_attribute(
    query_text=None, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index,
    direct_countries={"Russia"}, direct_motivation={"Espionage"},
    top_n=15
)
for r in results:
    print(f"{r['name']:<20} combined={r['combined_score']}  country={r['country_score']}  motivation={r['motivation_score']}")
