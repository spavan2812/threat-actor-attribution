import sys, json
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

results = hybrid_attribute(
    query_text=None, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index,
    direct_countries={"Russia"}, direct_motivation={"Espionage"},
    top_n=10
)
print("=== AMBIGUOUS CASE (known 9-way tie) ===")
print("Confidence:", results[0]["attribution_confidence"])
print("Reasoning:", results[0]["confidence_reasoning"])
print()

results2 = hybrid_attribute(
    query_text="""Phishing emails targeted state organizations delivering
    malicious shortcut files executing PowerShell commands. MASEPIE used for
    file transfers, STEELHOOK for browser data theft, OCEANMAP as backdoor.
    Poland targeted.""",
    model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index, top_n=5
)
print("=== CLEAR-WINNER CASE (APT29, explicit tools) ===")
print("Confidence:", results2[0]["attribution_confidence"])
print("Reasoning:", results2[0]["confidence_reasoning"])
