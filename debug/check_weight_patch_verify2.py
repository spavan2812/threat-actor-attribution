import sys
sys.path.insert(0, "src")
import hybrid_engine
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

test_text = """
Phishing emails targeted state organizations delivering malicious
shortcut files executing PowerShell commands. MASEPIE used for
file transfers, STEELHOOK for browser data theft, OCEANMAP as
backdoor. Poland targeted.
"""

print("=== BEFORE: ENGINE_WEIGHTS[semantic] =", hybrid_engine.ENGINE_WEIGHTS["semantic"], "===")
results1 = hybrid_attribute(
    query_text=test_text, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index, top_n=3
)
for r in results1:
    print(r["name"], "combined:", r["combined_score"])

print()
print("Setting ENGINE_WEIGHTS[semantic] to 0.0 (the dict, not the standalone constant)")
hybrid_engine.ENGINE_WEIGHTS["semantic"] = 0.0

print("=== AFTER: ENGINE_WEIGHTS[semantic] =", hybrid_engine.ENGINE_WEIGHTS["semantic"], "===")
results2 = hybrid_attribute(
    query_text=test_text, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index, top_n=3
)
for r in results2:
    print(r["name"], "combined:", r["combined_score"])

print()
if results1[0]["combined_score"] == results2[0]["combined_score"]:
    print("STILL NO CHANGE -- need to investigate further.")
else:
    print("CHANGE CONFIRMED -- ENGINE_WEIGHTS dict mutation works correctly.")
