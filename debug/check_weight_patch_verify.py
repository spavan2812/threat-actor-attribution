import sys, json
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

print("=== BEFORE: real baseline SEMANTIC_WEIGHT =", hybrid_engine.SEMANTIC_WEIGHT, "===")
results1 = hybrid_attribute(
    query_text=test_text, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index, top_n=3
)
for r in results1:
    print(r["name"], "combined:", r["combined_score"], "semantic:", r["semantic_score"])

print()
print("Setting SEMANTIC_WEIGHT to an EXTREME value: 0.0")
hybrid_engine.SEMANTIC_WEIGHT = 0.0

print("=== AFTER: hybrid_engine.SEMANTIC_WEIGHT is now", hybrid_engine.SEMANTIC_WEIGHT, "===")
results2 = hybrid_attribute(
    query_text=test_text, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index, top_n=3
)
for r in results2:
    print(r["name"], "combined:", r["combined_score"], "semantic:", r["semantic_score"])

print()
if results1[0]["combined_score"] == results2[0]["combined_score"]:
    print("!!! NO CHANGE DETECTED even at SEMANTIC_WEIGHT=0.0 -- the monkey-patch is NOT reaching the real computation. Confirmed bug in the sweep methodology.")
else:
    print("Change detected -- monkey-patching IS working. The perfect invariance in the sweep is a genuine finding, needs a different explanation.")
