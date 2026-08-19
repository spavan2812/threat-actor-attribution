import sys, json
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from evaluation import TEST_CASES

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

malware_index = {}
import os
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))

print(f"{'ID':<4} {'Expected':<16} {'Got':<16} {'Correct?':<10} {'Confidence'}")
print("-" * 65)
for case in TEST_CASES:
    results = hybrid_attribute(
        query_text=case["description"], model=model, embeddings=embeddings,
        semantic_profiles=semantic_profiles, groups=groups,
        malware_index=malware_index, ioc_index=ioc_index, top_n=5
    )
    got = results[0]["name"] if results else "None"
    correct = "yes" if got == case["expected"] else "no"
    conf = results[0]["attribution_confidence"] if results else "n/a"
    print(f"{case['id']:<4} {case['expected']:<16} {got:<16} {correct:<10} {conf}")
