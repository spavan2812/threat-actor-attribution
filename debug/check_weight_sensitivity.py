import sys, json
sys.path.insert(0, "src")
import hybrid_engine
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf
from evaluation import TEST_CASES

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

malware_index = {}
import os
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))


def run_eval():
    """Real Top-1/MRR on the 15-case dev set, using whatever weight
    values are CURRENTLY set as module-level constants in
    hybrid_engine (monkey-patched before each call)."""
    correct = 0
    rr_sum = 0.0
    for case in TEST_CASES:
        results = hybrid_attribute(
            query_text=case["description"], model=model, embeddings=embeddings,
            semantic_profiles=semantic_profiles, groups=groups,
            malware_index=malware_index, ioc_index=ioc_index, top_n=10
        )
        names = [r["name"] for r in results]
        if names and names[0] == case["expected"]:
            correct += 1
        if case["expected"] in names:
            rr_sum += 1.0 / (names.index(case["expected"]) + 1)
    n = len(TEST_CASES)
    return correct / n * 100, rr_sum / n


# Real, current baseline weights -- captured before any perturbation
BASELINE = {
    "SEMANTIC_WEIGHT": hybrid_engine.SEMANTIC_WEIGHT,
    "KEYWORD_WEIGHT": hybrid_engine.KEYWORD_WEIGHT,
    "TOOL_WEIGHT": hybrid_engine.TOOL_WEIGHT,
    "SECTOR_WEIGHT": hybrid_engine.SECTOR_WEIGHT,
    "MOTIVATION_WEIGHT": hybrid_engine.MOTIVATION_WEIGHT,
    "COUNTRY_WEIGHT": hybrid_engine.COUNTRY_WEIGHT,
    "IOC_WEIGHT": hybrid_engine.IOC_WEIGHT,
}

print("Confirming real baseline before any perturbation...")
baseline_top1, baseline_mrr = run_eval()
print(f"Baseline: Top-1={baseline_top1:.1f}%  MRR={baseline_mrr:.3f}\n")
print(f"(Should match the confirmed known-good baseline: 73.3% / 0.822 "
f"reranked, or close to it without reranking)\n")

print(f"{'Weight':<20} {'Value':>8} {'Top-1':>8} {'MRR':>7} {'Delta Top-1':>13}")
print("-" * 62)

PERTURBATIONS = [-0.20, -0.10, +0.10, +0.20]  # relative fractional change

for weight_name, baseline_value in BASELINE.items():
    for pct in PERTURBATIONS:
        new_value = round(baseline_value * (1 + pct), 4)
        setattr(hybrid_engine, weight_name, new_value)

        top1, mrr = run_eval()
        delta = top1 - baseline_top1
        sign = "+" if pct > 0 else ""
        print(f"{weight_name:<20} {new_value:>8.3f} {top1:>7.1f}% {mrr:>7.3f} "
              f"{sign}{delta:>11.1f}pp  ({sign}{pct*100:.0f}%)")

        # Restore baseline before testing the next perturbation
        setattr(hybrid_engine, weight_name, baseline_value)
    print()

print("Restored all weights to real baseline values.")
print(f"Final confirmation baseline still holds: ", end="")
final_top1, final_mrr = run_eval()
print(f"Top-1={final_top1:.1f}%  MRR={final_mrr:.3f}")