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


# CORRECTED: mutate the actual ENGINE_WEIGHTS dict that
# fuse_engine_scores reads via global lookup at call time. The
# earlier version of this script mutated the standalone constants
# (hybrid_engine.SEMANTIC_WEIGHT etc.), which was CONFIRMED, via
# direct testing, to have zero effect -- ENGINE_WEIGHTS is built
# once from those constants at module-import time and never
# automatically refreshed afterward. Verified fix directly before
# use: setting ENGINE_WEIGHTS["semantic"]=0.0 produced a real,
# dramatic score change (APT29 90.19 -> 100.0, entirely different
# runner-up actors), confirming this is the correct mechanism.

DICT_KEY_MAP = {
    "SEMANTIC_WEIGHT": "semantic",
    "KEYWORD_WEIGHT": "keyword",
    "TOOL_WEIGHT": "tool",
    "SECTOR_WEIGHT": "sector",
    "MOTIVATION_WEIGHT": "motivation",
    "COUNTRY_WEIGHT": "country",
    "IOC_WEIGHT": "ioc",
}

BASELINE = {name: hybrid_engine.ENGINE_WEIGHTS[key] for name, key in DICT_KEY_MAP.items()}

print("Confirming real baseline before any perturbation...")
baseline_top1, baseline_mrr = run_eval()
print(f"Baseline: Top-1={baseline_top1:.1f}%  MRR={baseline_mrr:.3f}\n")

print(f"{'Weight':<20} {'Value':>8} {'Top-1':>8} {'MRR':>7} {'Delta Top-1':>13}")
print("-" * 62)

PERTURBATIONS = [-0.80, -0.50, -0.20, +0.20, +0.50, +1.00, +2.00]

for weight_name, dict_key in DICT_KEY_MAP.items():
    baseline_value = BASELINE[weight_name]
    for pct in PERTURBATIONS:
        new_value = round(baseline_value * (1 + pct), 4)
        hybrid_engine.ENGINE_WEIGHTS[dict_key] = new_value

        top1, mrr = run_eval()
        delta = top1 - baseline_top1
        sign = "+" if pct > 0 else ""
        dsign = "+" if delta > 0 else ""
        print(f"{weight_name:<20} {new_value:>8.3f} {top1:>7.1f}% {mrr:>7.3f} "
              f"{dsign}{delta:>11.1f}pp  ({sign}{pct*100:.0f}%)")

        # Restore true baseline before the next perturbation
        hybrid_engine.ENGINE_WEIGHTS[dict_key] = baseline_value
    print()

print("Restored all weights to real baseline values.")
final_top1, final_mrr = run_eval()
print(f"Final confirmation baseline still holds: Top-1={final_top1:.1f}%  MRR={final_mrr:.3f}")