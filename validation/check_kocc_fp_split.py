import sys, json
sys.path.insert(0, "src")
from collections import Counter, defaultdict
from hybrid_engine import load_semantic_components, get_semantic_scores
import statistics

model, embeddings, semantic_profiles = load_semantic_components()

# Same real, diverse query gathering as before, now WITH ground truth
# tracked per query, so each top-5 appearance can be classified as a
# genuine correct match or a false-positive hub appearance.
queries = []  # (source, id, text, expected_actor)

from evaluation import TEST_CASES
for c in TEST_CASES:
    queries.append(("dev_set", c["id"], c["description"], c["expected"]))

try:
    from thales_validation import THALES_TEST_CASES
    for c in THALES_TEST_CASES:
        queries.append(("thales", c["id"], c["description"], c["expected"]))
except Exception as e:
    print(f"Could not load Thales cases: {e}")

try:
    from unit42_validation import UNIT42_TEST_CASES
    for c in UNIT42_TEST_CASES:
        queries.append(("unit42", c["id"], c["description"], c["expected"]))
except Exception as e:
    print(f"Could not load Unit 42 cases: {e}")

NAME_CORRECTIONS = {"lazarus": "Lazarus Group", "gamaredon": "Gamaredon Group"}
kb = json.load(open("data/unified/knowledge_base.json"))
kb_names = {}
for a in kb:
    for n in [a["name"]] + a.get("aliases", []):
        kb_names[n.lower().strip()] = a["name"]

try:
    merged = json.load(open("cti_taa_merged.json"))
    for i, row in enumerate(merged):
        raw_gt = row["GT"].strip()
        gt = kb_names.get(raw_gt.lower().strip()) or NAME_CORRECTIONS.get(raw_gt.lower().strip())
        if gt:
            queries.append(("cti_taa", f"CTA{i}", row["Text"], gt))
except Exception as e:
    print(f"Could not load CTI-TAA cases: {e}")

print(f"Total real, diverse queries with ground truth: {len(queries)}\n")

K = 5
correct_counts = Counter()
incorrect_counts = Counter()
total_counts = Counter()

for source, qid, text, expected in queries:
    scores = get_semantic_scores(text, model, embeddings, semantic_profiles)
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    top_k_names = [name for name, _ in ranked[:K]]
    for name in top_k_names:
        total_counts[name] += 1
        if name == expected:
            correct_counts[name] += 1
        else:
            incorrect_counts[name] += 1

print(f"{'Actor':<20} {'Total':>7} {'Correct':>9} {'Incorrect':>11} {'FP Rate':>9}")
print("-" * 60)

ranked_by_total = sorted(total_counts.items(), key=lambda x: -x[1])
for name, total in ranked_by_total[:20]:
    correct = correct_counts.get(name, 0)
    incorrect = incorrect_counts.get(name, 0)
    fp_rate = incorrect / total * 100 if total > 0 else 0
    print(f"{name:<20} {total:>7} {correct:>9} {incorrect:>11} {fp_rate:>8.1f}%")

print("\n(FP Rate = % of this actor's top-5 appearances that were WRONG")
print(" -- i.e. the actor appeared in the top-5 for a query it was NOT")
print(" the correct answer to. High total occurrence + high FP rate =")
print(" genuine hub/false-positive behavior. High total occurrence +")
print(" low FP rate = genuinely frequently-correct, strong actor.)")