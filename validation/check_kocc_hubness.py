import sys, json
sys.path.insert(0, "src")
from collections import Counter
from hybrid_engine import load_semantic_components, get_semantic_scores
import statistics

model, embeddings, semantic_profiles = load_semantic_components()

queries = []

from evaluation import TEST_CASES
for c in TEST_CASES:
    queries.append(("dev_set", c["id"], c["description"]))

try:
    from thales_validation import THALES_TEST_CASES
    for c in THALES_TEST_CASES:
        queries.append(("thales", c["id"], c["description"]))
except Exception as e:
    print(f"Could not load Thales cases: {e}")

try:
    from unit42_validation import UNIT42_TEST_CASES
    for c in UNIT42_TEST_CASES:
        queries.append(("unit42", c["id"], c["description"]))
except Exception as e:
    print(f"Could not load Unit 42 cases: {e}")

try:
    merged = json.load(open("cti_taa_merged.json"))
    for i, row in enumerate(merged):
        queries.append(("cti_taa", f"CTA{i}", row["Text"]))
except Exception as e:
    print(f"Could not load CTI-TAA cases: {e}")

print(f"Total real, diverse queries for k-occurrence analysis: {len(queries)}\n")

K = 5  
occurrence_counts = Counter()

for source, qid, text in queries:
    scores = get_semantic_scores(text, model, embeddings, semantic_profiles)
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    top_k_names = [name for name, _ in ranked[:K]]
    for name in top_k_names:
        occurrence_counts[name] += 1

n_actors = len(semantic_profiles)
n_queries = len(queries)
expected_occurrence = (K * n_queries) / n_actors  # uniform-distribution baseline

print(f"Expected k-occurrence under a UNIFORM (non-hub) distribution: "
      f"{expected_occurrence:.2f} per actor\n")


all_counts = [occurrence_counts.get(p["name"], 0) for p in semantic_profiles]
mean_count = statistics.mean(all_counts)
std_count = statistics.pstdev(all_counts)


n = len(all_counts)
skewness = (sum((c - mean_count) ** 3 for c in all_counts) / n) / (std_count ** 3) if std_count > 0 else 0

print(f"Mean k-occurrence: {mean_count:.2f}")
print(f"Std dev: {std_count:.2f}")
print(f"SKEWNESS of k-occurrence distribution: {skewness:.3f}")
print("(0 = symmetric/no hubness; positive = right-skewed, a small")
print(" number of actors dominate top-k far more than expected --")
print(" the real, standard signature of hubness)\n")

# Real, top hub actors by this proper measure
ranked_hubs = sorted(occurrence_counts.items(), key=lambda x: -x[1])
print(f"Top 15 actors by REAL k-occurrence (out of {n_queries} real, diverse queries, k={K}):")
print(f"{'Actor':<20} {'Occurrences':>12} {'vs Expected':>12}")
print("-" * 46)
for name, count in ranked_hubs[:15]:
    ratio = count / expected_occurrence if expected_occurrence > 0 else 0
    print(f"{name:<20} {count:>12} {ratio:>11.1f}x")

# Gini coefficient -- a second, standard concentration measure
sorted_counts = sorted(all_counts)
cum = 0
gini_numerator = 0
for i, c in enumerate(sorted_counts):
    gini_numerator += (2 * (i + 1) - n - 1) * c
gini = gini_numerator / (n * sum(sorted_counts)) if sum(sorted_counts) > 0 else 0
print(f"\nGini coefficient of k-occurrence distribution: {gini:.3f}")
print("(0 = perfectly even distribution; 1 = maximal concentration)")