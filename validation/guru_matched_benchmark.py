# Threat Actor Attribution System - MATCHED-CANDIDATE-SPACE
# Benchmark against Guru et al. (2025)
# ELE8095 OO05 - Sai Pavan Yoganand
#
# Restricts TRACE's candidate pool to the 27 real, confirmed
# overlapping actors between Guru et al.'s dataset and TRACE's own
# knowledge base (verified directly, including a correction for a
# real alias-cluster contamination bug found between Lazarus Group
# and AppleJeus), giving an average rank directly comparable to Guru
# et al.'s own published figures (7.55 best config / 10.68 baseline,
# chance = 15.0 on their 29-actor scale), rather than the earlier
# normalised "percentage of chance" comparison across mismatched
# candidate-space sizes.

import os
import json
import random
from collections import defaultdict

import sys
sys.path.insert(0, "src")
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf

# Real, verified mapping: Guru et al. folder name -> TRACE canonical
# name, for all 27 confirmed overlaps (Lazarus Group corrected after
# discovering it was being silently overwritten by AppleJeus's
# alias-cluster contamination in the naive lookup)
OVERLAP_MAP = {
    "APT17": "APT17", "APT28": "APT28", "APT29": "APT29", "APT3": "APT3",
    "APT32": "APT32", "APT33": "APT33", "APT39": "APT39",
    "Cobalt Group": "Cobalt Group", "DragonFly": "Dragonfly 2.0",
    "FIN6": "FIN6", "FIN7": "FIN7", "Gamaredon Group": "Gamaredon Group",
    "Kimsuky": "Kimsuky", "Lazarus Group": "Lazarus Group",
    "Magic Hound": "Magic Hound", "MuddyWater": "MuddyWater",
    "OilRig": "OilRig", "Sandworm": "Sandworm Team", "TA505": "TA505",
    "TeamTNT": "TeamTNT", "Threat Group-3390": "Threat Group-3390",
    "Tonto Team": "Tonto Team", "Tropic Trooper": "Tropic Trooper",
    "Turla": "Turla", "Winnti Group": "Winnti Group",
    "Wizard Spider": "Wizard Spider", "menuPass": "menuPass",
}

MAX_PER_ACTOR = 15  # same cap as the original benchmark, for fairness

def load_guru_dataset(base_path="guru_dataset/threat_actors_added_data"):
    cases = []
    for folder_name, trace_name in OVERLAP_MAP.items():
        actor_dir = os.path.join(base_path, folder_name)
        if not os.path.isdir(actor_dir):
            continue
        files = [f for f in os.listdir(actor_dir) if f.endswith(".txt")]
        for fname in files:
            fpath = os.path.join(actor_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read().strip()
                if len(text) > 50:
                    cases.append((text, trace_name, fname))
            except Exception:
                pass
    return cases

print("Loading components...")
groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

try:
    with open("data/malpedia/malware_actor_index.json") as f:
        malware_index = json.load(f)
except FileNotFoundError:
    malware_index = {}

# REAL restriction: filter groups (for keyword/tool/sector/motivation/
# country/IoC engines) AND semantic_profiles+embeddings (for the
# semantic engine) down to ONLY the 27 confirmed-overlap actors,
# keeping embeddings correctly aligned with the filtered profile list
allowed_names = set(OVERLAP_MAP.values())
restricted_groups = [g for g in groups if g["name"] in allowed_names]

restricted_indices = [i for i, p in enumerate(semantic_profiles) if p["name"] in allowed_names]
restricted_semantic_profiles = [semantic_profiles[i] for i in restricted_indices]
restricted_embeddings = embeddings[restricted_indices]

print(f"Restricted candidate space: {len(restricted_groups)} actors "
      f"(from {len(groups)} full KB)")
print(f"Restricted semantic profiles: {len(restricted_semantic_profiles)}\n")

print("Loading Guru et al. real dataset...")
cases = load_guru_dataset()
print(f"Loaded {len(cases)} real reports\n")

rng = random.Random(42)
by_actor = defaultdict(list)
for text, actor, fname in cases:
    by_actor[actor].append((text, fname))

results = []
total = sum(min(MAX_PER_ACTOR, len(v)) for v in by_actor.values())
processed = 0

for actor, items in by_actor.items():
    sampled = rng.sample(items, min(MAX_PER_ACTOR, len(items)))
    for text, fname in sampled:
        processed += 1
        print(f"  [{processed}/{total}] {actor} / {fname}...", flush=True)
        try:
            predictions = hybrid_attribute(
                query_text=text, model=model, embeddings=restricted_embeddings,
                semantic_profiles=restricted_semantic_profiles,
                groups=restricted_groups, malware_index=malware_index,
                ioc_index=ioc_index, top_n=len(restricted_groups)
            )
        except Exception as e:
            print(f"    Failed: {e}")
            continue

        names = [p["name"] for p in predictions]
        rank = names.index(actor) + 1 if actor in names else len(restricted_groups) + 1
        results.append({"actor": actor, "file": fname, "rank": rank,
                         "top1": rank == 1, "top3": rank <= 3})

n = len(results)
avg_rank = sum(r["rank"] for r in results) / n
top1 = sum(r["top1"] for r in results)
top3 = sum(r["top3"] for r in results)

print("\n" + "="*65)
print("MATCHED-CANDIDATE-SPACE BENCHMARK vs Guru et al. (2025)")
print("="*65)
print(f"Candidate space: {len(restricted_groups)} actors (matched to Guru et al.'s real overlap)")
print(f"Total real reports tested: {n}")
print(f"Average rank of correct actor: {avg_rank:.2f}")
print(f"  (Guru et al. published: 7.55 best config / 10.68 baseline / chance=15.0 on 29 actors)")
print(f"  (Chance on THIS {len(restricted_groups)}-actor space: {len(restricted_groups)/2:.2f})")
print(f"Top-1 accuracy: {top1}/{n} ({top1/n*100:.1f}%)")
print(f"Top-3 accuracy: {top3}/{n} ({top3/n*100:.1f}%)")

with open("data/guru_matched_benchmark_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nSaved to data/guru_matched_benchmark_results.json")
