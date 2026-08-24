import os, json, random
from collections import defaultdict

import sys
sys.path.insert(0, "src")
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf

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
MAX_PER_ACTOR = 15


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


def count_supporting_engines(r):
    keys = ["keyword_score", "tool_score", "sector_score",
            "motivation_score", "country_score", "ioc_score"]
    return sum(1 for k in keys if r.get(k, 0) > 0)


print("Loading components...")
groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

malware_index = {}
if os.path.exists("data/malpedia/malware_actor_index.json"):
    malware_index = json.load(open("data/malpedia/malware_actor_index.json"))

allowed_names = set(OVERLAP_MAP.values())
restricted_groups = [g for g in groups if g["name"] in allowed_names]
restricted_indices = [i for i, p in enumerate(semantic_profiles) if p["name"] in allowed_names]
restricted_semantic_profiles = [semantic_profiles[i] for i in restricted_indices]
restricted_embeddings = embeddings[restricted_indices]

print("Loading Guru et al. real dataset...")
cases = load_guru_dataset()

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
        top1 = rank == 1

        # Real per-case engine data for the TOP prediction specifically
        top_result = predictions[0] if predictions else {}
        direct_signal = top_result.get("direct_signal", False)
        support_count = count_supporting_engines(top_result)

        results.append({
            "actor": actor, "file": fname, "rank": rank, "top1": top1,
            "direct_signal": direct_signal, "support_count": support_count,
        })

n = len(results)
top1_cases = [r for r in results if r["top1"]]
wrong_cases = [r for r in results if not r["top1"]]

print("\n" + "="*70)
print("MECHANISM ANALYSIS: why TRACE performed well on this matched space")
print("="*70)
print(f"Total cases: {n}")
print(f"Top-1 correct: {len(top1_cases)} ({len(top1_cases)/n*100:.1f}%)")
print()

# Direct-signal (exclusive tool/IoC match) firing rate
correct_direct = sum(1 for r in top1_cases if r["direct_signal"])
wrong_direct = sum(1 for r in wrong_cases if r["direct_signal"])
print(f"Direct-signal (exclusive tool/IoC match) fired on CORRECT predictions: "
      f"{correct_direct}/{len(top1_cases)} ({correct_direct/len(top1_cases)*100:.1f}%)")
if wrong_cases:
    print(f"Direct-signal fired on WRONG predictions: "
          f"{wrong_direct}/{len(wrong_cases)} ({wrong_direct/len(wrong_cases)*100:.1f}%)")

# Average engine support
avg_support_correct = sum(r["support_count"] for r in top1_cases) / len(top1_cases)
print(f"\nAverage non-semantic engine support on CORRECT predictions: {avg_support_correct:.2f}")
if wrong_cases:
    avg_support_wrong = sum(r["support_count"] for r in wrong_cases) / len(wrong_cases)
    print(f"Average non-semantic engine support on WRONG predictions: {avg_support_wrong:.2f}")

with open("data/guru_matched_mechanism_results.json", "w") as f:
    json.dump(results, f, indent=2)
print("\nSaved to data/guru_matched_mechanism_results.json")