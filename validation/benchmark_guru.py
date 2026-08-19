import os
import json
from collections import defaultdict

# Actors present in BOTH TRACE's evaluation set and Guru et al.'s
# real dataset -- direct, fair overlap, no invented ground truth
OVERLAPPING_ACTORS = {
    "APT28": "APT28",
    "APT29": "APT29",
    "Lazarus Group": "Lazarus Group",
    "Kimsuky": "Kimsuky",
    "OilRig": "OilRig",
    "Sandworm": "Sandworm Team",   # their folder name -> TRACE's canonical name
    "Winnti Group": "Winnti Group",
}


def load_guru_dataset(base_path="guru_dataset/threat_actors_added_data"):
    """
    Loads real report text files from Guru et al.'s dataset folder
    structure: {base_path}/{ActorFolderName}/*.txt

    Returns list of (text, expected_actor_trace_name) tuples, only
    for actors present in TRACE's own evaluation set.
    """
    cases = []
    for folder_name, trace_name in OVERLAPPING_ACTORS.items():
        actor_dir = os.path.join(base_path, folder_name)
        if not os.path.isdir(actor_dir):
            print(f"  WARNING: folder not found for {folder_name} "
                  f"(expected at {actor_dir}) -- skipping")
            continue

        files = [f for f in os.listdir(actor_dir) if f.endswith(".txt")]
        for fname in files:
            fpath = os.path.join(actor_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read().strip()
                if len(text) > 50:  # skip near-empty files
                    cases.append((text, trace_name, fname))
            except Exception as e:
                print(f"  Could not read {fpath}: {e}")

    return cases


def run_benchmark(cases, hybrid_attribute_fn, model, embeddings,
                  semantic_profiles, groups, malware_index=None,
                  idf_weights=None, max_per_actor=15):
    
    import random
    rng = random.Random(42)

    by_actor = defaultdict(list)
    for text, actor, fname in cases:
        by_actor[actor].append((text, fname))

    total_to_process = sum(min(max_per_actor, len(items)) for items in by_actor.values())
    processed = 0
    print(f"Processing {total_to_process} reports (capped at "
          f"{max_per_actor} per actor)...\n")

    results = []
    for actor, items in by_actor.items():
        sampled = rng.sample(items, min(max_per_actor, len(items)))
        print(f"[{actor}] {len(sampled)} reports to process...")
        for text, fname in sampled:
            processed += 1
            print(f"  [{processed}/{total_to_process}] {fname}...",
                  flush=True)
            try:
                predictions = hybrid_attribute_fn(
                    text, model, embeddings, semantic_profiles, groups,
                    malware_index=malware_index, idf_weights=idf_weights,
                    top_n=len(groups)  # need full ranking for average-rank metric
                )
            except Exception as e:
                print(f"    Attribution failed on {fname}: {e}")
                continue

            names = [p["name"] for p in predictions]
            rank = names.index(actor) + 1 if actor in names else len(groups) + 1
            top1 = rank == 1
            top3 = rank <= 3

            results.append({
                "actor": actor, "file": fname, "rank": rank,
                "top1": top1, "top3": top3,
            })

    return results


def summarise(results, n_total_actors_in_trace_kb):
    n = len(results)
    if n == 0:
        print("No results -- check dataset path and folder structure.")
        return

    avg_rank = sum(r["rank"] for r in results) / n
    top1 = sum(r["top1"] for r in results)
    top3 = sum(r["top3"] for r in results)

    print("\n" + "=" * 60)
    print("BENCHMARK vs Guru et al. (2025) REAL DATASET")
    print("=" * 60)
    print(f"Total real reports tested: {n}")
    print(f"Average rank of correct actor: {avg_rank:.2f}  "
          f"(their own reported metric; lower is better; "
          f"their paper reports 7.55 out of 29 actors)")
    print(f"Top-1 accuracy: {top1}/{n} ({top1/n*100:.1f}%)")
    print(f"Top-3 accuracy: {top3}/{n} ({top3/n*100:.1f}%)")
    print(f"\nNote: TRACE's search space is {n_total_actors_in_trace_kb} "
          f"actors, versus their 29 -- a harder discrimination task "
          f"by construction. State this explicitly alongside any "
          f"average-rank comparison.")

    print("\nPer-actor breakdown:")
    by_actor = defaultdict(list)
    for r in results:
        by_actor[r["actor"]].append(r["rank"])
    for actor, ranks in sorted(by_actor.items()):
        avg = sum(ranks) / len(ranks)
        print(f"  {actor:20s} n={len(ranks):3d}  avg_rank={avg:.2f}")

    with open("data/guru_benchmark_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved to data/guru_benchmark_results.json")


if __name__ == "__main__":
    from hybrid_engine import hybrid_attribute, load_semantic_components
    from attribution_engine import load_groups_with_idf

    print("Loading model and knowledge base...")
    model, embeddings, semantic_profiles = load_semantic_components()
    groups, idf_weights = load_groups_with_idf()

    try:
        with open("data/malpedia/malware_actor_index.json") as f:
            malware_index = json.load(f)
    except FileNotFoundError:
        malware_index = {}

    print("Loading Guru et al. (2025) real dataset...")
    cases = load_guru_dataset()
    print(f"Loaded {len(cases)} real reports across "
          f"{len(set(c[1] for c in cases))} overlapping actors\n")

    if not cases:
        print("\nNo cases loaded. Make sure the dataset is downloaded "
              "from the Google Drive link in the repo README and "
              "placed at guru_dataset/threat_actors_added_data/ "
              "with per-actor subfolders.")
    else:
        results = run_benchmark(
            cases, hybrid_attribute, model, embeddings,
            semantic_profiles, groups, malware_index, idf_weights
        )
        summarise(results, len(groups))