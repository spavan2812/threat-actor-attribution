import json
import os
import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

ORKL_BASE = "https://orkl.eu/api/v1"
_executor = ThreadPoolExecutor(max_workers=6)

_gpu_lock = threading.Lock()


def call_with_timeout(func, timeout, *args, **kwargs):
    """Same bulletproof timeout pattern used in otx_pipeline.py --
    guarantees control returns after `timeout` seconds regardless of
    what the network call is doing."""
    future = _executor.submit(func, *args, **kwargs)
    return future.result(timeout=timeout)


def search_orkl(actor_name, limit=10):
    
    url = f"{ORKL_BASE}/library/search"
    params = {"query": actor_name, "full": "true", "limit": limit}
    headers = {
        "Accept": "application/json",
        "User-Agent": "TRACE-research-project/1.0",
    }
    resp = requests.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def extract_report_text(report):
    
    for field in ("plain_text", "full_text", "content", "text"):
        if report.get(field):
            return report[field]
    return report.get("summary") or report.get("title") or ""


def redact_actor_names(text, ground_truth_names, groups):
       import re

    names_to_redact = set()
    for gt_name in ground_truth_names:
        for group in groups:
            if group["name"] == gt_name:
                names_to_redact.add(group["name"])
                names_to_redact.update(group.get("aliases", []))

    redacted = text
    for name in sorted(names_to_redact, key=len, reverse=True):
        if len(name) < 3:
            continue  # skip very short aliases, too easy to false-match
        pattern = r'\b' + re.escape(name) + r'\b'
        redacted = re.sub(pattern, "[ACTOR]", redacted, flags=re.IGNORECASE)

    return redacted


def get_report_ground_truth_names(report, kb_name_to_canonical):
   
    ground_truth = set()
    for ta in report.get("threat_actors", []):
        candidates = [ta.get("main_name") or ""] + (ta.get("aliases") or [])
        for name in candidates:
            key = name.strip().lower()
            if key in kb_name_to_canonical:
                ground_truth.add(kb_name_to_canonical[key])
    return ground_truth


def build_kb_name_index(groups):
    """Maps every actor name/alias (lowercased) to that actor's canonical name in your knowledge base."""
    index = {}
    for g in groups:
        index[g["name"].strip().lower()] = g["name"]
        for alias in g.get("aliases", []):
            index[alias.strip().lower()] = g["name"]
    return index


def validate_actor(actor_name, hybrid_attribute_fn, model, embeddings,
                    semantic_profiles, groups, malware_index=None,
                    idf_weights=None, max_reports=10, kb_name_index=None):
  
    if kb_name_index is None:
        kb_name_index = build_kb_name_index(groups)

    try:
        results_json = call_with_timeout(search_orkl, 30, actor_name, max_reports)
    except FutureTimeoutError:
        print(f"  ORKL search timed out for {actor_name}")
        return []
    except Exception as e:
        print(f"  ORKL search failed for {actor_name}: {e}")
        return []

    reports = results_json.get("data", results_json.get("results", []))
    if not reports:
        print(f"  No ORKL reports found for {actor_name}")
        return []

    outcomes = []
    for report_num, report in enumerate(reports[:max_reports], 1):
        print(f"  [{actor_name}] report {report_num}/{len(reports[:max_reports])}: "
              f"starting...", flush=True)
        text = extract_report_text(report)
        if not text or len(text) < 50:
            continue

        ground_truth_names = get_report_ground_truth_names(report, kb_name_index)
        if not ground_truth_names:
            
            ground_truth_names = {actor_name}

        try:
            print(f"    [{actor_name}] waiting for GPU...", flush=True)
            with _gpu_lock:
                print(f"    [{actor_name}] full-text pass running...", flush=True)
                predictions = hybrid_attribute_fn(
                    text, model, embeddings, semantic_profiles, groups,
                    malware_index=malware_index, idf_weights=idf_weights,
                    top_n=10
                )
        except Exception as e:
            print(f"    Attribution failed on a report: {e}")
            continue

        names = [p["name"] for p in predictions]
        top1_correct = bool(names) and names[0] in ground_truth_names
        top3_correct = any(n in ground_truth_names for n in names[:3])


        redacted_text = redact_actor_names(text, ground_truth_names, groups)
        redacted_top1_correct = None
        redacted_top3_correct = None
        redacted_predicted = None
        try:
            print(f"    [{actor_name}] waiting for GPU (redacted pass)...", flush=True)
            with _gpu_lock:
                print(f"    [{actor_name}] redacted pass running...", flush=True)
                redacted_predictions = hybrid_attribute_fn(
                    redacted_text, model, embeddings, semantic_profiles, groups,
                    malware_index=malware_index, idf_weights=idf_weights,
                    top_n=10
                )
            redacted_names = [p["name"] for p in redacted_predictions]
            redacted_top1_correct = bool(redacted_names) and redacted_names[0] in ground_truth_names
            redacted_top3_correct = any(n in ground_truth_names for n in redacted_names[:3])
            redacted_predicted = redacted_names[0] if redacted_names else None
        except Exception as e:
            print(f"    Redacted attribution failed on a report: {e}")

        outcomes.append({
            "actor": actor_name,
            "ground_truth": sorted(ground_truth_names),
            "report_title": report.get("title", "")[:80],
            "report_id": report.get("id"),
            "predicted_top1": names[0] if names else None,
            "top1_correct": top1_correct,
            "top3_correct": top3_correct,
            "redacted_predicted_top1": redacted_predicted,
            "redacted_top1_correct": redacted_top1_correct,
            "redacted_top3_correct": redacted_top3_correct,
        })

    return outcomes


def run_orkl_validation(actor_names, hybrid_attribute_fn, model, embeddings,
                         semantic_profiles, groups, malware_index=None,
                         idf_weights=None, max_workers=4):
   
    os.makedirs("data/orkl", exist_ok=True)
    results_path = "data/orkl/validation_results.json"
    completed_path = "data/orkl/completed_actors.json"

    all_outcomes = []
    if os.path.exists(results_path):
        with open(results_path, "r") as f:
            all_outcomes = json.load(f)
        print(f"Loaded {len(all_outcomes)} existing results from a "
              f"previous run.")

    completed_actors = set()
    if os.path.exists(completed_path):
        with open(completed_path, "r") as f:
            completed_actors = set(json.load(f))

    actors_in_results = {o["actor"] for o in all_outcomes}
    if actors_in_results - completed_actors:
        print(f"Found {len(actors_in_results - completed_actors)} "
              f"actors with saved results but no completion record "
              f"(likely from an older run) -- treating them as "
              f"completed rather than redoing them.")
    completed_actors |= actors_in_results

    if completed_actors:
        print(f"{len(completed_actors)} actors already completed -- "
              f"these will be skipped.\n")

    kb_name_index = build_kb_name_index(groups)
    remaining = [a for a in actor_names if a not in completed_actors]

    print(f"Processing {len(remaining)} actors, {max_workers} at a "
          f"time...\n")

    lock = threading.Lock()
    completed_count = [0]

    def process_one(actor_name):
        outcomes = validate_actor(
            actor_name, hybrid_attribute_fn, model, embeddings,
            semantic_profiles, groups, malware_index, idf_weights,
            kb_name_index=kb_name_index
        )
        with lock:
            all_outcomes.extend(outcomes)
            completed_actors.add(actor_name)
            completed_count[0] += 1
            print(f"[{completed_count[0]}/{len(remaining)}] "
                  f"{actor_name}: {len(outcomes)} reports tested")
            # Save incrementally so a long run is never all-or-nothing
            with open(results_path, "w") as f:
                json.dump(all_outcomes, f, indent=2)
            with open(completed_path, "w") as f:
                json.dump(sorted(completed_actors), f)
        return outcomes

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(process_one, a) for a in remaining]
        for f in futures:
            try:
                f.result()
            except Exception as e:
                print(f"  A worker failed: {e}")

    n = len(all_outcomes)
    if n == 0:
        print("\nNo ORKL validation data collected -- check search results "
              "and API response structure above before trusting this run.")
        return all_outcomes

    top1 = sum(1 for o in all_outcomes if o["top1_correct"])
    top3 = sum(1 for o in all_outcomes if o["top3_correct"])

    redacted_evaluated = [o for o in all_outcomes if o.get("redacted_top1_correct") is not None]
    n_red = len(redacted_evaluated)
    red_top1 = sum(1 for o in redacted_evaluated if o["redacted_top1_correct"])
    red_top3 = sum(1 for o in redacted_evaluated if o["redacted_top3_correct"])

    print("\n" + "=" * 60)
    print("ORKL VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total reports tested: {n}")
    print(f"\nWith actor name present in text (as-published reports):")
    print(f"  Top-1 accuracy: {top1}/{n} ({top1/n*100:.1f}%)")
    print(f"  Top-3 accuracy: {top3}/{n} ({top3/n*100:.1f}%)")
    if n_red > 0:
        print(f"\nWith actor name/aliases REDACTED (genuine attribution test):")
        print(f"  Top-1 accuracy: {red_top1}/{n_red} ({red_top1/n_red*100:.1f}%)")
        print(f"  Top-3 accuracy: {red_top3}/{n_red} ({red_top3/n_red*100:.1f}%)")
        gap = (top1/n - red_top1/n_red) * 100
        print(f"\n  Gap: {gap:.1f} percentage points -- this is roughlyr how "
              f"much of the raw accuracy above comes from the actor's own "
              f"name appearing in the report text, versus genuine "
              f"behavioural/TTP/IoC-based attribution.")
    print("\nSaved to data/orkl/validation_results.json")

    return all_outcomes


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

rr
    with open("data/unified/knowledge_base.json") as f:
        all_actors = json.load(f)
    TEST_ACTORS = [a["name"] for a in all_actors]
    print(f"Running ORKL validation across all {len(TEST_ACTORS)} actors "
          f"in the knowledge base...")

    run_orkl_validation(
        TEST_ACTORS, hybrid_attribute, model, embeddings,
        semantic_profiles, groups, malware_index, idf_weights,
        max_workers=4
    )