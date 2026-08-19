import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from OTXv2 import OTXv2


socket.setdefaulttimeout(30)

_executor = ThreadPoolExecutor(max_workers=12)


def call_with_timeout(func, timeout, *args, **kwargs):
    
    future = _executor.submit(func, *args, **kwargs)
    return future.result(timeout=timeout)



def load_actors_from_knowledge_base(kb_path="data/unified/knowledge_base.json",
                                     limit_to=None):
    
    with open(kb_path, "r") as f:
        kb = json.load(f)

    if limit_to is not None:
        kb = [a for a in kb if a["name"] in limit_to]

    search_terms = {}
    for actor in kb:
        terms = [actor["name"]] + actor.get("aliases", [])[:3]
        # dedupe while preserving order
        seen = set()
        deduped = []
        for t in terms:
            if t and t.lower() not in seen:
                seen.add(t.lower())
                deduped.append(t)
        search_terms[actor["name"]] = deduped

    return search_terms



EVAL_ACTORS = [
    "APT29", "APT28", "Lazarus Group", "Sandworm Team",
    "Kimsuky", "APT41", "OilRig", "Winnti Group",
]
ACTOR_SEARCH_TERMS = load_actors_from_knowledge_base(limit_to=None)  # FULL 189-actor run


RELEVANT_TYPES = {
    "IPv4": "ip",
    "domain": "domain",
    "hostname": "domain",
    "FileHash-MD5": "hash",
    "FileHash-SHA1": "hash",
    "FileHash-SHA256": "hash",
}


def get_otx_client():
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Set the OTX_API_KEY environment variable first. "
            "Get a free key at https://otx.alienvault.com after "
            "signing up, found on your account's API page."
        )
    return OTXv2(api_key)


def fetch_all_pulses_parallel(otx, actor_search_terms, max_pulses=8):
    
    # Flatten to a list of (actor_name, term) pairs
    all_pairs = [
        (actor_name, term)
        for actor_name, terms in actor_search_terms.items()
        for term in terms
    ]
    total = len(all_pairs)
    print(f"Searching OTX across {total} (actor, alias) pairs "
          f"for {len(actor_search_terms)} actors, "
          f"in parallel...\n", flush=True)

    futures = {
        _executor.submit(otx.search_pulses, term, max_results=max_pulses): (actor_name, term)
        for actor_name, term in all_pairs
    }

    pulse_registry = {}
    completed = 0
    failed = 0
    failed_terms = []

    for future in futures:
        actor_name, term = futures[future]
        completed += 1
        if completed % 10 == 0 or completed == total:
            print(f"  [{completed}/{total}] searches complete "
                  f"({failed} failed so far)...", flush=True)
        try:
            results = future.result(timeout=30)
        except FutureTimeoutError:
            failed += 1
            failed_terms.append((actor_name, term, "timeout"))
            continue
        except Exception as e:
            failed += 1
            failed_terms.append((actor_name, term, str(e)))
            continue

        for pulse in results.get("results", [])[:max_pulses]:
            pulse_id = pulse.get("id")
            if not pulse_id:
                continue
            if pulse_id not in pulse_registry:
                pulse_registry[pulse_id] = {"pulse": pulse, "actors": set()}
            pulse_registry[pulse_id]["actors"].add(actor_name)

    print(f"\nSearch phase complete: {len(pulse_registry)} unique "
          f"pulses found across all actors ({failed} of {total} "
          f"searches failed/timed out and were skipped).\n",
          flush=True)
    if failed_terms:
        print("Failed searches (actor, search term, reason):")
        for actor_name, term, reason in failed_terms:
            print(f"  {actor_name:20s} '{term}'  -- {reason}")
        print()

    
    os.makedirs("data/otx", exist_ok=True)
    serialisable = {
        pid: {"pulse": entry["pulse"], "actors": sorted(entry["actors"])}
        for pid, entry in pulse_registry.items()
    }
    with open("data/otx/pulse_registry.json", "w") as f:
        json.dump(serialisable, f, indent=2)
    print(f"Saved {len(pulse_registry)} pulses to "
          f"data/otx/pulse_registry.json -- the search phase never "
          f"needs to be repeated after this point.\n")

    return pulse_registry, failed_terms



JUNK_PULSE_PATTERNS = [
    "mining domain", "mining pool", "truecar", "auto-generated pulse",
    "new .com domains", "phishing army blocklist", "malware domain feed",
    "cert.pl list", "operation endgame clone",
]


def _is_junk_pulse(pulse_name):
    name_lower = pulse_name.lower()
    return any(pattern in name_lower for pattern in JUNK_PULSE_PATTERNS)


def fetch_all_indicators_parallel(otx, pulse_registry, already_done=None,
                                   batch_size=6, batch_delay=2.0,
                                   fetch_timeout=60, max_attempts=2):
    
    already_done = already_done or set()
    attempt_counts = _load_attempt_counts()
    given_up = _load_given_up_ids()

    junk_ids = {
        pid for pid, entry in pulse_registry.items()
        if _is_junk_pulse(entry["pulse"].get("name", ""))
    }
    if junk_ids:
        print(f"Filtering out {len(junk_ids)} generic/non-actor-relevant "
              f"pulses (blocklists, mining domain lists, etc.) that "
              f"wouldn't contribute useful attribution data anyway.\n")

    remaining = [
        pid for pid in pulse_registry
        if pid not in already_done
        and pid not in given_up
        and pid not in junk_ids
    ]
    total = len(remaining)
    skipped_done = len(already_done & set(pulse_registry.keys()))
    skipped_given_up = len(given_up & set(pulse_registry.keys()))
    if skipped_done:
        print(f"Resuming: skipping {skipped_done} pulses already "
              f"completed in a previous run.")
    if skipped_given_up:
        print(f"Skipping {skipped_given_up} pulses that failed "
              f"{max_attempts}+ times previously and have been "
              f"given up on (too large/slow to fetch within the "
              f"timeout).")
    print(f"\nFetching indicators for {total} pulses, in batches of "
          f"{batch_size} with a {batch_delay}s pause between "
          f"batches, {fetch_timeout}s timeout per request...\n",
          flush=True)

    found = []
    completed = 0
    failed = 0
    failed_pulses = []
    succeeded_ids = set()
    checkpoint_every = 50

    for batch_start in range(0, total, batch_size):
        batch = remaining[batch_start:batch_start + batch_size]
        futures = {
            _executor.submit(otx.get_pulse_indicators, pid): pid
            for pid in batch
        }

        for future in futures:
            pulse_id = futures[future]
            entry = pulse_registry[pulse_id]
            pulse_name = entry["pulse"].get("name", "")
            actors = entry["actors"]
            completed += 1

            if completed % 10 == 0 or completed == total:
                print(f"  [{completed}/{total}] indicator fetches "
                      f"complete ({failed} failed so far)...",
                      flush=True)

            try:
                indicators = future.result(timeout=fetch_timeout)
            except FutureTimeoutError:
                failed += 1
                attempt_counts[pulse_id] = attempt_counts.get(pulse_id, 0) + 1
                failed_pulses.append((pulse_id, pulse_name, "timeout"))
                if attempt_counts[pulse_id] >= max_attempts:
                    given_up.add(pulse_id)
                    print(f"      FAILED: {pulse_name[:50]} -- timeout "
                          f"(attempt {attempt_counts[pulse_id]}, "
                          f"giving up on this pulse)", flush=True)
                else:
                    print(f"      FAILED: {pulse_name[:50]} -- timeout "
                          f"(attempt {attempt_counts[pulse_id]}, "
                          f"will retry on next run)", flush=True)
                _save_attempt_counts(attempt_counts)
                _save_given_up_ids(given_up)
                continue
            except Exception as e:
                failed += 1
                attempt_counts[pulse_id] = attempt_counts.get(pulse_id, 0) + 1
                failed_pulses.append((pulse_id, pulse_name, str(e)))
                if attempt_counts[pulse_id] >= max_attempts:
                    given_up.add(pulse_id)
                print(f"      FAILED: {pulse_name[:50]} -- {e}",
                      flush=True)
                _save_attempt_counts(attempt_counts)
                _save_given_up_ids(given_up)
                continue

            succeeded_ids.add(pulse_id)
            for ind in indicators:
                ind_type = ind.get("type")
                if ind_type in RELEVANT_TYPES:
                    found.append((
                        ind.get("indicator"),
                        RELEVANT_TYPES[ind_type],
                        pulse_name,
                        pulse_id,
                        actors,
                    ))

            if completed % checkpoint_every == 0:
                _save_checkpoint(found)
                _save_succeeded_ids(already_done | succeeded_ids)
                _save_failures_so_far(failed_pulses)
                _save_attempt_counts(attempt_counts)
                _save_given_up_ids(given_up)

       
        if batch_start + batch_size < total:
            time.sleep(batch_delay)

    _save_succeeded_ids(already_done | succeeded_ids)
    _save_attempt_counts(attempt_counts)
    _save_given_up_ids(given_up)

    print(f"\nIndicator fetch phase complete "
          f"({failed} of {total} failed/timed out).\n", flush=True)
    if given_up:
        print(f"{len(given_up)} pulses have now been given up on "
              f"permanently (failed {max_attempts}+ times) and will "
              f"be excluded from all future runs.\n")
    if failed_pulses:
        print("Failed indicator fetches (pulse name, reason):")
        for pulse_id, pulse_name, reason in failed_pulses:
            print(f"  {pulse_name[:50]:50s}  -- {reason}")
        print()
    return found, failed_pulses


def _save_succeeded_ids(succeeded_ids):
    """Persists which pulse IDs have been successfully processed, for resume support."""
    with open("data/otx/succeeded_pulse_ids.json", "w") as f:
        json.dump(sorted(succeeded_ids), f)


def _save_failures_so_far(failed_pulses):
    
    with open("data/otx/failed_indicator_fetches_live.json", "w") as f:
        json.dump([
            {"pulse_id": pid, "pulse_name": pn, "reason": r}
            for pid, pn, r in failed_pulses
        ], f, indent=2)


def _load_succeeded_ids():
    path = "data/otx/succeeded_pulse_ids.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return set(json.load(f))
    return set()


def _save_attempt_counts(attempt_counts):
    """Persists how many times each pulse has been attempted, across runs."""
    os.makedirs("data/otx", exist_ok=True)
    with open("data/otx/pulse_attempt_counts.json", "w") as f:
        json.dump(attempt_counts, f)


def _load_attempt_counts():
    path = "data/otx/pulse_attempt_counts.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def _save_given_up_ids(given_up):
    
    os.makedirs("data/otx", exist_ok=True)
    with open("data/otx/gave_up_pulse_ids.json", "w") as f:
        json.dump(sorted(given_up), f)


def _load_given_up_ids():
    path = "data/otx/gave_up_pulse_ids.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return set(json.load(f))
    return set()


def _save_checkpoint(found_so_far):
    
    new_index = _build_index_from_found(found_so_far)
    existing_index = {}
    if os.path.exists("data/otx/ioc_actor_index.json"):
        with open("data/otx/ioc_actor_index.json", "r") as f:
            existing_index = json.load(f)

    for key, entry in new_index.items():
        if key in existing_index:
            existing_actors = set(existing_index[key].get("actors", []))
            existing_actors.update(entry["actors"])
            existing_index[key]["actors"] = sorted(existing_actors)
            existing_index[key].setdefault("sources", []).extend(
                entry["sources"]
            )
        else:
            existing_index[key] = entry

    os.makedirs("data/otx", exist_ok=True)
    with open("data/otx/ioc_actor_index.json", "w") as f:
        json.dump(existing_index, f, indent=2)
    print(f"    [checkpoint saved: {len(existing_index)} total "
          f"IoCs on disk]", flush=True)


def _build_index_from_found(found):
    ioc_index = {}
    for ioc_value, ioc_type, pulse_name, pulse_id, actors in found:
        if not ioc_value:
            continue
        key = ioc_value.lower().strip()
        if key not in ioc_index:
            ioc_index[key] = {"type": ioc_type, "actors": [], "sources": []}
        for actor_name in actors:
            if actor_name not in ioc_index[key]["actors"]:
                ioc_index[key]["actors"].append(actor_name)
        ioc_index[key]["sources"].append({
            "pulse_name": pulse_name,
            "pulse_id": pulse_id,
        })
    return ioc_index


def build_ioc_actor_index():
    
    otx = get_otx_client()

    pulse_registry_path = "data/otx/pulse_registry.json"
    if os.path.exists(pulse_registry_path):
        print("Found a saved pulse registry from a previous run -- "
              "skipping the search phase and resuming indicator "
              "fetching only.\n")
        with open(pulse_registry_path, "r") as f:
            raw = json.load(f)
        pulse_registry = {
            pid: {"pulse": v["pulse"], "actors": set(v["actors"])}
            for pid, v in raw.items()
        }
        failed_searches = []
    else:
        pulse_registry, failed_searches = fetch_all_pulses_parallel(
            otx, ACTOR_SEARCH_TERMS
        )

    already_done = _load_succeeded_ids()
    found, failed_indicator_fetches = fetch_all_indicators_parallel(
        otx, pulse_registry, already_done=already_done
    )

    
    ioc_index = {}
    if os.path.exists("data/otx/ioc_actor_index.json"):
        with open("data/otx/ioc_actor_index.json", "r") as f:
            ioc_index = json.load(f)
    new_index = _build_index_from_found(found)
    for key, entry in new_index.items():
        if key in ioc_index:
            existing_actors = set(ioc_index[key].get("actors", []))
            existing_actors.update(entry["actors"])
            ioc_index[key]["actors"] = sorted(existing_actors)
            ioc_index[key].setdefault("sources", []).extend(
                entry["sources"]
            )
        else:
            ioc_index[key] = entry

    per_actor_counts = {name: 0 for name in ACTOR_SEARCH_TERMS}
    for entry in ioc_index.values():
        for actor_name in entry["actors"]:
            if actor_name in per_actor_counts:
                per_actor_counts[actor_name] += 1

    # Save everything that failed, in a format that can be fed
    # straight back in for a targeted retry, rather than needing to
    # rerun the entire 566-term search again from scratch.
    if failed_searches or failed_indicator_fetches:
        os.makedirs("data/otx", exist_ok=True)
        with open("data/otx/failed_fetches.json", "w") as f:
            json.dump({
                "failed_searches": [
                    {"actor": a, "term": t, "reason": r}
                    for a, t, r in failed_searches
                ],
                "failed_indicator_fetches": [
                    {"pulse_id": pid, "pulse_name": pn, "reason": r}
                    for pid, pn, r in failed_indicator_fetches
                ],
            }, f, indent=2)
        print(f"Saved {len(failed_searches)} failed searches and "
              f"{len(failed_indicator_fetches)} failed indicator "
              f"fetches to data/otx/failed_fetches.json for a "
              f"targeted retry later.\n")

    return ioc_index, per_actor_counts


if __name__ == "__main__":
    os.makedirs("data/otx", exist_ok=True)

    ioc_index, per_actor_counts = build_ioc_actor_index()

    with open("data/otx/ioc_actor_index.json", "w") as f:
        json.dump(ioc_index, f, indent=2)

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    covered = {a: c for a, c in per_actor_counts.items() if c > 0}
    uncovered = [a for a, c in per_actor_counts.items() if c == 0]
    print(f"Actors with at least one IoC found: "
          f"{len(covered)} / {len(per_actor_counts)}\n")
    for actor, count in sorted(covered.items(), key=lambda x: -x[1]):
        print(f"  {actor:25s} {count} indicators")
    if uncovered:
        print(f"\n{len(uncovered)} actors had no IoCs found "
              f"(no OTX pulses matched, or all matching searches "
              f"failed/timed out): {', '.join(uncovered[:15])}"
              f"{' ...' if len(uncovered) > 15 else ''}")
    print(f"\nTotal unique IoCs indexed: {len(ioc_index)}")
    print("Saved to data/otx/ioc_actor_index.json")

    # Flag IoCs shared across multiple actors — these are NOT
    # reliable direct signals (same reasoning as shared tools like
    # Mimikatz in attribution_engine.py) and should be treated as
    # weak/generic evidence, not exclusive attribution.
    shared = {k: v for k, v in ioc_index.items()
              if len(v["actors"]) > 1}
    if shared:
        print(f"\n{len(shared)} IoCs were associated with more than "
              f"one actor (not usable as exclusive/direct signals):")
        for k, v in list(shared.items())[:5]:
            print(f"  {k} -> {v['actors']}")