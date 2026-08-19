import os, sys, random, json
sys.path.insert(0, "src")
from kill_chain_sequencing import (
    build_technique_phase_map, extract_ordered_techniques,
    techniques_to_phase_sequence, score_by_transition_overlap,
    build_actor_phase_profiles
)

BASE_PATH = "guru_dataset/threat_actors_added_data"
MIN_REPORTS_FOR_PROFILE = 5
HELD_OUT_PER_ACTOR = 3

phase_map = build_technique_phase_map()

all_files = {}
for actor_folder in os.listdir(BASE_PATH):
    actor_dir = os.path.join(BASE_PATH, actor_folder)
    if not os.path.isdir(actor_dir):
        continue
    files = [f for f in os.listdir(actor_dir) if f.endswith(".txt")]
    all_files[actor_folder] = files

rng = random.Random(42)
train_profiles = {}
test_cases = []

for actor, files in all_files.items():
    if len(files) < MIN_REPORTS_FOR_PROFILE + HELD_OUT_PER_ACTOR:
        continue
    shuffled = files[:]
    rng.shuffle(shuffled)
    held_out = shuffled[:HELD_OUT_PER_ACTOR]
    training = shuffled[HELD_OUT_PER_ACTOR:]

    sequences = []
    for fname in training:
        fpath = os.path.join(BASE_PATH, actor, fname)
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        seq = techniques_to_phase_sequence(
            extract_ordered_techniques(text), phase_map
        )
        if len(seq) >= 5:
            sequences.append(seq)

    if len(sequences) >= MIN_REPORTS_FOR_PROFILE:
        train_profiles[actor] = sequences
        for fname in held_out:
            test_cases.append((actor, os.path.join(BASE_PATH, actor, fname)))

print(f"WITHIN-DATASET HELD-OUT TEST (transition overlap, {len(test_cases)} cases)")
print(f"{'Expected':<16} {'Got':<20} {'Top1':<6} {'Score'}")
print("-" * 60)

correct = 0
fired = 0
for actor, fpath in test_cases:
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    scores = score_by_transition_overlap(text, train_profiles, phase_map=phase_map)
    if not scores:
        continue
    fired += 1
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    got, top_score = ranked[0]
    is_correct = got == actor
    if is_correct:
        correct += 1
    print(f"{actor:<16} {got:<20} {'yes' if is_correct else 'no':<6} {top_score:.3f}")

print(f"\nWithin-dataset Top-1: {correct}/{fired} ({correct/fired*100:.1f}%)" if fired else "No cases fired.")

# Cross-source test, same real external cases as before
print(f"\n\nCROSS-SOURCE TEST (transition overlap)")
full_profiles = build_actor_phase_profiles(phase_map=phase_map)

all_cases = []
try:
    from thales_validation import THALES_TEST_CASES
    for c in THALES_TEST_CASES:
        all_cases.append(("Thales", c["expected"], c["description"]))
except Exception as e:
    print(f"Could not load Thales cases: {e}")

try:
    from unit42_validation import UNIT42_TEST_CASES
    for c in UNIT42_TEST_CASES:
        all_cases.append(("Unit 42", c["expected"], c["description"]))
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
    for row in merged:
        raw_gt = row["GT"].strip()
        gt = kb_names.get(raw_gt.lower().strip()) or NAME_CORRECTIONS.get(raw_gt.lower().strip())
        if gt:
            all_cases.append(("CTI-TAA", gt, row["Text"]))
except Exception as e:
    print(f"Could not load CTI-TAA cases: {e}")

PROFILE_NAME_ALIASES = {"Sandworm Team": "Sandworm", "Winnti Group": "Winnti"}

print(f"{'Source':<10} {'Expected':<20} {'Got':<20} {'Top1':<6} {'Score'}")
print("-" * 80)

x_correct = 0
x_fired = 0
for source, expected, text in all_cases:
    profile_key = PROFILE_NAME_ALIASES.get(expected, expected)
    if profile_key not in full_profiles:
        continue
    scores = score_by_transition_overlap(text, full_profiles, phase_map=phase_map)
    if not scores:
        continue
    x_fired += 1
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    got, top_score = ranked[0]
    got_canonical = "Sandworm Team" if got == "Sandworm" else (
        "Winnti Group" if got == "Winnti" else got
    )
    is_correct = got_canonical == expected
    if is_correct:
        x_correct += 1
    print(f"{source:<10} {expected:<20} {got_canonical:<20} "
          f"{'yes' if is_correct else 'no':<6} {top_score:.3f}")

print(f"\nCross-source Top-1: {x_correct}/{x_fired} "
      f"({x_correct/x_fired*100:.1f}%)" if x_fired else "No cases fired.")