import os, sys, random
sys.path.insert(0, "src")
from kill_chain_sequencing import (
    build_technique_phase_map, extract_ordered_techniques,
    techniques_to_phase_sequence, score_by_kill_chain
)

BASE_PATH = "guru_dataset/threat_actors_added_data"
MIN_REPORTS_FOR_PROFILE = 5
HELD_OUT_PER_ACTOR = 3

phase_map = build_technique_phase_map()
print(f"Mapped {len(phase_map)} techniques.\n")

# Gather all real files per actor first
all_files = {}
for actor_folder in os.listdir(BASE_PATH):
    actor_dir = os.path.join(BASE_PATH, actor_folder)
    if not os.path.isdir(actor_dir):
        continue
    files = [f for f in os.listdir(actor_dir) if f.endswith(".txt")]
    all_files[actor_folder] = files

rng = random.Random(42)
train_profiles = {}
test_cases = []  # list of (actor, filepath)

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

print(f"Actors with real held-out test: {list(train_profiles.keys())}")
print(f"Total held-out test cases: {len(test_cases)}\n")

print(f"{'Expected':<16} {'File':<40} {'Got':<16} {'Top1':<6} {'Score'}")
print("-" * 95)

correct = 0
fired = 0
for actor, fpath in test_cases:
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    scores = score_by_kill_chain(text, train_profiles, phase_map=phase_map)
    if not scores:
        print(f"{actor:<16} {os.path.basename(fpath):<40} "
              f"{'(no sequence)':<16}")
        continue

    fired += 1
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    got, top_score = ranked[0]
    is_correct = got == actor
    if is_correct:
        correct += 1

    print(f"{actor:<16} {os.path.basename(fpath):<40} {got:<16} "
          f"{'yes' if is_correct else 'no':<6} {top_score:.3f}")

print(f"\nTop-1 accuracy (kill-chain scoring alone): "
      f"{correct}/{fired} ({correct/fired*100:.1f}%)" if fired else
      "No test cases produced a usable sequence.")
print(f"(Random baseline for {len(train_profiles)} actors: "
      f"{100/len(train_profiles):.1f}%)" if train_profiles else "")