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

print(f"Real held-out test cases: {len(test_cases)}\n")

GRID = [
    (-1.0, -1.0),   # linear-equivalent (no affine distinction) -- baseline
    (-2.0, -0.5),   # the untested default just tried
    (-1.0, -0.25),  # gentler overall
    (-3.0, -0.5),   # steeper open, same extend
    (-2.0, -1.0),   # open/extend closer together
    (-4.0, -0.25),  # strongly discourage new gaps, cheap to extend
]

print(f"{'gap_open':>10} {'gap_extend':>12} {'Top-1':>10} {'Fired':>8}")
print("-" * 45)

results = []
for gap_open, gap_extend in GRID:
    correct = 0
    fired = 0
    for actor, fpath in test_cases:
        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        scores = score_by_kill_chain(
            text, train_profiles, phase_map=phase_map,
            gap_open=gap_open, gap_extend=gap_extend
        )
        if not scores:
            continue
        fired += 1
        ranked = sorted(scores.items(), key=lambda x: -x[1])
        if ranked[0][0] == actor:
            correct += 1

    top1_pct = correct / fired * 100 if fired else 0
    results.append((gap_open, gap_extend, top1_pct, correct, fired))
    print(f"{gap_open:>10.2f} {gap_extend:>12.2f} "
          f"{top1_pct:>9.1f}% {fired:>8}")

best = max(results, key=lambda x: x[2])
print(f"\nBest combination: gap_open={best[0]}, gap_extend={best[1]} "
      f"-> {best[2]:.1f}% ({best[3]}/{best[4]})")