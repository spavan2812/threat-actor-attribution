import os, sys, json
sys.path.insert(0, "src")
from kill_chain_sequencing import build_technique_phase_map, build_actor_phase_profiles, score_by_kill_chain

# Build FULL profiles (all real Guru et al. data, no held-out split
# needed -- the test cases below come from entirely different real
# sources, so there's no leakage risk to guard against here).
print("Building technique-to-phase map...")
phase_map = build_technique_phase_map()

print("Building full actor phase profiles from Guru et al. dataset...")
profiles = build_actor_phase_profiles(phase_map=phase_map)
print(f"Real profiles built for {len(profiles)} actors: "
      f"{sorted(profiles.keys())}\n")

# Gather real test cases from all three independent external sources
all_cases = []  # list of (source, expected_actor, text)

# Thales
try:
    from thales_validation import THALES_TEST_CASES
    for c in THALES_TEST_CASES:
        all_cases.append(("Thales", c["expected"], c["description"]))
except Exception as e:
    print(f"Could not load Thales cases: {e}")

# Unit 42
try:
    from unit42_validation import UNIT42_TEST_CASES
    for c in UNIT42_TEST_CASES:
        all_cases.append(("Unit 42", c["expected"], c["description"]))
except Exception as e:
    print(f"Could not load Unit 42 cases: {e}")

# CTI-TAA (real ground truth from the actual benchmark)
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

print(f"Total real cases across all 3 sources: {len(all_cases)}\n")

# Real profile names use Guru et al.'s own folder naming, which may
# differ slightly from TRACE's canonical KB names (e.g. "Sandworm"
# vs "Sandworm Team"). Map both directions so a real match isn't
# missed purely due to naming.
PROFILE_NAME_ALIASES = {
    "Sandworm Team": "Sandworm",
    "Winnti Group": "Winnti",
}

print(f"{'Source':<10} {'Expected':<20} {'Got':<20} {'Top1':<6} {'Score'}")
print("-" * 80)

correct = 0
fired = 0
tested_actor_missing = 0

for source, expected, text in all_cases:
    profile_key = PROFILE_NAME_ALIASES.get(expected, expected)
    if profile_key not in profiles:
        tested_actor_missing += 1
        continue

    scores = score_by_kill_chain(text, profiles, phase_map=phase_map)
    if not scores:
        continue

    fired += 1
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    got, top_score = ranked[0]
    # Reverse-map for comparison
    got_canonical = "Sandworm Team" if got == "Sandworm" else (
        "Winnti Group" if got == "Winnti" else got
    )
    is_correct = got_canonical == expected
    if is_correct:
        correct += 1

    print(f"{source:<10} {expected:<20} {got_canonical:<20} "
          f"{'yes' if is_correct else 'no':<6} {top_score:.3f}")

print(f"\nCases where expected actor has no real kill-chain profile "
      f"(skipped): {tested_actor_missing}")
print(f"Cases where query sequence too short (no signal): "
      f"{len(all_cases) - tested_actor_missing - fired}")
print(f"\nTop-1 accuracy on cases that fired: "
      f"{correct}/{fired} ({correct/fired*100:.1f}%)" if fired else
      "No cases produced a usable sequence.")