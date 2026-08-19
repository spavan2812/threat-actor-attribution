import sys
sys.path.insert(0, "src")
from kill_chain_sequencing import build_technique_phase_map, build_actor_phase_profiles, smith_waterman_similarity

phase_map = build_technique_phase_map()
profiles = build_actor_phase_profiles(phase_map=phase_map)

actors = list(profiles.keys())
avg_sim = {}

for actor_a in actors:
    sims_to_others = []
    for actor_b in actors:
        if actor_a == actor_b:
            continue
        best = 0.0
        for seq_a in profiles[actor_a]:
            for seq_b in profiles[actor_b]:
                _, normalised = smith_waterman_similarity(seq_a, seq_b)
                best = max(best, normalised)
        sims_to_others.append(best)
    avg_sim[actor_a] = sum(sims_to_others) / len(sims_to_others)

ranked = sorted(avg_sim.items(), key=lambda x: -x[1])
print("Actors ranked by average similarity to all OTHER actors (potential sequence hubs):")
for name, sim in ranked:
    print(f"  {name:<20} avg_sim={sim:.3f}  n_sequences={len(profiles[name])}")
