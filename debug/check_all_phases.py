import json
from collections import Counter

data = json.load(open("data/mitre/enterprise-attack.json"))
objects = data.get("objects", data) if isinstance(data, dict) else data

phase_counts = Counter()
for obj in objects:
    if obj.get("type") == "attack-pattern":
        for kcp in obj.get("kill_chain_phases", []):
            phase_counts[(kcp.get("kill_chain_name"), kcp.get("phase_name"))] += 1

print(f"Total distinct (kill_chain_name, phase_name) pairs: {len(phase_counts)}")
for (chain, phase), count in sorted(phase_counts.items(), key=lambda x: -x[1]):
    print(f"  {chain:<20} {phase:<25} n={count}")
