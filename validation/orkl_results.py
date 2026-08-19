import json
from collections import defaultdict

with open('data/orkl/validation_results.json') as f:
    results = json.load(f)

n = len(results)
top1 = sum(1 for r in results if r['top1_correct'])
top3 = sum(1 for r in results if r['top3_correct'])

redacted = [r for r in results if r.get('redacted_top1_correct') is not None]
n_red = len(redacted)
red_top1 = sum(1 for r in redacted if r['redacted_top1_correct'])
red_top3 = sum(1 for r in redacted if r['redacted_top3_correct'])

actors_tested = len(set(r['actor'] for r in results))

lines = []
lines.append("=" * 60)
lines.append("ORKL VALIDATION - FINAL RESULTS")
lines.append("=" * 60)
lines.append(f"Actors tested: {actors_tested}")
lines.append(f"Total reports tested: {n}")
lines.append("")
lines.append("Full text (as-published reports):")
lines.append(f"  Top-1: {top1}/{n} ({top1/n*100:.1f}%)")
lines.append(f"  Top-3: {top3}/{n} ({top3/n*100:.1f}%)")
lines.append("")
if n_red > 0:
    lines.append("Redacted (actor name stripped -- genuine attribution test):")
    lines.append(f"  Top-1: {red_top1}/{n_red} ({red_top1/n_red*100:.1f}%)")
    lines.append(f"  Top-3: {red_top3}/{n_red} ({red_top3/n_red*100:.1f}%)")
    lines.append("")
    gap = (top1/n - red_top1/n_red) * 100
    lines.append(f"Gap: {gap:.1f} percentage points")

lines.append("")
lines.append("Per-actor accuracy (actors with 3+ reports tested):")
per_actor = defaultdict(lambda: [0, 0])
for r in results:
    per_actor[r['actor']][1] += 1
    if r['top1_correct']:
        per_actor[r['actor']][0] += 1

qualifying = [(a, c, t) for a, (c, t) in per_actor.items() if t >= 3]
qualifying.sort(key=lambda x: x[1]/x[2])
for actor, correct, total in qualifying:
    lines.append(f"  {actor:25s} {correct}/{total} ({correct/total*100:.0f}%)")

output = "\n".join(lines)
print(output)

with open("orkl_summary.txt", "w") as f:
    f.write(output)

print("\nSaved to orkl_summary.txt")