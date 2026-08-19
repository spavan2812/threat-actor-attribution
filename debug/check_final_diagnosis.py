import os, sys, re, json
sys.path.insert(0, "src")
from entity_extractor import extract_explicit_ttps
from attribution_engine import TOOL_TO_ACTOR


fpath = "guru_dataset/threat_actors_added_data/Kimsuky/Academia.txt"
with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
    text = f.read().strip()
print("Explicit TTPs found in Academia.txt:", extract_explicit_ttps(text))
print()

fpath2 = "guru_dataset/threat_actors_added_data/Kimsuky/ChromeExtention.txt"
with open(fpath2, "r", encoding="utf-8", errors="ignore") as f:
    text2 = f.read().strip().lower()

print(f"TOOL_TO_ACTOR has {len(TOOL_TO_ACTOR)} entries")
matches = [tool for tool in TOOL_TO_ACTOR if tool.lower() in text2]
print("TOOL_TO_ACTOR entries found in ChromeExtention.txt:", matches)
for m in matches:
    print(f"  {m} -> {TOOL_TO_ACTOR[m]}")
