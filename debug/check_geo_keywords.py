import sys
sys.path.insert(0, "src")
import entity_extractor

print("south korea" in "malicious windows shortcut files disguised as a legitimate newsletter to south korean academics")
print("'south korea' key present:", "south korea" in entity_extractor.GEOGRAPHY_KEYWORDS)
print("GEOGRAPHY_KEYWORDS full dict:")
for k, v in entity_extractor.GEOGRAPHY_KEYWORDS.items():
    print(f"  {k!r}: {v!r}")
