import sys, json
sys.path.insert(0, "src")
from attribution_engine import load_groups_with_idf
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from entity_extractor import extract_entities

groups, idf_weights = load_groups_with_idf()
model, embeddings, semantic_profiles = load_semantic_components()
ioc_index = load_ioc_index()

t5 = """
            Between March and July 2025, a sophisticated campaign
            targeted diplomatic missions and foreign ministries in
            Seoul and other regions. Initial access relied on highly
            tailored spearphishing emails impersonating trusted
            diplomatic contacts, using password-protected ZIP
            attachments concealing Windows shortcut files. Opening the
            shortcut triggered obfuscated PowerShell scripts that
            fetched a remote access trojan family. Rather than using
            traditional command-and-control infrastructure, the
            malware used GitHub repositories as a covert C2 channel via
            the GitHub API, blending malicious traffic with legitimate
            HTTPS activity, with the objective of harvesting sensitive
            diplomatic communications and system reconnaissance data.
        """

entities = extract_entities(t5, {})
print("geographies:", entities["geographies"])
print("origin_countries:", entities["origin_countries"])
print()

results = hybrid_attribute(
    query_text=t5, model=model, embeddings=embeddings,
    semantic_profiles=semantic_profiles, groups=groups,
    ioc_index=ioc_index, top_n=5
)
for r in results:
    print(json.dumps(r, indent=2))
