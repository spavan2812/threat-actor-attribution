import sys
sys.path.insert(0, "src")
from entity_extractor import extract_geographies, extract_entities

t4 = """
            In mid-2025 a campaign deployed a Rust-based backdoor
            alongside a Python loader and additional surveillance
            tooling, including a PowerShell-based backdoor and a
            dedicated data-stealing component, to conduct covert
            monitoring and maintain persistent access on Windows
            systems via spearphishing and stealthy code injection. A
            separate operation delivered malicious Windows shortcut
            (LNK) files disguised as a legitimate newsletter to South
            Korean academics, researchers, and officials, launching a
            multi-stage infection chain culminating in a well-known
            remote-access malware family associated with this actor,
            enabling remote command execution, credential harvesting,
            screenshot capture, and exfiltration to cloud services.
        """

print("DIRECT extract_geographies call:", extract_geographies(t4))
print()
e = extract_entities(t4, {})
print("VIA extract_entities:", e["geographies"])
