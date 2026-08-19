import sys, json
sys.path.insert(0, "src")
from entity_extractor import extract_entities

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

for name, text in [("T4 (APT37)", t4), ("T5 (Kimsuky)", t5)]:
    e = extract_entities(text, {})
    print(f"--- {name} ---")
    print("geographies:", e["geographies"])
    print("sectors:", e["sectors"])
    print("motivation:", e["motivation"])
    print()
