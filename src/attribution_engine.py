import json
import re
from collections import defaultdict

def load_groups(filepath="data/unified/knowledge_base.json"):
    """Loads unified knowledge base from JSON file."""
    with open(filepath, "r") as f:
        return json.load(f)

def load_groups_with_idf(filepath="data/unified/knowledge_base.json"):
    groups = load_groups(filepath)
    idf_weights = compute_idf_weights(groups)
    print(f"Computed IDF weights for {len(idf_weights)} techniques.")
    return groups, idf_weights

TOOL_TO_TTP = {
    # Execution tools
    "powershell": "T1059.001",
    "cmd": "T1059.003",
    "command prompt": "T1059.003",
    "python": "T1059.006",
    "bash": "T1059.004",
    "javascript": "T1059.007",
    "vbscript": "T1059.005",
    "wscript": "T1059.005",
    "cscript": "T1059.005",
    "wmic": "T1047",

    # Credential access tools
    "mimikatz": "T1003.001",
    "procdump": "T1003.001",
    "lsass": "T1003.001",
    "hashdump": "T1003.002",
    "secretsdump": "T1003.002",
    "lazagne": "T1555",

    # Lateral movement tools
    "impacket": "T1021.002",
    "smbexec": "T1021.002",
    "psexec": "T1021.002",
    "wmiexec": "T1047",
    "winrm": "T1021.006",
    "rdp": "T1021.001",
    "remote desktop": "T1021.001",
    "ssh": "T1021.004",
    "openssh": "T1021.004",

    # Persistence mechanisms
    "registry": "T1547.001",
    "startup": "T1547.001",
    "scheduled task": "T1053.005",
    "cron": "T1053.003",
    "service": "T1543.003",

    # Initial access
    "phishing": "T1566",
    "spearphishing": "T1566.001",
    "spear phishing": "T1566.001",
    "watering hole": "T1189",
    "exploit": "T1190",
    "shortcut": "T1204.002",
    "lnk": "T1204.002",
    "malicious link": "T1204.001",
    "macro": "T1137",

    # Exfiltration and C2
    "steelhook": "T1185",
    "masepie": "T1041",
    "oceanmap": "T1071.001",
    "backdoor": "T1071",
    "c2": "T1071",
    "command and control": "T1071",
    "tunneling": "T1572",
    "dns tunneling": "T1071.004",

    # Discovery
    "reconnaissance": "T1595",
    "nmap": "T1595.001",
    "network scan": "T1595.001",
    "port scan": "T1595.001",

    # Defence evasion
    "obfuscation": "T1027",
    "base64": "T1027",
    "packed": "T1027.002",
    "living off the land": "T1218",
    "lolbins": "T1218",

    # Collection
    "keylogger": "T1056.001",
    "screenshot": "T1113",
    "clipboard": "T1115",
    "browser": "T1185",

    # Impact
    "ransomware": "T1486",
    "encrypt": "T1486",
    "wiper": "T1485",
    "data destruction": "T1485",
}


import os

# Load MITRE-sourced malware-actor index
# Falls back to hardcoded list for recent tools not yet in MITRE
def load_malware_actor_index():
    index_path = "data/malpedia/malware_actor_index.json"
    
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            mitre_index = json.load(f)
        print(f"Loaded MITRE malware-actor index: {len(mitre_index)} entries")
    else:
        mitre_index = {}
        print("MITRE index not found — using hardcoded fallback only")

    
    recent_tools = {
        "masepie": ["APT29"],
        "steelhook": ["APT29"],
        "oceanmap": ["APT29"],
        "wellmess": ["APT29"],
        "sunburst": ["APT29"],
        "cozycar": ["APT29"],
        "fancy bear": ["APT28"],
        "cozy bear": ["APT29"],
    }

    
    combined = {**recent_tools, **mitre_index}
    return combined

TOOL_TO_ACTOR = load_malware_actor_index()

def extract_ttps_from_text(text, all_techniques):
    """
    Extracts ATT&CK TTPs from text using three methods:
    1. Explicit ATT&CK technique ID mentions (e.g. T1566)
    2. Known tool/malware name matching
    3. Exact full technique name matching
    """
    found_ttps = set()
    text_lower = text.lower()

  
    explicit_ids = re.findall(r't\d{4}(?:\.\d{3})?', text_lower)
    for tid in explicit_ids:
        found_ttps.add(tid.upper())


    for tool_name, technique_id in TOOL_TO_TTP.items():
        if tool_name in text_lower:
            found_ttps.add(technique_id)


    for technique_id, technique_name, tactics in all_techniques:
        if len(technique_name) > 4:  # Skip very short names
            if technique_name.lower() in text_lower:
                found_ttps.add(technique_id)

    return found_ttps

def build_technique_index(groups):
    """
    Builds a flat list of all unique techniques across all groups.
    Returns list of (technique_id, technique_name, tactics) tuples.
    """
    seen = set()
    all_techniques = []

    for group in groups:
        for ttp in group.get("ttps", []):
            tid = ttp["technique_id"]
            if tid not in seen:
                seen.add(tid)
                all_techniques.append((
                    tid,
                    ttp["technique_name"],
                    ttp["tactics"]
                ))

    return all_techniques

def compute_idf_weights(groups):
    import math

    total_actors = len([g for g in groups if g["ttp_count"] > 0])
    technique_actor_count = {}

    
    for group in groups:
        for ttp in group.get("ttps", []):
            tid = ttp["technique_id"]
            if tid:
                technique_actor_count[tid] = \
                    technique_actor_count.get(tid, 0) + 1


    idf_weights = {}
    for tid, count in technique_actor_count.items():
        idf_weights[tid] = math.log(total_actors / count)

    return idf_weights

def score_groups(groups, matched_ttps,
                 direct_actor_signals=None, idf_weights=None):
    
    if direct_actor_signals is None:
        direct_actor_signals = set()

    if not matched_ttps and not direct_actor_signals:
        return []

    scored = []

    def technique_family(tid):
        """Base technique ID, stripping any sub-technique suffix (T1071.001 -> T1071)."""
        return tid.split(".")[0]

    for group in groups:
        if group["ttp_count"] == 0:
            continue

        group_ttps = set(t["technique_id"] for t in group["ttps"])

        exact_overlap = matched_ttps.intersection(group_ttps) \
            if matched_ttps else set()

        
        family_overlap = set()
        if matched_ttps:
            query_families = {technique_family(t) for t in matched_ttps}
            group_families = {technique_family(t) for t in group_ttps}
            matching_families = query_families & group_families
            for t in matched_ttps:
                if technique_family(t) in matching_families:
                    family_overlap.add(t)

        overlap = exact_overlap | family_overlap

        if len(overlap) == 0 and group["name"] \
                not in direct_actor_signals:
            # Check aliases too
            alias_match = False
            for alias in group.get("aliases", []):
                if alias in direct_actor_signals:
                    alias_match = True
                    break
            if not alias_match:
                continue

        
        if matched_ttps and idf_weights:
            matched_weight_sum = sum(
                idf_weights.get(t, 1.0) for t in matched_ttps
            )
            overlap_weight_sum = sum(
                idf_weights.get(t, 1.0) for t in overlap
            )
            ttp_score = (overlap_weight_sum / matched_weight_sum
                        if matched_weight_sum > 0 else 0)
        else:
            ttp_score = len(overlap) / len(matched_ttps) \
                if matched_ttps else 0

      
        actor_bonus = 0
        if group["name"] in direct_actor_signals:
            actor_bonus = 1.0
        else:
            for alias in group.get("aliases", []):
                if alias in direct_actor_signals:
                    actor_bonus = 1.0
                    break

        final_score = min((ttp_score + actor_bonus) * 100, 100)

        scored.append({
            "name": group["name"],
            "aliases": group.get("aliases", []),
            "score": round(final_score, 2),
            "matched_ttps": list(overlap),
            "matched_count": len(overlap),
            "total_group_ttps": group["ttp_count"],
            "direct_signal": group["name"] in direct_actor_signals,
        })

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored

def attribute(text, groups=None, top_n=5):
    if groups is None:
        groups = load_groups()

    all_techniques = build_technique_index(groups)
    matched_ttps = extract_ttps_from_text(text, all_techniques)

    # Extract direct actor signals from known tools
    direct_actor_signals = set()
    text_lower = text.lower()
    for tool_name, actor_names in TOOL_TO_ACTOR.items():
        if tool_name in text_lower:
            if isinstance(actor_names, list):
                # Only add as direct signal if exclusively used by one actor
                if len(actor_names) == 1:
                    direct_actor_signals.add(actor_names[0])
            elif isinstance(actor_names, str) and actor_names != "multiple":
                direct_actor_signals.add(actor_names)
                print(f"  Direct signal: '{tool_name}' → {actor_name}")

    print(f"\nMatched {len(matched_ttps)} TTPs from input text:")
    for ttp in matched_ttps:
        print(f"  - {ttp}")

    if direct_actor_signals:
        print(f"\nDirect actor signals found: {direct_actor_signals}")

    if not matched_ttps and not direct_actor_signals:
        print("No TTPs or actor signals matched.")
        return []

    results = score_groups(groups, matched_ttps, direct_actor_signals)
    return results[:top_n]


if __name__ == "__main__":
    
    test_description = """
    Spear phishing emails were sent to government ministry employees 
    containing malicious Word documents with embedded macros. Upon 
    execution, X-Agent malware was deployed for keylogging and data 
    exfiltration. The attackers used Mimikatz for credential dumping 
    and moved laterally using stolen credentials via RDP. 
    Reconnaissance was conducted using network scanning tools. 
    Data was staged and exfiltrated via encrypted channels. 
    The campaign targeted defence ministries across Eastern Europe 
    and showed consistent infrastructure overlap with previous 
    Sofacy operations.
"""
    groups = load_groups()
    results = attribute(test_description, groups)

    print(f"\nTop {len(results)} attributed threat actors:")
    print("-" * 50)
    for i, r in enumerate(results, 1):
        print(f"\n#{i} {r['name']}")
        print(f"   Confidence: {r['score']}%")
        print(f"   Matched TTPs: {r['matched_count']}")
        print(f"   Matching techniques: {r['matched_ttps']}")