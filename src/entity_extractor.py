import re
import json
import os


def normalize_whitespace(text):
    
    return " ".join(text.split())


# ── Sector keywords ──────────────────────────────────────────────────
SECTOR_KEYWORDS = {
    "government": "Government",
    "ministry": "Government",
    "parliament": "Government",
    "public sector": "Government",
    "defence": "Defence",
    "defense": "Defence",
    "military": "Defence",
    "nato": "Defence",
    "armed forces": "Defence",
    "financial": "Finance",
    "finance": "Finance",
    "bank": "Finance",
    "banking": "Finance",
    "cryptocurrency": "Finance",
    "crypto": "Finance",
    "stock exchange": "Finance",
    "energy": "Energy",
    "power grid": "Energy",
    "electricity": "Energy",
    "nuclear": "Energy",
    "oil": "Energy",
    "gas": "Energy",
    "pipeline": "Energy",
    "healthcare": "Healthcare",
    "hospital": "Healthcare",
    "medical": "Healthcare",
    "pharmaceutical": "Healthcare",
    "technology": "Technology",
    "software": "Technology",
    "telecom": "Telecommunications",
    "telecommunications": "Telecommunications",
    "research": "Research",
    "think tank": "Research",
    "academia": "Research",
    "university": "Research",
    "manufacturing": "Manufacturing",
    "industrial": "Manufacturing",
    "critical infrastructure": "Critical Infrastructure",
    "media": "Media",
    "retail": "Retail",
    "state organization": "Government",
    "state organisations": "Government",
    "public administration": "Government",
}


GEOGRAPHY_KEYWORDS = {
    "poland": "Poland",
    "polish": "Poland",
    "ukraine": "Ukraine",
    "ukrainian": "Ukraine",
    "kyiv": "Ukraine",
    "russia": "Russia",
    "russian": "Russia",
    "moscow": "Russia",
    "china": "China",
    "chinese": "China",
    "beijing": "China",
    "north korea": "North Korea",
    "north korean": "North Korea",
    "dprk": "North Korea",
    "pyongyang": "North Korea",
    "iran": "Iran",
    "iranian": "Iran",
    "tehran": "Iran",
    "middle east": "Middle East",
    "eastern europe": "Eastern Europe",
    "europe": "Europe",
    "european": "Europe",
    "united states": "United States",
    "american": "United States",
    "south korea": "South Korea",
    "south korean": "South Korea",
    "seoul": "South Korea",
    "israel": "Israel",
    "india": "India",
    "indian": "India",
    "nato": "NATO",
    "asia": "Asia",
    "southeast asia": "Southeast Asia",
    "africa": "Africa",
    "latin america": "Latin America",
    "germany": "Germany",
    "france": "France",
    "united kingdom": "United Kingdom",
    "uk": "United Kingdom",
    "japan": "Japan",
    "taiwan": "Taiwan",
}

# ── Technique hint keywords ──────────────────────────────────────────
TECHNIQUE_HINTS = {
    "phishing": "T1566",
    "spearphishing": "T1566.001",
    "spear phishing": "T1566.001",
    "powershell": "T1059.001",
    "command prompt": "T1059.003",
    "bash": "T1059.004",
    "python script": "T1059.006",
    "credential dump": "T1003",
    "credential dumping": "T1003",
    "lsass": "T1003.001",
    "mimikatz": "T1003.001",
    "pass the hash": "T1550.002",
    "lateral movement": "T1021",
    "rdp": "T1021.001",
    "remote desktop": "T1021.001",
    "smb": "T1021.002",
    "ssh": "T1021.004",
    "keylog": "T1056.001",
    "keylogger": "T1056.001",
    "ransomware": "T1486",
    "data encryption": "T1486",
    "wiper": "T1485",
    "exfiltration": "T1041",
    "data exfil": "T1041",
    "dns tunnel": "T1071.004",
    "supply chain": "T1195",
    "watering hole": "T1189",
    "scheduled task": "T1053.005",
    "registry persistence": "T1547.001",
    "startup persistence": "T1547.001",
    "port scan": "T1595.001",
    "network scan": "T1595.001",
    "reconnaissance": "T1595",
    "privilege escalation": "T1068",
    "defence evasion": "T1027",
    "defense evasion": "T1027",
    "obfuscation": "T1027",
    "living off the land": "T1218",
    "lolbins": "T1218",
    "backdoor": "T1071",
    "command and control": "T1071",
    "c2": "T1071",
    "dropper": "T1105",
    "downloader": "T1105",
    "macro": "T1137",
    "shortcut": "T1204.002",
    "lnk file": "T1204.002",
    "browser theft": "T1185",
    "browser data": "T1185",
    "screenshot": "T1113",
    "screen capture": "T1113",
    "clipboard": "T1115",
    "network share": "T1039",
    "removable media": "T1091",
    "usb": "T1091",
}

def extract_explicit_ttps(text):
    """Extract explicitly mentioned ATT&CK technique IDs."""
    pattern = r'[Tt]\d{4}(?:\.\d{3})?'
    found = re.findall(pattern, text)
    return list(set(t.upper() for t in found))

def extract_technique_hints(text):
    """
    Extract implied TTPs from technique-related keywords.
    Returns dict of technique_id -> keyword that triggered it.
    """
    text_lower = normalize_whitespace(text.lower())
    found = {}
    for keyword, ttp_id in TECHNIQUE_HINTS.items():
        if keyword in text_lower:
            found[ttp_id] = keyword
    return found

def extract_sectors(text):
    """Extract target sector mentions."""
    text_lower = normalize_whitespace(text.lower())
    found = set()
    for keyword, sector in SECTOR_KEYWORDS.items():
        if keyword in text_lower:
            found.add(sector)
    return list(found)

MOTIVATION_KEYWORDS = {
    "espionage": "Espionage",
    "intelligence gathering": "Espionage",
    "information theft": "Espionage",
    "data theft": "Espionage",
    "spying": "Espionage",
    "surveillance": "Espionage",
    "reconnaissance": "Espionage",
    "confidential information": "Espionage",
    "financial gain": "Financial",
    "financial crime": "Financial",
    "ransomware": "Financial",
    "extortion": "Financial",
    "banking fraud": "Financial",
    "cryptocurrency theft": "Financial",
    "monetary": "Financial",
    "profit": "Financial",
    "stolen funds": "Financial",
    "sabotage": "Sabotage/Destruction",
    "destructive": "Sabotage/Destruction",
    "destruction": "Sabotage/Destruction",
    "disruption": "Sabotage/Destruction",
    "wiper": "Sabotage/Destruction",
    "physical damage": "Sabotage/Destruction",
    "denial of service": "Sabotage/Destruction",
    "blackout": "Sabotage/Destruction",
    "power outage": "Sabotage/Destruction",
}


def extract_motivation(text):
    """Extract motivation category mentions from free text."""
    text_lower = normalize_whitespace(text.lower())
    found = set()
    for keyword, motivation in MOTIVATION_KEYWORDS.items():
        if keyword in text_lower:
            found.add(motivation)
    return list(found)


def extract_geographies(text):
    
    text_lower = normalize_whitespace(text.lower())
    found = set()
    for keyword, geography in GEOGRAPHY_KEYWORDS.items():
        if keyword in text_lower:
            found.add(geography)
    return list(found)



ORIGIN_INDICATORS = [
    "based", "linked", "sponsored", "attributed", "backed",
    "affiliated", "regime", "government", "intelligence",
    "state-sponsored", "nation-state", "military intelligence",
]


def extract_origin_countries(text, window=50):
    
    text_lower = normalize_whitespace(text.lower())
    found = set()
    for keyword, country in GEOGRAPHY_KEYWORDS.items():
        start = 0
        while True:
            idx = text_lower.find(keyword, start)
            if idx == -1:
                break
            window_start = max(0, idx - window)
            window_end = min(len(text_lower), idx + len(keyword) + window)
            context = text_lower[window_start:window_end]
            if any(indicator in context for indicator in ORIGIN_INDICATORS):
                found.add(country)
                break
            start = idx + len(keyword)
    return list(found)

def extract_tools(text, malware_index):
    
    text_lower = normalize_whitespace(text.lower())
    found = {}

    GENERIC_MALWARE_TERMS = {
        "backdoor", "trojan", "malware", "downloader", "loader",
        "worm", "virus", "ransomware", "stealer", "dropper",
        "implant", "rootkit", "keylogger", "wiper", "botnet",
    }

    for tool_name, actors in malware_index.items():
        if len(tool_name) > 5 and tool_name in text_lower:
            found[tool_name] = actors
            continue
        family = tool_name.split(".")[0].split("_")[0]
        if (len(family) > 5 and family != tool_name
                and family not in GENERIC_MALWARE_TERMS
                and family in text_lower):
            found[tool_name] = actors
    return found

def get_direct_signals(found_tools):
    """
    Extracts direct actor signals from tools exclusively
    associated with one actor.
    Only exclusive tool associations are reliable signals.
    """
    signals = set()
    for tool_name, actors in found_tools.items():
        if isinstance(actors, list) and len(actors) == 1:
            signals.add(actors[0])
        elif isinstance(actors, str):
            signals.add(actors)
    return signals

def extract_iocs(text):
    """
    Extract IoCs of the three types TRACE is scoped to handle:
    IP addresses, domains, and file hashes (MD5/SHA1/SHA256).
    Returns a dict of ioc_type -> list of found values.

    CTI text sometimes "defangs" indicators to stop them being
    clickable/live, e.g. writing "185[.]220[.]101[.]1" instead of
    "185.220.101.1", or "malicious[.]com". Both forms are normalised
    before matching so defanged IoCs from real reports are still
    caught.
    """
    normalised = text.replace("[.]", ".").replace("(.)", ".")

    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}' \
                   r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
    ips = re.findall(ipv4_pattern, normalised)

   
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}' \
                      r'[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domain_candidates = re.findall(domain_pattern, normalised)
    ip_set = set(ips)
    domains = [d for d in domain_candidates
               if d not in ip_set and not re.match(r'^[\d.]+$', d)]

    # File hashes: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
    md5s = re.findall(r'\b[a-fA-F0-9]{32}\b', text)
    sha1s = re.findall(r'\b[a-fA-F0-9]{40}\b', text)
    sha256s = re.findall(r'\b[a-fA-F0-9]{64}\b', text)

    return {
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "hashes": sorted(set(md5s) | set(sha1s) | set(sha256s)),
    }


def extract_entities(text, malware_index=None):
    """
    Main entity extraction function.
    Takes raw text and returns all extracted entities
    as a structured dictionary.
    """
    if malware_index is None:
        malware_index = {}

    # Extract each entity type
    explicit_ttps = extract_explicit_ttps(text)
    technique_hints = extract_technique_hints(text)
    sectors = extract_sectors(text)
    motivation = extract_motivation(text)
    geographies = extract_geographies(text)
    origin_countries = extract_origin_countries(text)
    tools = extract_tools(text, malware_index)
    direct_signals = get_direct_signals(tools)

    # Combine all TTP signals
    all_ttps = set(explicit_ttps)
    all_ttps.update(technique_hints.keys())

    return {
        "explicit_ttps": explicit_ttps,
        "technique_hints": technique_hints,
        "all_ttps": list(all_ttps),
        "sectors": sectors,
        "motivation": motivation,
        "geographies": geographies,
        "origin_countries": origin_countries,
        "tools": tools,
        "direct_actor_signals": list(direct_signals),
    }

def print_extraction_report(text, entities):
    """Prints a clean extraction report."""
    print("\n" + "="*60)
    print("ENTITY EXTRACTION REPORT")
    print("="*60)
    print(f"Text: {text.strip()[:120]}...")
    print(f"\nExplicit TTP IDs:     {entities['explicit_ttps']}")
    print(f"Technique hints:      "
          f"{list(entities['technique_hints'].values())[:6]}")
    print(f"All TTPs combined:    {len(entities['all_ttps'])} signals")
    print(f"Target sectors:       {entities['sectors']}")
    print(f"Geographies:          {entities['geographies']}")
    print(f"Tools found:          "
          f"{list(entities['tools'].keys())[:8]}")
    print(f"Direct actor signals: {entities['direct_actor_signals']}")

if __name__ == "__main__":
    # Load malware index
    index_path = "data/malpedia/malware_actor_index.json"
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            malware_index = json.load(f)
        print(f"Loaded malware index: {len(malware_index)} entries\n")
    else:
        malware_index = {}

    tests = [
        """
        Phishing emails targeted state organizations delivering malicious
        shortcut files executing PowerShell commands. MASEPIE used for
        file transfers, STEELHOOK for browser data theft, OCEANMAP as
        backdoor. Registry persistence established. Poland targeted.
        """,
        """
        Nation-state actor sent spearphishing emails to defence ministry
        officials. Credentials harvested from memory using credential
        dumping techniques. Lateral movement via RDP using stolen accounts.
        NATO member states targeted. Russian military intelligence overlap.
        """,
        """
        WannaCry ransomware deployed across financial institutions and
        cryptocurrency exchanges. T1486 and T1041 observed. Custom
        backdoors installed for persistent access. North Korean
        attribution indicators present.
        """
    ]

    for i, test in enumerate(tests, 1):
        print(f"\nTEST {i}")
        entities = extract_entities(test, malware_index)
        print_extraction_report(test, entities)
