import json
import os
import re
import requests

REPO_API_TREE_URL = (
    "https://api.github.com/repos/carbonblack/"
    "active_c2_ioc_public/git/trees/main?recursive=1"
)
RAW_BASE_URL = (
    "https://raw.githubusercontent.com/carbonblack/"
    "active_c2_ioc_public/main/"
)

IOC_INDEX_PATH = "data/otx/ioc_actor_index.json"

# Same 7 test actors as otx_pipeline.py, plus known aliases —
# matched against file/folder names in the repo (case-insensitive
# substring match), since the repo organises files by actor/malware
# name rather than a clean structured index.
ACTOR_NAME_MATCHES = {
    "APT29": ["apt29", "cozybear", "cozy_bear", "cozy-bear"],
    "APT28": ["apt28", "fancybear", "sofacy"],
    "Lazarus Group": ["lazarus"],
    "Sandworm Team": ["sandworm", "blackenergy", "black_energy"],
    "Kimsuky": ["kimsuky"],
    "APT41": ["apt41"],
    "OilRig": ["oilrig", "apt34"],
    "Winnti Group": ["winnti"],
}

IP_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
)
DOMAIN_PATTERN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,}\b'
)


def list_repo_files():
    """
    Uses GitHub's API to list every file in the repo (no auth
    needed for public repos at this request volume). Returns a
    list of file paths.
    """
    print("Fetching repository file listing...")
    resp = requests.get(REPO_API_TREE_URL, timeout=30)
    resp.raise_for_status()
    tree = resp.json().get("tree", [])
    files = [item["path"] for item in tree if item["type"] == "blob"]
    print(f"Found {len(files)} files in the repository.")
    return files


def match_files_to_actors(files):
    """
    Matches file/folder paths against known actor name variants.
    Returns dict of actor_name -> list of matching file paths.
    """
    matches = {name: [] for name in ACTOR_NAME_MATCHES}
    for path in files:
        path_lower = path.lower()
        for actor_name, variants in ACTOR_NAME_MATCHES.items():
            if any(v in path_lower for v in variants):
                matches[actor_name].append(path)
    return matches


def extract_iocs_from_csv_text(text):
    """
    Extracts IPs and domains from a CSV/TSV file's raw text. These
    files aren't uniformly structured (columns vary by file), so
    this uses regex extraction across the whole text rather than
    assuming a fixed column layout — safer given the repo has many
    different contributors/formats.
    """
    ips = set(IP_PATTERN.findall(text))
    # Filter domain matches down, excluding anything that's really
    # just an IP (the IP pattern already caught those)
    domain_candidates = set(DOMAIN_PATTERN.findall(text))
    domains = {d for d in domain_candidates
               if d not in ips and not re.match(r'^[\d.]+$', d)}
    return ips, domains


def fetch_and_parse(path):
    url = RAW_BASE_URL + path
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"    Failed to fetch {path}: {e}")
        return set(), set()
    return extract_iocs_from_csv_text(resp.text)


def build_carbonblack_index():
    files = list_repo_files()
    # Only bother fetching files that look like data files
    data_files = [f for f in files
                  if f.endswith(('.csv', '.tsv', '.txt'))]
    matches = match_files_to_actors(data_files)

    ioc_index = {}
    per_actor_counts = {}

    for actor_name, paths in matches.items():
        if not paths:
            per_actor_counts[actor_name] = 0
            continue
        print(f"\nFetching {len(paths)} file(s) for {actor_name}...")
        actor_ioc_count = 0
        for path in paths:
            print(f"  {path}")
            ips, domains = fetch_and_parse(path)
            for ip in ips:
                key = ip.lower().strip()
                entry = ioc_index.setdefault(
                    key, {"type": "ip", "actors": [], "sources": []}
                )
                if actor_name not in entry["actors"]:
                    entry["actors"].append(actor_name)
                entry["sources"].append({"file": path,
                                         "repo": "carbonblack"})
                actor_ioc_count += 1
            for domain in domains:
                key = domain.lower().strip()
                entry = ioc_index.setdefault(
                    key, {"type": "domain", "actors": [], "sources": []}
                )
                if actor_name not in entry["actors"]:
                    entry["actors"].append(actor_name)
                entry["sources"].append({"file": path,
                                         "repo": "carbonblack"})
                actor_ioc_count += 1
        per_actor_counts[actor_name] = actor_ioc_count

    return ioc_index, per_actor_counts


if __name__ == "__main__":
    os.makedirs("data/otx", exist_ok=True)

    # Load existing index (e.g. from otx_pipeline.py) to MERGE into,
    # rather than overwrite — run this before or after otx_pipeline.py
    # in either order, both contribute to the same combined index.
    existing_index = {}
    if os.path.exists(IOC_INDEX_PATH):
        with open(IOC_INDEX_PATH, "r") as f:
            existing_index = json.load(f)
        print(f"Loaded {len(existing_index)} existing IoCs "
              f"(from otx_pipeline.py or a prior run) to merge into.")

    cb_index, per_actor_counts = build_carbonblack_index()

    # Merge: for keys that exist in both, combine actor lists and
    # sources rather than one overwriting the other
    for key, entry in cb_index.items():
        if key in existing_index:
            existing_actors = set(existing_index[key].get("actors", []))
            existing_actors.update(entry["actors"])
            existing_index[key]["actors"] = sorted(existing_actors)
            existing_index[key].setdefault("sources", []).extend(
                entry["sources"]
            )
        else:
            existing_index[key] = entry

    with open(IOC_INDEX_PATH, "w") as f:
        json.dump(existing_index, f, indent=2)

    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    for actor, count in per_actor_counts.items():
        print(f"  {actor:20s} {count} IoCs found")
    print(f"\nTotal combined index size (including any prior OTX "
          f"data): {len(existing_index)}")
    print(f"Saved to {IOC_INDEX_PATH}")