import json
import os
import re
from collections import defaultdict, Counter


MITRE_DATA_PATH = "data/mitre/enterprise-attack.json"
PHASE_MAP_CACHE_PATH = "data/mitre/technique_phase_map.json"


def build_technique_phase_map():
    
    if os.path.exists(PHASE_MAP_CACHE_PATH):
        with open(PHASE_MAP_CACHE_PATH, "r") as f:
            return json.load(f)

    data = json.load(open(MITRE_DATA_PATH))
    objects = data.get("objects", data) if isinstance(data, dict) else data

    phase_map = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        technique_ids = [
            r.get("external_id") for r in obj.get("external_references", [])
            if r.get("source_name") == "mitre-attack"
        ]
        phases = [
            kcp.get("phase_name") for kcp in obj.get("kill_chain_phases", [])
            if kcp.get("kill_chain_name") == "mitre-attack"
        ]
        for tid in technique_ids:
            if tid and phases:
                phase_map[tid] = phases

    os.makedirs(os.path.dirname(PHASE_MAP_CACHE_PATH), exist_ok=True)
    with open(PHASE_MAP_CACHE_PATH, "w") as f:
        json.dump(phase_map, f, indent=2)

    return phase_map


def extract_ordered_techniques(text):
    
    from entity_extractor import TECHNIQUE_HINTS, normalize_whitespace

    normalized = normalize_whitespace(text)
    text_lower = normalized.lower()

    matches = []  # list of (position, technique_id)

    # Explicit literal technique IDs
    for m in re.finditer(r'[Tt]\d{4}(?:\.\d{3})?', normalized):
        matches.append((m.start(), m.group().upper()))

    
    for keyword, ttp_id in TECHNIQUE_HINTS.items():
        start = 0
        while True:
            idx = text_lower.find(keyword, start)
            if idx == -1:
                break
            matches.append((idx, ttp_id))
            start = idx + len(keyword)

    matches.sort(key=lambda x: x[0])
    return [tid for _, tid in matches]


def techniques_to_phase_sequence(technique_ids, phase_map):
    
    raw_phases = []
    for tid in technique_ids:
        phases = phase_map.get(tid)
        if phases:
            raw_phases.append(phases[0])

    sequence = []
    for phase in raw_phases:
        if not sequence or sequence[-1] != phase:
            sequence.append(phase)
    return sequence


_phase_rarity_weights_cache = {}


def compute_phase_rarity_weights(actor_profiles):
    
    cache_key = id(actor_profiles)
    if cache_key in _phase_rarity_weights_cache:
        return _phase_rarity_weights_cache[cache_key]

    import math
    from collections import Counter

    doc_count = Counter()
    total_sequences = 0
    for actor, sequences in actor_profiles.items():
        for seq in sequences:
            total_sequences += 1
            for phase in set(seq):
                doc_count[phase] += 1

    weights = {}
    for phase, count in doc_count.items():
       
        weights[phase] = max(0.1, math.log(total_sequences / count))

    _phase_rarity_weights_cache[cache_key] = weights
    return weights


def smith_waterman_similarity(seq_a, seq_b, phase_weights=None,
                               match_score=2, mismatch_penalty=-1,
                               gap_open=-2, gap_extend=-0.5):
    
    if phase_weights is None:
        phase_weights = {}

    def weighted_match_score(phase):
        return match_score * phase_weights.get(phase, 1.0)

    n, m = len(seq_a), len(seq_b)
    if n == 0 or m == 0:
        return 0.0, 0.0

    NEG_INF = float("-inf")
    H = [[0.0] * (m + 1) for _ in range(n + 1)]
    E = [[NEG_INF] * (m + 1) for _ in range(n + 1)]  # gap in seq_a
    F = [[NEG_INF] * (m + 1) for _ in range(n + 1)]  # gap in seq_b
    max_score = 0.0

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if seq_a[i-1] == seq_b[j-1]:
                diag_score = weighted_match_score(seq_a[i-1])
            else:
                diag_score = mismatch_penalty

            E[i][j] = max(H[i][j-1] + gap_open, E[i][j-1] + gap_extend)
            F[i][j] = max(H[i-1][j] + gap_open, F[i-1][j] + gap_extend)
            H[i][j] = max(0.0, H[i-1][j-1] + diag_score, E[i][j], F[i][j])
            max_score = max(max_score, H[i][j])

    self_align_a = sum(weighted_match_score(p) for p in seq_a)
    self_align_b = sum(weighted_match_score(p) for p in seq_b)
    denom = min(self_align_a, self_align_b)
    normalised = max_score / denom if denom > 0 else 0.0

    return max_score, normalised


def build_actor_phase_profiles(base_path="guru_dataset/threat_actors_added_data",
                                phase_map=None, min_reports=5):
    
    if phase_map is None:
        phase_map = build_technique_phase_map()

    profiles = defaultdict(list)

    if not os.path.isdir(base_path):
        print(f"WARNING: {base_path} not found -- no actor profiles built.")
        return {}

    for actor_folder in os.listdir(base_path):
        actor_dir = os.path.join(base_path, actor_folder)
        if not os.path.isdir(actor_dir):
            continue

        for fname in os.listdir(actor_dir):
            if not fname.endswith(".txt"):
                continue
            fpath = os.path.join(actor_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue

            technique_ids = extract_ordered_techniques(text)
            sequence = techniques_to_phase_sequence(technique_ids, phase_map)
            if len(sequence) >= 5:
                profiles[actor_folder].append(sequence)

    return {
        actor: sequences for actor, sequences in profiles.items()
        if len(sequences) >= min_reports
    }


def score_by_kill_chain(query_text, actor_profiles, phase_map=None,
                        penalty_coefficient=0.05, gap_open=-2,
                        gap_extend=-0.5):
    
    import math

    if phase_map is None:
        phase_map = build_technique_phase_map()

    query_techniques = extract_ordered_techniques(query_text)
    query_sequence = techniques_to_phase_sequence(query_techniques, phase_map)

    if len(query_sequence) < 5:
        return {}

    phase_weights = compute_phase_rarity_weights(actor_profiles)

    scores = {}
    for actor, sequences in actor_profiles.items():
        best = 0.0
        for actor_sequence in sequences:
            _, normalised = smith_waterman_similarity(
                query_sequence, actor_sequence, phase_weights=phase_weights,
                gap_open=gap_open, gap_extend=gap_extend
            )
            best = max(best, normalised)

        n = len(sequences)
        penalty = penalty_coefficient * math.log(n) if n > 1 else 0.0
        scores[actor] = max(0.0, best - penalty)

    return scores


_transition_rarity_weights_cache = {}


def extract_transitions(sequence):
    
    return set(zip(sequence, sequence[1:]))


def compute_transition_rarity_weights(actor_profiles):
    
    cache_key = id(actor_profiles)
    if cache_key in _transition_rarity_weights_cache:
        return _transition_rarity_weights_cache[cache_key]

    import math
    from collections import Counter

    doc_count = Counter()
    total_sequences = 0
    for actor, sequences in actor_profiles.items():
        for seq in sequences:
            total_sequences += 1
            for transition in extract_transitions(seq):
                doc_count[transition] += 1

    weights = {}
    for transition, count in doc_count.items():
        weights[transition] = max(0.1, math.log(total_sequences / count))

    _transition_rarity_weights_cache[cache_key] = weights
    return weights


def transition_overlap_similarity(seq_a, seq_b, transition_weights=None):
    
    if transition_weights is None:
        transition_weights = {}

    trans_a = extract_transitions(seq_a)  # query
    trans_b = extract_transitions(seq_b)  # candidate actor's real sequence

    if not trans_a:
        return 0.0

    shared = trans_a & trans_b
    query_weight_total = sum(transition_weights.get(t, 1.0) for t in trans_a)
    shared_weight_total = sum(transition_weights.get(t, 1.0) for t in shared)

    return shared_weight_total / query_weight_total if query_weight_total > 0 else 0.0


def score_by_transition_overlap(query_text, actor_profiles, phase_map=None,
                                 penalty_coefficient=0.05):
    
    import math

    if phase_map is None:
        phase_map = build_technique_phase_map()

    query_techniques = extract_ordered_techniques(query_text)
    query_sequence = techniques_to_phase_sequence(query_techniques, phase_map)

    if len(query_sequence) < 5:
        return {}

    transition_weights = compute_transition_rarity_weights(actor_profiles)

    scores = {}
    for actor, sequences in actor_profiles.items():
        best = 0.0
        for actor_sequence in sequences:
            sim = transition_overlap_similarity(
                query_sequence, actor_sequence, transition_weights
            )
            best = max(best, sim)

        n = len(sequences)
        penalty = penalty_coefficient * math.log(n) if n > 1 else 0.0
        scores[actor] = max(0.0, best - penalty)

    return scores


if __name__ == "__main__":
    print("Building technique-to-phase map from real MITRE data...")
    phase_map = build_technique_phase_map()
    print(f"Mapped {len(phase_map)} techniques to real phase categories.\n")

    print("Building real per-actor phase profiles from Guru et al. dataset...")
    profiles = build_actor_phase_profiles(phase_map=phase_map)
    print(f"Built profiles for {len(profiles)} actors "
          f"(min 5 real reports each):")
    for actor, sequences in profiles.items():
        print(f"  {actor}: {len(sequences)} real sequences")
        # Show the most common sequence length as a sanity check
        lengths = Counter(len(s) for s in sequences)
        print(f"    sequence lengths: {dict(lengths)}")