# Threat Actor Attribution System - Hybrid Engine
# ELE8095 OO05 - Sai Pavan Yoganand
# Source: Developed with Claude AI assistance (Anthropic)
# Purpose: Combines keyword baseline with semantic similarity

import json
import torch
from sentence_transformers import SentenceTransformer, util
from attribution_engine import (
    load_groups,
    build_technique_index,
    extract_ttps_from_text,
    score_groups,
    TOOL_TO_ACTOR
)

# Weights for combining scores
# These will eventually be learned by the fusion layer
# For now we set them manually based on intuition
KEYWORD_WEIGHT = 0.35
SEMANTIC_WEIGHT = 0.65

MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDINGS_PATH = "data/unified/actor_embeddings.pt"
PROFILES_PATH = "data/unified/knowledge_base.json"

def load_semantic_components():
    """Load model and pre-computed embeddings."""
    print("Loading semantic components...")
    model = SentenceTransformer(MODEL_NAME)

    save_data = torch.load(EMBEDDINGS_PATH, weights_only=False)
    embeddings = save_data["embeddings"]
    actor_names = save_data["actor_names"]

    with open(PROFILES_PATH, "r") as f:
        all_profiles = json.load(f)

    name_to_profile = {a["name"]: a for a in all_profiles}
    valid_profiles = [name_to_profile[n] for n in actor_names
                     if n in name_to_profile]

    print(f"Loaded {len(valid_profiles)} actor embeddings.")
    return model, embeddings, valid_profiles

def get_semantic_scores(query_text, model, embeddings, profiles):
    """
    Returns a dictionary of actor_name -> semantic_score
    for all actors.
    """
    query_embedding = model.encode(
        query_text,
        convert_to_tensor=True
    )
    similarities = util.cos_sim(query_embedding, embeddings)[0]

    scores = {}
    for idx, score in enumerate(similarities):
        actor_name = profiles[idx]["name"]
        scores[actor_name] = score.item()

    return scores

def get_keyword_scores(query_text, groups):
    """
    Returns a dictionary of actor_name -> keyword_score
    using the existing baseline engine.
    """
    all_techniques = build_technique_index(groups)
    matched_ttps = extract_ttps_from_text(query_text, all_techniques)

    # Get direct actor signals
    direct_actor_signals = set()
    text_lower = query_text.lower()
    for tool_name, actor_names in TOOL_TO_ACTOR.items():
        if tool_name in text_lower:
            if isinstance(actor_names, list):
                if len(actor_names) == 1:
                    direct_actor_signals.add(actor_names[0])
            elif isinstance(actor_names, str) and actor_names != "multiple":
                direct_actor_signals.add(actor_names)
    # Score all groups
    results = score_groups(groups, matched_ttps, direct_actor_signals)

    # Convert to dictionary
    scores = {}
    for r in results:
        scores[r["name"]] = r["score"] / 100.0  # normalise to 0-1

    return scores, matched_ttps, direct_actor_signals

def hybrid_attribute(query_text, model, embeddings,
                     semantic_profiles, groups, top_n=5):
    """
    Main hybrid attribution function.
    Combines keyword and semantic scores.
    """
    # Get both score sets
    semantic_scores = get_semantic_scores(
        query_text, model, embeddings, semantic_profiles
    )
    keyword_scores, matched_ttps, direct_signals = get_keyword_scores(
        query_text, groups
    )

    # Combine scores for all actors
    combined = {}
    all_actor_names = set(semantic_scores.keys()) | set(keyword_scores.keys())

    for name in all_actor_names:
        sem = semantic_scores.get(name, 0.0)
        kw = keyword_scores.get(name, 0.0)
        base = (SEMANTIC_WEIGHT * sem) + (KEYWORD_WEIGHT * kw)
    
        # Direct signal boost — exclusive tool/malware identification
        # is a strong evidence signal that overrides general similarity
        if name in direct_signals:
            base = base + 0.25
    
        combined[name] = min(base, 1.0)

    # Sort by combined score
    ranked = sorted(combined.items(), key=lambda x: x[1], reverse=True)

    # Build result objects
    name_to_profile = {p["name"]: p for p in semantic_profiles}
    results = []

    for name, score in ranked[:top_n]:
        profile = name_to_profile.get(name, {})
        results.append({
            "name": name,
            "combined_score": round(score * 100, 2),
            "semantic_score": round(semantic_scores.get(name, 0) * 100, 2),
            "keyword_score": round(keyword_scores.get(name, 0) * 100, 2),
            "country": profile.get("country", []),
            "motivation": profile.get("motivation", []),
            "direct_signal": name in direct_signals,
            "matched_ttps": matched_ttps
        })

    return results

if __name__ == "__main__":
    # Load all components
    groups = load_groups()
    model, embeddings, semantic_profiles = load_semantic_components()

    tests = [
        {
            "name": "TEST 1 - Explicit tool names (APT29 expected)",
            "text": """
                Phishing emails targeted state organizations delivering 
                malicious shortcut files that executed PowerShell commands. 
                The attack leveraged MASEPIE for file transfers, STEELHOOK 
                for browser data theft, and OCEANMAP as a backdoor. 
                Similar attacks observed in Poland.
            """
        },
        {
            "name": "TEST 2 - Paraphrased no tool names (APT29 expected)",
            "text": """
                A sophisticated nation-state actor sent targeted emails to 
                government ministry employees containing malicious attachments. 
                After execution credentials were harvested from memory and 
                the attacker moved laterally using stolen account details. 
                Data was collected from browsers and exfiltrated through 
                encrypted channels. The campaign focused on Eastern European 
                government organisations.
            """
        },
        {
            "name": "TEST 3 - Paraphrased APT28 description",
            "text": """
                State sponsored actors sent targeted emails to defence 
                ministry officials containing weaponised documents. After 
                opening a keylogger was installed and credentials stolen. 
                The group used these credentials to access additional systems 
                and collect sensitive documents. Infrastructure overlaps with 
                previous Russian military intelligence operations targeting 
                NATO member states.
            """
        }
    ]

    for test in tests:
        print("\n" + "="*60)
        print(test["name"])
        print("="*60)

        results = hybrid_attribute(
            test["text"], model, embeddings, semantic_profiles, groups
        )

        for i, r in enumerate(results, 1):
            signal = " ← DIRECT SIGNAL" if r["direct_signal"] else ""
            print(f"#{i} {r['name']}")
            print(f"   Combined: {r['combined_score']}% | "
                  f"Semantic: {r['semantic_score']}% | "
                  f"Keyword: {r['keyword_score']}%")
            print(f"   Country: {r['country']}{signal}")