import json
import os
import re
import torch
import torch.nn.functional as F
from sentence_transformers import SentenceTransformer, util, CrossEncoder
from attribution_engine import (
    load_groups_with_idf,
    score_groups,
    TOOL_TO_ACTOR
)
from entity_extractor import extract_entities, extract_iocs

KEYWORD_WEIGHT = 0.35
SEMANTIC_WEIGHT = 0.65
SECTOR_WEIGHT = 0.10
IOC_WEIGHT = 0.30
MOTIVATION_WEIGHT = 0.10  
TOOL_WEIGHT = 0.20  
COUNTRY_WEIGHT = 0.15  
ENGINE_WEIGHTS = {
    "semantic": SEMANTIC_WEIGHT,
    "keyword": KEYWORD_WEIGHT,
    "sector": SECTOR_WEIGHT,
    "ioc": IOC_WEIGHT,
    "motivation": MOTIVATION_WEIGHT,
    "tool": TOOL_WEIGHT,
    "country": COUNTRY_WEIGHT,
}

#Fusion Formula
def fuse_engine_scores(engine_outputs, base_weights=None):
    
    if base_weights is None:
        base_weights = ENGINE_WEIGHTS

    active = {name: scores for name, scores in engine_outputs.items()
              if scores}
    if not active:
        return {}

    total_weight = sum(base_weights.get(name, 0.0) for name in active)
    if total_weight == 0:
        # None of the active engines have a configured weight —
        # fall back to equal weighting rather than dividing by zero.
        normalised = {name: 1.0 / len(active) for name in active}
    else:
        normalised = {name: base_weights.get(name, 0.0) / total_weight
                      for name in active}

    all_actors = set()
    for scores in active.values():
        all_actors.update(scores.keys())

    combined = {}
    for actor in all_actors:
        combined[actor] = sum(
            normalised[name] * active[name].get(actor, 0.0)
            for name in active
        )
    return combined

MODEL_NAME = "all-MiniLM-L6-v2"  
EMBEDDINGS_PATH = "data/unified/actor_embeddings.pt"
PROFILES_PATH = "data/unified/knowledge_base.json"


def load_semantic_components():
    
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Loading semantic components on device: {device}...")
    model = SentenceTransformer(MODEL_NAME, device=device)

    save_data = torch.load(EMBEDDINGS_PATH, weights_only=False)
    embeddings = save_data["embeddings"].to(device)
    actor_names = save_data["actor_names"]

    with open(PROFILES_PATH, "r") as f:
        all_profiles = json.load(f)

    name_to_profile = {a["name"]: a for a in all_profiles}
    valid_profiles = [name_to_profile[n] for n in actor_names
                      if n in name_to_profile]

    print(f"Loaded {len(valid_profiles)} actor embeddings.")
    return model, embeddings, valid_profiles


def get_semantic_scores(query_text, model, embeddings, profiles):
    
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


def get_keyword_scores(query_text, groups,
                       malware_index=None, idf_weights=None,
                       direct_ttps=None):
    
    if malware_index is None:
        malware_index = {}
    if direct_ttps is None:
        direct_ttps = set()

    query_text = query_text or ""

    
    entities = extract_entities(query_text, malware_index)

    
    matched_ttps = set(entities["explicit_ttps"]) | set(direct_ttps)

    
    direct_actor_signals = set(entities["direct_actor_signals"])

   
    text_lower = query_text.lower()
    for tool_name, actor_names in TOOL_TO_ACTOR.items():
        if len(tool_name) <= 3:
            continue
        if not re.search(r'\b' + re.escape(tool_name) + r'\b', text_lower):
            continue
        if isinstance(actor_names, list) and len(actor_names) == 1:
            direct_actor_signals.add(actor_names[0])
        elif isinstance(actor_names, str) \
                and actor_names != "multiple":
            direct_actor_signals.add(actor_names)

    # Score groups
    results = score_groups(
        groups, matched_ttps,
        direct_actor_signals,
        idf_weights=idf_weights
    )

    scores = {}
    for r in results:
        scores[r["name"]] = r["score"] / 100.0

    
    tool_scores = {}
    for tool_name, actors in entities["tools"].items():
        if isinstance(actors, list) and len(actors) > 1:
            for actor in actors:
                tool_scores[actor] = max(tool_scores.get(actor, 0.0),
                                          1.0 / len(actors))

    return scores, matched_ttps, direct_actor_signals, entities, tool_scores


_sector_idf_cache = {}


def compute_sector_idf(groups):
   
    cache_key = id(groups)
    if cache_key in _sector_idf_cache:
        return _sector_idf_cache[cache_key]

    from collections import Counter
    import math
    sector_doc_count = Counter()
    for a in groups:
        for s in set(a.get("target_sectors", [])):
            sector_doc_count[s] += 1

    n_actors = len(groups)
    sector_idf = {
        s: math.log(n_actors / c) for s, c in sector_doc_count.items()
    }
    _sector_idf_cache[cache_key] = sector_idf
    return sector_idf


def get_sector_scores(query_sectors, groups, sector_idf=None):
    
    if not query_sectors:
        return {}

    query_set = set(query_sectors)
    scores = {}

    if sector_idf:
        query_weight = sum(sector_idf.get(s, 1.0) for s in query_set)
        for group in groups:
            actor_sectors = set(group.get("target_sectors", []))
            overlap = query_set & actor_sectors
            if overlap and query_weight > 0:
                overlap_weight = sum(sector_idf.get(s, 1.0) for s in overlap)
                scores[group["name"]] = overlap_weight / query_weight
    else:
        for group in groups:
            actor_sectors = set(group.get("target_sectors", []))
            overlap = query_set & actor_sectors
            if overlap:
                scores[group["name"]] = len(overlap) / len(query_set)

    return scores


def get_motivation_scores(query_motivation, groups):
   
    if not query_motivation:
        return {}

    query_set = set(query_motivation)
    scores = {}
    for group in groups:
        actor_motivation = set(group.get("motivation", []))
        overlap = query_set & actor_motivation
        if overlap:
            scores[group["name"]] = len(overlap) / len(query_set)
    return scores


def get_country_scores(query_countries, groups):
    
    if not query_countries:
        return {}

    query_set = set(query_countries)
    scores = {}
    for group in groups:
        actor_countries = set(group.get("country", []))
        overlap = query_set & actor_countries
        if overlap:
            scores[group["name"]] = len(overlap) / len(query_set)
    return scores


IOC_INDEX_PATH = "data/otx/ioc_actor_index.json"


def load_ioc_index():
    """Loads the OTX-built IoC-to-actor index, if it exists yet."""
    if os.path.exists(IOC_INDEX_PATH):
        with open(IOC_INDEX_PATH, "r") as f:
            return json.load(f)
    return {}


def get_ioc_scores(query_iocs, ioc_index):
    
    if not query_iocs or not ioc_index:
        return {}, set()

    scores = {}
    direct_signals = set()

    for raw in query_iocs:
        key = raw.lower().strip()
        entry = ioc_index.get(key)
        if not entry:
            continue

        actors = entry.get("actors", [])
        if len(actors) == 1:
            
            direct_signals.add(actors[0])
            scores[actors[0]] = 1.0
        else:
            
            for actor in actors:
                scores[actor] = max(scores.get(actor, 0.0),
                                    1.0 / len(actors))

    return scores, direct_signals


def assess_attribution_confidence(ranked, top_support_count=None,
                                   cluster_threshold=0.90,
                                   min_supporting_engines=4):
    
    if not ranked:
        return {
            "confidence": "high",
            "top_cluster": [],
            "reasoning": "No candidates to assess.",
        }

    top_name, top_score = ranked[0]
    if top_score <= 0:
        return {
            "confidence": "low",
            "top_cluster": [],
            "reasoning": "No candidate scored above zero -- no "
                         "meaningful evidence to attribute from.",
        }

    top_cluster = [
        (name, score) for name, score in ranked
        if score >= top_score * cluster_threshold
    ]

    isolated = len(top_cluster) == 1

    if not isolated:
        names = ", ".join(n for n, _ in top_cluster)
        return {
            "confidence": "low",
            "top_cluster": top_cluster,
            "reasoning": (
                f"{len(top_cluster)} candidates ({names}) score within "
                f"{cluster_threshold*100:.0f}% of each other -- the "
                f"available evidence does not confidently distinguish "
                f"between them. This may reflect genuinely insufficient "
                f"discriminating evidence, OR a false-flag scenario "
                f"where an actor has deliberately mimicked another's "
                f"known TTPs. Further investigation is recommended "
                f"before treating {top_name} as a confirmed attribution."
            ),
        }

    
    if top_support_count is None:
        return {
            "confidence": "high",
            "top_cluster": top_cluster,
            "reasoning": (
                f"{top_name} is clearly separated from all other "
                f"candidates."
            ),
        }

    if top_support_count >= min_supporting_engines:
        return {
            "confidence": "high",
            "top_cluster": top_cluster,
            "reasoning": (
                f"{top_name} is clearly separated from all other "
                f"candidates AND corroborated by {top_support_count} "
                f"independent non-semantic engines -- genuinely strong, "
                f"multi-source evidence."
            ),
        }

    return {
        "confidence": "low",
        "top_cluster": top_cluster,
        "reasoning": (
            f"{top_name} appears isolated in score, but only "
            f"{top_support_count} independent non-semantic engine(s) "
            f"actually support it (below the {min_supporting_engines} "
            f"required). This isolated-looking lead may be driven "
            f"primarily by semantic similarity alone, which real "
            f"testing has shown can produce a false, hub-driven sense "
            f"of confidence. Treat this attribution with caution "
            f"until corroborated by further evidence."
        ),
    }


def hybrid_attribute(query_text=None, model=None, embeddings=None,
                     semantic_profiles=None, groups=None,
                     malware_index=None, idf_weights=None, top_n=5,
                     direct_ttps=None, direct_sectors=None,
                     direct_iocs=None, ioc_index=None,
                     direct_motivation=None, direct_countries=None,
                     engine_weights=None):
    
    if malware_index is None:
        malware_index = {}
    if direct_ttps is None:
        direct_ttps = set()
    if direct_sectors is None:
        direct_sectors = set()
    if direct_motivation is None:
        direct_motivation = set()
    if direct_countries is None:
        direct_countries = set()
    if direct_iocs is None:
        direct_iocs = set()
    if ioc_index is None:
        ioc_index = load_ioc_index()

    engine_outputs = {}

    # Semantic engine: only fires with actual free text
    semantic_scores = {}
    if query_text and query_text.strip():
        semantic_scores = get_semantic_scores(
            query_text, model, embeddings, semantic_profiles
        )
        engine_outputs["semantic"] = semantic_scores

    # Keyword engine: fires on extracted-from-text TTPs, direct
    # TTP input, or both combined
    keyword_scores, matched_ttps, direct_signals, entities, tool_scores = \
        get_keyword_scores(
            query_text, groups, malware_index, idf_weights,
            direct_ttps=direct_ttps
        )
    if keyword_scores:
        engine_outputs["keyword"] = keyword_scores

    
    if tool_scores:
        engine_outputs["tool"] = tool_scores

   
    query_sectors = set(entities["sectors"]) | set(direct_sectors)
    sector_idf = compute_sector_idf(groups)
    sector_scores = get_sector_scores(query_sectors, groups, sector_idf=sector_idf)
    if sector_scores:
        engine_outputs["sector"] = sector_scores

    query_motivation = set(entities["motivation"]) | set(direct_motivation)
    motivation_scores = get_motivation_scores(query_motivation, groups)
    if motivation_scores:
        engine_outputs["motivation"] = motivation_scores

    
    query_countries = set(entities["origin_countries"]) | set(direct_countries)
    country_scores = get_country_scores(query_countries, groups)
    if country_scores:
        engine_outputs["country"] = country_scores

  
    text_iocs = extract_iocs(query_text) if query_text else \
        {"ips": [], "domains": [], "hashes": []}
    query_iocs = (set(text_iocs["ips"]) | set(text_iocs["domains"]) |
                  set(text_iocs["hashes"]) | set(direct_iocs))
    ioc_scores, ioc_direct_signals = get_ioc_scores(
        query_iocs, ioc_index
    )
    if ioc_scores:
        engine_outputs["ioc"] = ioc_scores
    direct_signals = direct_signals | ioc_direct_signals

  
    if not engine_outputs:
        return []

    fused = fuse_engine_scores(engine_outputs, base_weights=engine_weights)

   
    combined = {}
    for name, score in fused.items():
        base = score
        if name in direct_signals:
            base = base + 0.25
        combined[name] = min(base, 1.0)

    
    ranked = sorted(combined.items(), key=lambda x: (-x[1], x[0]))

   
    top_support_count = None
    if ranked:
        top_name_for_support = ranked[0][0]
        support_scores = [
            keyword_scores.get(top_name_for_support, 0),
            tool_scores.get(top_name_for_support, 0),
            sector_scores.get(top_name_for_support, 0),
            motivation_scores.get(top_name_for_support, 0),
            country_scores.get(top_name_for_support, 0),
            ioc_scores.get(top_name_for_support, 0),
        ]
        top_support_count = sum(1 for s in support_scores if s > 0)

    confidence_assessment = assess_attribution_confidence(
        ranked, top_support_count=top_support_count
    )
    top_cluster_names = {name for name, _ in confidence_assessment["top_cluster"]}

    name_to_profile = {p["name"]: p for p in (semantic_profiles or [])}
    results = []

    for name, score in ranked[:top_n]:
        profile = name_to_profile.get(name, {})
        results.append({
            "name": name,
            "combined_score": round(score * 100, 2),
            "semantic_score": round(
                semantic_scores.get(name, 0) * 100, 2),
            "keyword_score": round(
                keyword_scores.get(name, 0) * 100, 2),
            "tool_score": round(
                tool_scores.get(name, 0) * 100, 2),
            "sector_score": round(
                sector_scores.get(name, 0) * 100, 2),
            "motivation_score": round(
                motivation_scores.get(name, 0) * 100, 2),
            "country_score": round(
                country_scores.get(name, 0) * 100, 2),
            "ioc_score": round(
                ioc_scores.get(name, 0) * 100, 2),
            "engines_used": list(engine_outputs.keys()),
            "country": profile.get("country", []),
            "motivation": profile.get("motivation", []),
            "direct_signal": name in direct_signals,
            
            "attribution_confidence": confidence_assessment["confidence"],
            "confidence_reasoning": confidence_assessment["reasoning"],
            "in_top_cluster": name in top_cluster_names,
            "matched_ttps": list(matched_ttps),
            "extracted_sectors": entities["sectors"],
            "extracted_geographies": entities["geographies"],
        })

    return results



CROSS_ENCODER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
_cross_encoder_cache = {}


def load_cross_encoder():
   
    if CROSS_ENCODER_MODEL not in _cross_encoder_cache:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Loading cross-encoder reranker on device: {device}...")
        _cross_encoder_cache[CROSS_ENCODER_MODEL] = CrossEncoder(
            CROSS_ENCODER_MODEL, device=device
        )
    return _cross_encoder_cache[CROSS_ENCODER_MODEL]


def build_rerank_text(profile):
    
    parts = [profile.get("name", "")]
    if profile.get("description"):
        parts.append(profile["description"])
    if profile.get("motivation"):
        parts.append("Motivation: " + ", ".join(profile["motivation"]))
    if profile.get("target_sectors"):
        parts.append("Targets: " + ", ".join(profile["target_sectors"]))
    return ". ".join(parts)


def rerank_with_cross_encoder(query_text, results, semantic_profiles,
                              cross_encoder=None, rerank_top_k=10,
                              blend_weight=0.3):
    
   
    if not query_text or not query_text.strip() or not results:
        return results

    if cross_encoder is None:
        cross_encoder = load_cross_encoder()

    name_to_profile = {p["name"]: p for p in (semantic_profiles or [])}

    to_rerank = results[:rerank_top_k]
    remainder = results[rerank_top_k:]

    pairs = []
    for r in to_rerank:
        profile = name_to_profile.get(r["name"], {})
        candidate_text = build_rerank_text(profile)
        pairs.append((query_text, candidate_text))

    raw_scores = [float(s) for s in cross_encoder.predict(pairs)]
    fusion_scores = [r["combined_score"] for r in to_rerank]

   
    ce_min, ce_max = min(raw_scores), max(raw_scores)
    ce_range = ce_max - ce_min
    f_min, f_max = min(fusion_scores), max(fusion_scores)
    f_range = f_max - f_min

    reranked = []
    for r, raw_score in zip(to_rerank, raw_scores):
        r = dict(r)
        r["cross_encoder_score"] = raw_score
        normalised_ce = (raw_score - ce_min) / ce_range if ce_range > 0 else 0.5
        normalised_fusion = ((r["combined_score"] - f_min) / f_range
                             if f_range > 0 else 0.5)
        r["blended_score"] = (
            blend_weight * normalised_ce
            + (1 - blend_weight) * normalised_fusion
        )
        reranked.append(r)

    reranked.sort(key=lambda x: x["blended_score"], reverse=True)

    return reranked + remainder


if __name__ == "__main__":
    index_path = "data/malpedia/malware_actor_index.json"
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            malware_index = json.load(f)
    else:
        malware_index = {}

    groups, idf_weights = load_groups_with_idf()
    model, embeddings, semantic_profiles = load_semantic_components()

    tests = [
        {
            "name": "TEST 1 - Explicit tools (APT29 expected)",
            "text": """
                Phishing emails targeted state organizations delivering
                malicious shortcut files executing PowerShell commands.
                MASEPIE used for file transfers, STEELHOOK for browser
                data theft, OCEANMAP as backdoor. Poland targeted.
            """
        },
        {
            "name": "TEST 2 - Paraphrased (APT29 expected)",
            "text": """
                Nation-state actor sent spearphishing emails to government
                ministry employees. Credentials harvested from memory,
                lateral movement via RDP. Browser data collected and
                exfiltrated. Eastern European government targeted.
            """
        },
        {
            "name": "TEST 3 - APT28 paraphrased",
            "text": """
                State sponsored actors sent targeted emails to defence
                ministry officials. Keylogger installed, credentials stolen.
                NATO member states targeted. Russian military intelligence
                infrastructure overlap observed.
            """
        }
    ]

    for test in tests:
        print("\n" + "="*60)
        print(test["name"])
        print("="*60)

        results = hybrid_attribute(
            test["text"], model, embeddings,
            semantic_profiles, groups,
            malware_index=malware_index,
            idf_weights=idf_weights
        )

        for i, r in enumerate(results, 1):
            signal = " ← DIRECT" if r["direct_signal"] else ""
            print(f"#{i} {r['name']}")
            print(f"   Combined: {r['combined_score']}% | "
                  f"Semantic: {r['semantic_score']}% | "
                  f"Keyword: {r['keyword_score']}%")
            print(f"   Country: {r['country']}{signal}")
            if r['extracted_sectors']:
                print(f"   Sectors: {r['extracted_sectors']}")
            if r['extracted_geographies']:
                print(f"   Geos: {r['extracted_geographies']}")