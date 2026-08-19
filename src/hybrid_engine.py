# Threat Actor Attribution System - Hybrid Engine
# ELE8095 OO05 - Sai Pavan Yoganand
# Purpose: Combines keyword baseline with semantic similarity

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

# Weights for combining scores
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


def fuse_engine_scores(engine_outputs, base_weights=None):
    """
    Combines per-actor scores from multiple independent scoring
    engines (semantic, keyword, sector, and eventually IoC), only
    using engines that actually produced output for this query.

    engine_outputs: dict of {engine_name: {actor_name: score}}.
        An engine with an empty dict (e.g. semantic scoring on a
        query with no free text) is treated as "did not fire" and
        excluded entirely, rather than contributing a zero that
        would otherwise just dilute the final score.
    base_weights: dict of {engine_name: nominal_weight}. Defaults
        to ENGINE_WEIGHTS. Only the weights for engines present in
        engine_outputs are used, and they are renormalised to sum
        to 1 across those present engines.

    Returns: dict of {actor_name: fused_score}, or {} if no engine
    produced any output at all.
    """
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

MODEL_NAME = "all-MiniLM-L6-v2"  # reverted from jina-embeddings-v5-text-small; MUST match
# semantic_engine.py's MODEL_NAME exactly -- embeddings built with
# one model are incompatible with queries encoded by a different one.
EMBEDDINGS_PATH = "data/unified/actor_embeddings.pt"
PROFILES_PATH = "data/unified/knowledge_base.json"


def load_semantic_components():
    """
    Load model and pre-computed embeddings.

    Uses GPU automatically if available (confirmed present: RTX 4060
    Laptop GPU). Both the model AND the pre-computed embeddings are
    moved to the SAME device -- doing only one of these would cause
    a device-mismatch error the moment cosine similarity tries to
    compare a GPU-encoded query against CPU-resident actor
    embeddings (or vice versa).
    """
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Loading semantic components on device: {device}...")
    # NOTE: correct as-is for all-MiniLM-L6-v2. If switching back to
    # jina-embeddings-v5-text-small, restore trust_remote_code=True
    # and model_kwargs={"default_task": "text-matching"} -- see
    # semantic_engine.py for why.
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
    """
    Returns a dictionary of actor_name -> semantic_score for all
    actors, using plain cosine similarity.

    REAL BUG FOUND AND FIXED (found during a full-codebase audit): a
    BGE-specific query instruction prefix ("Represent this sentence
    for searching relevant passages: ") was left in this function
    from an abandoned BGE-base-en-v1.5 model-swap experiment.
    MODEL_NAME was correctly reverted back to all-MiniLM-L6-v2 after
    that experiment did not resolve the hubness problem, but this
    prefix-prepending code was never removed alongside it -- meaning
    every query, in every evaluation run since that revert, was
    having an irrelevant BGE-formatted instruction string silently
    prepended before being embedded by a model (MiniLM) never trained
    to expect it. Removed.

    Two post-hoc hubness-correction techniques were tried and
    reverted after real testing: global centering and CSLS. Both
    independently produced the same regression on the real
    evaluation suite (Top-1 73.3% -> 66.7%, MRR 0.822 -> 0.711) with
    no meaningful improvement on external validation sets. A
    source-text correction (stripping generic templated language)
    was also tried and found not to reduce hubness at all
    (correlation between hub-ness and centroid proximity remained
    ~1.0, just shifted which actors were hubs). A BGE-base-en-v1.5
    model swap was also tried and reverted for the same reason.
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


def get_keyword_scores(query_text, groups,
                       malware_index=None, idf_weights=None,
                       direct_ttps=None):
    """
    Uses entity extractor to pull structured signals from text,
    then scores actors using TTP overlap scoring. Also accepts
    direct_ttps — a set of ATT&CK technique IDs supplied directly
    by the analyst (bypassing free text entirely), for the case
    where someone already has a structured TTP list, e.g. exported
    from a SIEM or CTI platform, and no incident description at all.
    Direct signals from exclusive tools receive maximum score.

    Also computes tool_scores separately: shared (non-exclusive)
    tool matches -- e.g. a malware family used by several different
    actors -- are real CTI evidence but weaker than an exclusive
    match. Previously these were extracted by entity_extractor but
    then silently discarded, since only exclusive matches fed
    direct_actor_signals and nothing else consumed entities["tools"].
    Returned as its own dict so hybrid_attribute() can register it
    as an independent engine with its own weight, mirroring how
    get_ioc_scores() already handles shared IoC matches (split
    credit among the actors rather than dropping the signal).
    """
    if malware_index is None:
        malware_index = {}
    if direct_ttps is None:
        direct_ttps = set()

    query_text = query_text or ""

    # Extract entities from text (safe on empty string — just
    # returns empty results for every category)
    entities = extract_entities(query_text, malware_index)

    # Combine TTPs mentioned in free text with any supplied directly
    matched_ttps = set(entities["explicit_ttps"]) | set(direct_ttps)

    # Get direct actor signals from entity extractor
    direct_actor_signals = set(entities["direct_actor_signals"])

    # Also check TOOL_TO_ACTOR for recent tools not in MITRE index.
    #
    # REAL BUG FOUND AND FIXED: this loop previously had NO length
    # guard at all, unlike extract_tools() (which requires
    # len(tool_name) > 5). TOOL_TO_ACTOR contains short, legitimate
    # tool names -- "net", "at", "ping", "reg", "tor", "page", "lv",
    # "disco" (real Windows living-off-the-land binaries and short
    # malware family abbreviations) -- that are also common English
    # words or common substrings of unrelated words. Confirmed via
    # direct testing: "disco" matched inside a scraped webpage's
    # unrelated "trending articles" sidebar junk (almost certainly
    # matching inside a word like "discovered"), silently triggering
    # an exclusive-match +0.25 direct-signal boost for an unrelated
    # actor (MoustachedBouncer) on a real Kimsuky report. Since this
    # loop runs on every single query through get_keyword_scores, it
    # could have been quietly injecting false direct-signal boosts
    # across every evaluation run tonight, not just this one case.
    #
    # Fixed with the same length guard already used in extract_tools(),
    # plus word-boundary matching (so "net" doesn't match inside
    # "internet" or "Netscout") rather than raw substring matching.
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

    # Shared (non-exclusive) tool matches: real evidence, weaker than
    # a direct/exclusive signal, but previously thrown away entirely
    # once extract_tools found >1 associated actor. Mirrors
    # get_ioc_scores' shared-match handling -- split credit among the
    # actors rather than discarding it. Kept as its own engine output
    # (not merged into keyword_scores) so it gets its own weight and
    # its own ablation sweep, same discipline as sector/motivation/IoC.
    tool_scores = {}
    for tool_name, actors in entities["tools"].items():
        if isinstance(actors, list) and len(actors) > 1:
            for actor in actors:
                tool_scores[actor] = max(tool_scores.get(actor, 0.0),
                                          1.0 / len(actors))

    return scores, matched_ttps, direct_actor_signals, entities, tool_scores


_sector_idf_cache = {}


def compute_sector_idf(groups):
    """
    Computes IDF-style rarity weights per sector, same principle as
    attribution_engine.py's technique IDF weights: a sector shared by
    many actors (e.g. "Government", present in ~91/186 actors) is a
    weak discriminating signal; a rare sector (e.g. "Petroleum",
    present in 1 actor) is a strong one. Verified against real data:
    rarity-weighted sector scoring improved sector-only Top-1 from
    20% to 25% on the real test set, versus unweighted overlap
    scoring which treats "Government" and "Petroleum" as equally
    informative.

    Cached per groups object id, since this only needs computing
    once per knowledge base load, not per query.
    """
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
    """
    Scores each actor on overlap between the sectors extracted from
    the query text and the actor's normalised target_sectors.

    When sector_idf is provided (computed once via
    compute_sector_idf), uses RARITY-WEIGHTED overlap -- a match on
    a rare, specific sector counts far more than a match on a broad
    one nearly every state-linked actor shares. Falls back to simple
    unweighted overlap ratio if sector_idf is None, for backward
    compatibility.

    Returns an empty dict (no signal) if the query has no extractable
    sector mentions.
    """
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
    """
    Scores each actor on overlap between the motivation category
    extracted from the query text (Espionage / Financial /
    Sabotage-Destruction) and the actor's own normalised motivation.

    Diagnosed use case: distinguishes actors sharing near-identical
    country/sector/semantic profiles but genuinely different intent
    -- e.g. Sandworm Team (Sabotage/Destruction) vs its semantic
    confuser Inception (Espionage), a real signal no other engine
    currently uses. Returns an empty dict (no signal) if the query
    text has no extractable motivation language.
    """
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
    """
    Scores each actor on overlap between country/geography mentions
    extracted from the query text (or supplied directly) and the
    actor's own normalised country field.

    Diagnosed use case: a real 20-actor exact-tie cluster on sector
    data alone (all tagged only ['Government','Private Sector'],
    including APT29, Lazarus Group, Sandworm Team, and Kimsuky from
    the evaluation set) was found to collapse to 9 subgroups when
    motivation is added, and further to a largest remaining group of
    just 7 when country is added on top -- measured directly against
    real knowledge base data, not assumed. No new external source
    needed: country data was already present in every actor profile,
    just never scored.

    Some knowledge base entries carry bracketed placeholder values
    (e.g. "[Unknown]", "[South Asia]", "[Gaza]") for actors without
    a confirmed single-nation attribution. These simply won't match
    any extracted geography keyword (which are always plain country
    names, e.g. "Russia", "China" -- see entity_extractor.py's
    GEOGRAPHY_KEYWORDS), which is correct, honest behaviour: an
    actor with no confirmed single-nation origin genuinely can't be
    validated against a specific country mention, rather than a bug
    to work around.

    Returns an empty dict (no signal) if the query has no
    extractable country/geography mentions.
    """
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
    """
    Scores each actor on IoC matches between the IoCs found in the
    query (extracted from free text, or supplied directly) and the
    OTX-derived ioc_actor_index. Mirrors the exclusive-tool-signal
    logic in attribution_engine.score_groups: an IoC seen linked to
    exactly one actor is a strong signal; an IoC linked to multiple
    actors (shared infrastructure, or a coincidental false positive
    match) contributes a weaker, shared score instead of a direct one.

    query_iocs: flat list/set of raw IoC values (any of the three
        types — the index itself carries the type, so the caller
        doesn't need to pre-sort them).
    """
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
            # Exclusive match — same reasoning as an exclusive tool
            # in attribution_engine.py's direct-signal logic
            direct_signals.add(actors[0])
            scores[actors[0]] = 1.0
        else:
            # Shared across multiple actors — real but weaker
            # evidence, split among the actors it was seen with
            for actor in actors:
                scores[actor] = max(scores.get(actor, 0.0),
                                    1.0 / len(actors))

    return scores, direct_signals


def assess_attribution_confidence(ranked, top_support_count=None,
                                   cluster_threshold=0.90,
                                   min_supporting_engines=4):
    """
    Assesses whether the top-ranked attribution is confidently
    distinguishable from its closest competitors, or whether the
    evidence leaves genuine ambiguity among multiple candidates.

    SCOPE, STATED PLAINLY: this does NOT detect false flag
    operations directly. No automated text-based system can
    definitively confirm a false flag from CTI report text alone --
    that requires independent, out-of-band evidence (infrastructure
    reuse, OPSEC failures, signals intelligence) beyond what any
    text-based attribution engine can access. What this DOES provide
    is real, evidence-based AMBIGUITY DETECTION.

    REAL, EVIDENCE-DRIVEN REVISION (important -- read before
    changing thresholds): an earlier version of this function used
    ONLY score-cluster separation (is the top candidate clearly
    isolated from its closest competitors) to decide confidence.
    Tested directly against 47 real, external report cases (CTIBench
    CTI-TAA), that alone was a coin flip: 12 of 24 "high-confidence"
    predictions were WRONG (50%). Root cause, confirmed by direct
    measurement: embedding-space hubness (see the semantic-scoring
    history elsewhere in this file) can produce a clear, isolated,
    decisive-LOOKING score lead purely from structural bias, with no
    genuine multi-engine evidence behind it -- exactly the failure
    mode score-cluster-only confidence cannot distinguish from a
    real, well-evidenced win.

    Fix, grounded in the same real test: high-confidence CORRECT
    predictions averaged 3.42 independent NON-SEMANTIC engines
    (keyword, tool, sector, motivation, country, ioc) corroborating
    the winner; high-confidence WRONG predictions averaged only 2.17,
    and critically, ZERO of the 12 wrong predictions had 4 or more
    non-semantic engines agreeing, while 8 of 12 correct predictions
    did. "High" confidence now requires BOTH genuine score separation
    AND real multi-engine corroboration -- specifically to guard
    against hub-driven false confidence, the single largest risk
    identified in tonight's entire investigation.

    top_support_count: count of non-semantic engines that produced a
    real (>0) score for the winning candidate specifically. Must be
    supplied by the caller (hybrid_attribute has direct access to the
    per-engine score dicts needed to compute this; this function does
    not). If None, falls back to score-cluster-only assessment (with
    an explicit note in the reasoning that engine support wasn't
    checked), rather than silently assuming high confidence.

    min_supporting_engines: minimum non-semantic engine count
    required for "high" confidence, regardless of how isolated the
    score looks. Set to 4 based on the real evidence above.

    Returns a dict: confidence ("high"/"low"), top_cluster (list of
    (name, score) tuples), reasoning (short human-readable string).
    """
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

    # Score is isolated -- but isolation alone was proven (via real
    # external testing) to be an unreliable confidence signal on its
    # own, since embedding hubness can fake it. Require genuine
    # multi-engine corroboration too.
    if top_support_count is None:
        return {
            "confidence": "high",
            "top_cluster": top_cluster,
            "reasoning": (
                f"{top_name} is clearly separated from all other "
                f"candidates. NOTE: multi-engine corroboration was not "
                f"checked for this call (top_support_count not "
                f"supplied) -- this confidence level is based on score "
                f"separation alone, which was found, via real external "
                f"testing, to be unreliable on its own."
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
    """
    Main hybrid attribution function. Dispatches to whichever
    scoring engines are actually applicable given the input
    provided, then combines their outputs via the fusion layer.

    Supports partial input in any combination:
      - query_text alone (the original use case: free-text
        description, everything derived from it)
      - direct_ttps alone, with no query_text at all (analyst
        already has a structured technique list, e.g. exported
        from a SIEM, and no incident narrative to write)
      - direct_sectors alone, or combined with either of the above
      - direct_motivation and/or direct_countries, alone or combined
        with any of the above (e.g. an analyst who knows the target
        sector, suspects the intent, and has a country hypothesis,
        but no narrative text at all)
      - any combination of all five together

    The semantic engine only runs if query_text is actually
    provided — there is no meaningful text to embed otherwise, and
    running it anyway would inject a near-random similarity score
    into the fusion rather than correctly contributing nothing.
    """
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

    # Tool engine: shared (non-exclusive) tool/malware-family matches.
    # Exclusive matches already flow into direct_signals above and
    # get the additive direct-signal boost further down; this engine
    # covers the previously-discarded case where a tool is real
    # evidence but tied to more than one candidate actor.
    if tool_scores:
        engine_outputs["tool"] = tool_scores

    # Sector engine: fires on extracted-from-text sectors, direct
    # sector input, or both combined. sector_idf is computed once
    # and cached per groups object (see compute_sector_idf), so this
    # doesn't recompute rarity weights on every single query.
    query_sectors = set(entities["sectors"]) | set(direct_sectors)
    sector_idf = compute_sector_idf(groups)
    sector_scores = get_sector_scores(query_sectors, groups, sector_idf=sector_idf)
    if sector_scores:
        engine_outputs["sector"] = sector_scores

    # Motivation engine: fires on extracted-from-text motivation
    # language, direct motivation input, or both combined
    query_motivation = set(entities["motivation"]) | set(direct_motivation)
    motivation_scores = get_motivation_scores(query_motivation, groups)
    if motivation_scores:
        engine_outputs["motivation"] = motivation_scores

    # Country engine: fires on extracted-from-text ORIGIN country
    # mentions specifically (see entity_extractor.extract_origin_
    # countries), direct country input, or both combined. Uses
    # origin_countries rather than the broader geographies field --
    # geographies matches ANY country mentioned, including victim
    # locations, which was found (real evidence: Thales validation
    # case T5) to wrongly reward actors based in a victim's country
    # rather than the attacker's actual origin. See
    # get_country_scores docstring for the original tie-breaking
    # motivation behind this engine.
    query_countries = set(entities["origin_countries"]) | set(direct_countries)
    country_scores = get_country_scores(query_countries, groups)
    if country_scores:
        engine_outputs["country"] = country_scores

    # IoC engine: fires on extracted-from-text IoCs, direct IoC
    # input, or both combined. Requires ioc_index to be built
    # first (see otx_pipeline.py) — with no index yet, this
    # correctly produces no signal rather than erroring out.
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

    # If nothing fired at all — no text, no TTPs, no sectors —
    # there is genuinely nothing to attribute from. Return early
    # rather than proceeding with an empty, meaningless ranking.
    if not engine_outputs:
        return []

    fused = fuse_engine_scores(engine_outputs, base_weights=engine_weights)

    # Direct signal boost is applied additively, on top of the
    # fused score, rather than folded into the weighted blend —
    # an exclusive tool match is treated as near-decisive evidence
    # regardless of which other engines fired.
    combined = {}
    for name, score in fused.items():
        base = score
        if name in direct_signals:
            base = base + 0.25
        combined[name] = min(base, 1.0)

    # Deterministic tie-break: when scores are exactly equal (a real,
    # honest outcome -- e.g. two actors sharing identical documented
    # sector/motivation/country data), fall back to alphabetical
    # actor name rather than Python's per-process hash-seed-dependent
    # set ordering. Without this, identical inputs could silently
    # rank tied actors differently across separate runs, making
    # reported accuracy numbers non-reproducible.
    ranked = sorted(combined.items(), key=lambda x: (-x[1], x[0]))

    # Ambiguity / false-flag risk assessment -- computed once on the
    # full ranked list before truncating to top_n. Requires the top
    # candidate's non-semantic engine support count (see
    # assess_attribution_confidence's docstring for why score
    # isolation alone was proven unreliable via real external
    # testing).
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
            # New: ambiguity / false-flag-risk fields. "confidence"
            # and "reasoning" are the same for every entry in a given
            # call (they describe the overall attribution's
            # reliability, not a per-actor property) -- repeated on
            # each result for convenience so callers reading a single
            # result dict don't need to separately track the overall
            # assessment. in_top_cluster marks which specific
            # candidates are part of the genuinely-competitive group.
            "attribution_confidence": confidence_assessment["confidence"],
            "confidence_reasoning": confidence_assessment["reasoning"],
            "in_top_cluster": name in top_cluster_names,
            "matched_ttps": list(matched_ttps),
            "extracted_sectors": entities["sectors"],
            "extracted_geographies": entities["geographies"],
        })

    return results


# Cross-encoder reranking stage. Unlike the bi-encoder semantic engine
# above (which encodes query and actor profile INDEPENDENTLY, then
# compares fixed vectors via cosine similarity), a cross-encoder
# processes both texts TOGETHER through the model, letting them
# attend to each other directly. This is specifically well-suited to
# cases where two candidates share identical structured data (country,
# motivation, sector) and the only remaining discriminating signal is
# subtle phrasing in the actual prose -- exactly the diagnosed failure
# pattern for APT29 vs Inception.
#
# Standard two-stage pattern: the existing hybrid_attribute() above
# still does all the real work (semantic + keyword + sector +
# motivation + IoC fusion) to produce a shortlist. This stage ONLY
# reranks that shortlist -- it does not replace the fusion pipeline,
# since cross-encoders can't be run against all 186 actors for every
# query as cheaply as a precomputed-embedding cosine comparison.
CROSS_ENCODER_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
_cross_encoder_cache = {}


def load_cross_encoder():
    """Loads (once, cached) the cross-encoder reranking model."""
    if CROSS_ENCODER_MODEL not in _cross_encoder_cache:
        device = "cuda" if torch.cuda.is_available() else "cpu"
        print(f"Loading cross-encoder reranker on device: {device}...")
        _cross_encoder_cache[CROSS_ENCODER_MODEL] = CrossEncoder(
            CROSS_ENCODER_MODEL, device=device
        )
    return _cross_encoder_cache[CROSS_ENCODER_MODEL]


def build_rerank_text(profile):
    """
    Builds the text representation of an actor profile used for
    cross-encoder pairing. Kept simple and self-contained here
    rather than importing semantic_engine.py's profile-text builder,
    to avoid a circular dependency between the two modules.
    """
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
    # blend_weight=0.3 is a provisional starting default based on a
    # real (small-scale) sweep against one diagnosed hard case, NOT
    # yet properly ablation-tested -- same discipline as every other
    # new weight added tonight (sector/motivation/IoC all started
    # this way before their own validated sweep). Needs a real
    # ablation pass before being trusted as final.
    """
    Reranks the top rerank_top_k candidates from hybrid_attribute()'s
    results using a cross-encoder, BLENDED with the original fusion
    score (not replacing it). The cross-encoder only sees raw profile
    text -- it has no awareness of TTP, sector, motivation, or IoC
    signal, all of which the original combined_score already
    incorporates. A full override would throw that structured signal
    away; blending keeps both contributing.

    blend_weight controls how much the cross-encoder's opinion counts
    relative to the original fusion score (0.5 = equal weight).
    Cross-encoder raw scores are normalised via MIN-MAX across just
    this shortlist, not a fixed sigmoid -- sigmoid collapses badly
    when every candidate's raw score happens to land in the same
    tail of the curve (e.g. all strongly negative), squashing them
    all to a near-identical tiny value and silently erasing their
    relative differences. Min-max preserves whatever real spread
    exists among the actual candidates being compared, regardless of
    their absolute scale.

    Candidates beyond rerank_top_k keep their original ordering,
    appended after the reranked set. With no query_text, returns
    results unchanged -- nothing meaningful to rerank against.
    """
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

    # Symmetric min-max normalisation on BOTH sides -- dividing
    # fusion by a fixed /100 while min-max-stretching the cross-
    # encoder side is an asymmetry that let the cross-encoder
    # dominate almost regardless of blend_weight whenever fusion
    # scores happened to cluster tightly together (a real, tested
    # failure mode: at blend_weight=0.1, the cross-encoder's answer
    # still won outright). Min-max on both sides means blend_weight
    # actually controls the balance as intended.
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