import json
import os
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf

EXTERNAL_STRUCTURED_CASES = [
    # -- From Thales Threat Landscape Report H2 2025 --
    {"id": "ET1", "expected": "APT41",
     "country": ["China"], "sectors": [], "motivation": ["Espionage", "Financial"],
     "source": "Thales H2 2025"},
    {"id": "ET2", "expected": "APT28",
     "country": ["Russia"], "sectors": [], "motivation": ["Espionage"],
     "source": "Thales H2 2025"},
    {"id": "ET3", "expected": "Lazarus Group",
     "country": ["North Korea"], "sectors": ["Defence"], "motivation": ["Espionage"],
     "source": "Thales H2 2025"},
    {"id": "ET4", "expected": "APT37",
     "country": [], "sectors": ["Research"], "motivation": ["Espionage"],
     "source": "Thales H2 2025"},
    {"id": "ET5", "expected": "Sandworm Team",
     "country": ["Russia"], "sectors": ["Energy"], "motivation": ["Sabotage/Destruction"],
     "source": "Thales H2 2025"},
    {"id": "ET6", "expected": "APT29",
     "country": ["Russia"], "sectors": ["Healthcare"], "motivation": ["Espionage"],
     "source": "Thales H2 2025"},

    # -- From Unit 42 Threat Actor Groups page (Updated Aug 2025) --
    {"id": "EU1", "expected": "Silent Librarian",
     "country": ["Iran"], "sectors": ["Education", "Government"], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU2", "expected": "Agrius",
     "country": ["Iran"], "sectors": ["Education", "Finance"], "motivation": ["Sabotage/Destruction"],
     "source": "Unit 42"},
    {"id": "EU3", "expected": "GALLIUM",
     "country": ["China"], "sectors": ["Telecommunications", "Government", "Finance"], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU4", "expected": "MuddyWater",
     "country": ["Iran"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU5", "expected": "Threat Group-3390",
     "country": ["China"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU6", "expected": "APT29",
     "country": ["Russia"], "sectors": ["Government"], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU7", "expected": "Storm-1811",
     "country": [], "sectors": [], "motivation": ["Financial"],
     "source": "Unit 42"},
    {"id": "EU8", "expected": "CURIUM",
     "country": ["Iran"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU9", "expected": "Daggerfly",
     "country": ["China"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU10", "expected": "Play",
     "country": [], "sectors": [], "motivation": ["Financial"],
     "source": "Unit 42"},
    {"id": "EU11", "expected": "APT28",
     "country": ["Russia"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU12", "expected": "Akira",
     "country": [], "sectors": [], "motivation": ["Financial"],
     "source": "Unit 42"},
    {"id": "EU13", "expected": "Volt Typhoon",
     "country": ["China"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU14", "expected": "Leviathan",
     "country": ["China"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU15", "expected": "SideCopy",
     "country": ["Pakistan"], "sectors": [], "motivation": [],
     "source": "Unit 42"},
    {"id": "EU16", "expected": "Scattered Spider",
     "country": [], "sectors": [], "motivation": ["Financial"],
     "source": "Unit 42"},
    {"id": "EU17", "expected": "Chimera",
     "country": ["China"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU18", "expected": "Transparent Tribe",
     "country": ["Pakistan"], "sectors": ["Government", "Education"], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU19", "expected": "Turla",
     "country": ["Russia"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU20", "expected": "BlackByte",
     "country": [], "sectors": [], "motivation": ["Financial"],
     "source": "Unit 42"},
    {"id": "EU21", "expected": "Sandworm Team",
     "country": ["Russia"], "sectors": [], "motivation": ["Espionage", "Sabotage/Destruction"],
     "source": "Unit 42"},
    {"id": "EU22", "expected": "Winnti Group",
     "country": ["China"], "sectors": [], "motivation": ["Espionage", "Financial"],
     "source": "Unit 42"},
    {"id": "EU23", "expected": "Mustang Panda",
     "country": ["China"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
    {"id": "EU24", "expected": "INC Ransom",
     "country": [], "sectors": [], "motivation": ["Financial"],
     "source": "Unit 42"},
    {"id": "EU25", "expected": "Gamaredon Group",
     "country": ["Russia"], "sectors": [], "motivation": ["Espionage"],
     "source": "Unit 42"},
]


def evaluate_external_structured(model, embeddings, semantic_profiles,
                                  groups, malware_index=None, ioc_index=None):
    """
    Runs TRACE against real, externally-sourced structured facts
    (country/sector/motivation), with NO free text at all -- see
    module docstring for why this closes a real gap in tonight's
    validation work.
    """
    if ioc_index is None:
        ioc_index = load_ioc_index()

    top1_correct = 0
    top3_correct = 0
    reciprocal_ranks = []
    fired = 0

    print(f"\nRunning external structured-fact validation on "
          f"{len(EXTERNAL_STRUCTURED_CASES)} real cases "
          f"(no free text, direct facts only)...\n")
    print(f"{'ID':<6} {'Expected':<20} {'Got':<20} {'Top1':>5} "
          f"{'Top3':>5} {'RR':>6} {'Source'}")
    print("-" * 78)

    for case in EXTERNAL_STRUCTURED_CASES:
        if not (case["country"] or case["sectors"] or case["motivation"]):
            continue
        fired += 1

        results = hybrid_attribute(
            query_text=None, model=model, embeddings=embeddings,
            semantic_profiles=semantic_profiles, groups=groups,
            malware_index=malware_index, ioc_index=ioc_index,
            direct_countries=set(case["country"]),
            direct_sectors=set(case["sectors"]),
            direct_motivation=set(case["motivation"]),
            top_n=10
        )
        predicted_names = [r["name"] for r in results]
        expected = case["expected"]

        top1 = predicted_names[0] == expected if predicted_names else False
        top3 = expected in predicted_names[:3]

        if expected in predicted_names:
            rank = predicted_names.index(expected) + 1
            rr = 1.0 / rank
        else:
            rr = 0.0

        if top1:
            top1_correct += 1
        if top3:
            top3_correct += 1
        reciprocal_ranks.append(rr)

        mark = "correct" if top1 else "wrong"
        print(f"{case['id']:<6} {expected:<20} "
              f"{predicted_names[0] if predicted_names else 'None':<20} "
              f"{mark:>7} {'yes' if top3 else 'no':>5} {rr:>6.2f} "
              f"{case['source']}")

    n = fired
    top1_acc = top1_correct / n * 100 if n else 0
    top3_acc = top3_correct / n * 100 if n else 0
    mrr = sum(reciprocal_ranks) / n if n else 0

    print("\n" + "=" * 65)
    print("EXTERNAL STRUCTURED-FACT VALIDATION SUMMARY")
    print("=" * 65)
    print(f"Total cases with usable facts: {n}")
    print(f"Top-1 Accuracy:   {top1_acc:.1f}%  ({top1_correct}/{n})")
    print(f"Top-3 Accuracy:   {top3_acc:.1f}%  ({top3_correct}/{n})")
    print(f"MRR:              {mrr:.3f}")


if __name__ == "__main__":
    index_path = "data/malpedia/malware_actor_index.json"
    if os.path.exists(index_path):
        with open(index_path, "r") as f:
            malware_index = json.load(f)
    else:
        malware_index = {}

    print("\nLoading components...")
    groups, idf_weights = load_groups_with_idf()
    model, embeddings, semantic_profiles = load_semantic_components()
    ioc_index = load_ioc_index()

    evaluate_external_structured(
        model, embeddings, semantic_profiles, groups,
        malware_index=malware_index, ioc_index=ioc_index
    )