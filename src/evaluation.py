import json
import torch
from sentence_transformers import SentenceTransformer, util
from hybrid_engine import hybrid_attribute, load_semantic_components
from attribution_engine import load_groups

# ── Labelled Test Dataset ────────────────────────────────────────────
# Each entry has a description and the expected actor at ground truth
# Mix of explicit tool mentions and paraphrased descriptions
# Covers different actor types, countries, and motivations

TEST_CASES = [
    # APT29 - Russia - Government targeting
    {
        "id": 1,
        "description": """
            Phishing emails targeted state organizations delivering malicious 
            shortcut files executing PowerShell. MASEPIE used for file transfers,
            STEELHOOK for browser theft, OCEANMAP as backdoor. Poland targeted.
        """,
        "expected": "APT29",
        "type": "explicit_tools"
    },
    {
        "id": 2,
        "description": """
            Nation-state actor targeted European government ministries with 
            spearphishing emails. After execution credentials harvested from 
            memory, lateral movement via stolen accounts, browser data collected 
            and exfiltrated through encrypted channels.
        """,
        "expected": "APT29",
        "type": "paraphrased"
    },
    # APT28 - Russia - Defence/NATO targeting
    {
        "id": 3,
        "description": """
            X-Agent malware deployed against defence ministry via spearphishing. 
            Sofacy infrastructure used. Keylogging and credential theft observed.
            NATO member states targeted.
        """,
        "expected": "APT28",
        "type": "explicit_tools"
    },
    {
        "id": 4,
        "description": """
            Russian military intelligence actors targeted defence organisations 
            across Eastern Europe using weaponised documents. Keyloggers installed,
            credentials stolen, sensitive documents exfiltrated. Infrastructure 
            consistent with GRU operations.
        """,
        "expected": "APT28",
        "type": "paraphrased"
    },
    # Lazarus Group - North Korea - Financial targeting
    {
        "id": 5,
        "description": """
            WannaCry ransomware deployed across financial institutions. 
            Cryptocurrency exchanges targeted. BLINDINGCAN backdoor used 
            for persistent access. ATM network compromise observed.
        """,
        "expected": "Lazarus Group",
        "type": "explicit_tools"
    },
    {
        "id": 6,
        "description": """
            North Korean actors targeted cryptocurrency platforms and banks 
            using social engineering. After initial access, attackers deployed 
            custom backdoors and conducted large scale financial theft. 
            Hundreds of millions stolen across multiple campaigns.
        """,
        "expected": "Lazarus Group",
        "type": "paraphrased"
    },
    # Sandworm - Russia - Critical infrastructure
    {
        "id": 7,
        "description": """
            INDUSTROYER malware deployed against power grid infrastructure. 
            CRASHOVERRIDE used to manipulate industrial control systems. 
            Ukrainian energy sector targeted causing blackouts.
        """,
        "expected": "Sandworm Team",
        "type": "explicit_tools"
    },
    {
        "id": 8,
        "description": """
            Russian actors targeted critical infrastructure including power 
            grids and industrial control systems. Destructive malware deployed 
            causing physical impact. Ukrainian government and energy organisations 
            repeatedly targeted.
        """,
        "expected": "Sandworm Team",
        "type": "paraphrased"
    },
    # Kimsuky - North Korea - Research/Government
    {
        "id": 9,
        "description": """
            Spearphishing emails sent to South Korean think tanks and government 
            officials. BabyShark malware deployed for reconnaissance. 
            Nuclear policy researchers specifically targeted.
        """,
        "expected": "Kimsuky",
        "type": "explicit_tools"
    },
    {
        "id": 10,
        "description": """
            North Korean intelligence actors conducted espionage against 
            policy research organisations and government agencies focused 
            on Korean peninsula affairs. Credential theft and document 
            collection primary objectives.
        """,
        "expected": "Kimsuky",
        "type": "paraphrased"
    },
    # APT41 - China - Dual espionage and financial
    {
        "id": 11,
        "description": """
            POISONPLUG backdoor used against technology companies and 
            healthcare organisations. Supply chain compromise observed. 
            Both intellectual property theft and financial fraud conducted 
            by same actor simultaneously.
        """,
        "expected": "APT41",
        "type": "explicit_tools"
    },
    {
        "id": 12,
        "description": """
            Chinese actors conducted simultaneous espionage and financially 
            motivated intrusions. Technology sector, gaming companies, and 
            healthcare organisations targeted. Supply chain attacks used 
            to distribute trojanised software updates.
        """,
        "expected": "APT41",
        "type": "paraphrased"
    },
    # OilRig - Iran - Middle East government
    {
        "id": 13,
        "description": """
            HELMINTH backdoor deployed against Middle Eastern government 
            targets. DNS tunneling used for command and control. 
            JSONOSHELL used for persistent access to compromised networks.
        """,
        "expected": "OilRig",
        "type": "explicit_tools"
    },
    {
        "id": 14,
        "description": """
            Iranian actors targeted government organisations across the 
            Middle East using spearphishing and credential harvesting. 
            DNS based covert channels used for data exfiltration. 
            Long term persistent access maintained.
        """,
        "expected": "OilRig",
        "type": "paraphrased"
    },
    # Winnti Group - China - Gaming/Technology
    {
        "id": 15,
        "description": """
            Winnti malware used against gaming companies for source code theft. 
            Digital certificates stolen and used to sign malicious tools. 
            Supply chain attack via gaming software update mechanism.
        """,
        "expected": "Winnti Group",
        "type": "explicit_tools"
    },
]

def evaluate(model, embeddings, semantic_profiles, groups, test_cases):
    """
    Runs evaluation across all test cases.
    Computes Top-1, Top-3 accuracy and MRR.
    """
    top1_correct = 0
    top3_correct = 0
    reciprocal_ranks = []

    results_log = []

    print(f"\nRunning evaluation on {len(test_cases)} test cases...\n")
    print(f"{'ID':<4} {'Expected':<20} {'Got':<20} {'Top1':>5} "
          f"{'Top3':>5} {'RR':>6} {'Type'}")
    print("-" * 75)

    for case in test_cases:
        results = hybrid_attribute(
            case["description"],
            model, embeddings, semantic_profiles, groups,
            top_n=10
        )

        predicted_names = [r["name"] for r in results]
        expected = case["expected"]

        # Top-1 accuracy
        top1 = predicted_names[0] == expected if predicted_names else False

        # Top-3 accuracy
        top3 = expected in predicted_names[:3]

        # Reciprocal rank
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

        top1_mark = "✓" if top1 else "✗"
        top3_mark = "✓" if top3 else "✗"

        print(f"{case['id']:<4} {expected:<20} "
              f"{predicted_names[0] if predicted_names else 'None':<20} "
              f"{top1_mark:>5} {top3_mark:>5} {rr:>6.2f} "
              f"{case['type']}")

        results_log.append({
            "id": case["id"],
            "expected": expected,
            "predicted_top1": predicted_names[0] if predicted_names else None,
            "predicted_top3": predicted_names[:3],
            "top1": top1,
            "top3": top3,
            "reciprocal_rank": rr,
            "type": case["type"]
        })

    # Summary metrics
    n = len(test_cases)
    top1_acc = top1_correct / n * 100
    top3_acc = top3_correct / n * 100
    mrr = sum(reciprocal_ranks) / n

    # By description type
    explicit = [r for r in results_log if r["type"] == "explicit_tools"]
    paraphrased = [r for r in results_log if r["type"] == "paraphrased"]

    exp_top1 = sum(1 for r in explicit if r["top1"]) / len(explicit) * 100
    par_top1 = sum(1 for r in paraphrased if r["top1"]) / len(paraphrased) * 100

    print("\n" + "="*75)
    print("EVALUATION SUMMARY")
    print("="*75)
    print(f"Total test cases:        {n}")
    print(f"Top-1 Accuracy:          {top1_acc:.1f}%  ({top1_correct}/{n})")
    print(f"Top-3 Accuracy:          {top3_acc:.1f}%  ({top3_correct}/{n})")
    print(f"MRR:                     {mrr:.3f}")
    print(f"\nBy description type:")
    print(f"  Explicit tools Top-1:  {exp_top1:.1f}%")
    print(f"  Paraphrased Top-1:     {par_top1:.1f}%")

    return results_log

if __name__ == "__main__":
    print("Loading components...")
    groups = load_groups()
    model, embeddings, semantic_profiles = load_semantic_components()

    results = evaluate(model, embeddings, semantic_profiles, groups, TEST_CASES)

    # Save results
    with open("data/evaluation_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nSaved to data/evaluation_results.json")