import json
import os
import sys
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf

THALES_TEST_CASES = [
    {
        "id": "T1",
        "description": """
            A China-linked group ran a long-running espionage campaign
            against shipping, logistics, and automotive sector
            organisations, with victims across Italy, Spain, Taiwan,
            Thailand, Turkey, and the UK, beginning as early as 2023.
            Initial access relied on web shells including ANTSWORD and
            BLUEBEAM. A custom in-memory dropper, DUSTPAN, launched a
            BEACON backdoor for command-and-control while disguising
            itself as legitimate Windows processes. A second, modular
            multi-stage framework, DUSTTRAP, decrypted and executed
            payloads directly in memory. SQLULDR2 was used to extract
            database contents, and PINEGROVE exfiltrated data to cloud
            storage such as Microsoft OneDrive, with DLL side-loading
            used for detection evasion.
        """,
        "expected": "APT41",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
    {
        "id": "T2",
        "description": """
            A joint advisory from multiple national security agencies
            described a Russian state-sponsored campaign targeting
            Western logistics organisations and technology companies,
            including entities involved in coordinating aid delivery to
            Ukraine. The transportation sector was specifically
            targeted -- air, sea, rail, ports, airports, air traffic
            management, and major logistics providers. Techniques
            included spear-phishing, password spraying, exploitation of
            known vulnerabilities, abuse of internet-facing
            infrastructure, and use of compromised credentials, with a
            strong operational emphasis on reconnaissance.
        """,
        "expected": "APT28",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
    {
        "id": "T3",
        "description": """
            A North Korean state-aligned actor launched a targeted
            campaign in 2025 against European defence and aerospace
            companies, with particular focus on organisations involved
            in unmanned aerial vehicle (UAV/drone) technology. The
            operation used fake job-offer lures and social engineering
            to persuade engineers and staff to execute trojanised
            software disguised as legitimate application materials. The
            targeting of UAV supply-chain organisations suggests an
            intelligence objective aimed at proprietary manufacturing
            know-how supporting North Korea's drone development
            programmes.
        """,
        "expected": "Lazarus Group",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
    {
        "id": "T4",
        "description": """
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
        """,
        "expected": "APT37",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
    {
        "id": "T5",
        "description": """
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
        """,
        "expected": "Kimsuky",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
    {
        "id": "T6",
        "description": """
            A GRU-affiliated Russian threat cluster was identified
            operating infrastructure consistent with a well-known
            destructive state-sponsored actor, actively targeting
            Western energy organisations throughout 2025. The campaign
            focused on misconfigured network edge devices -- enterprise
            routers, VPN concentrators, and remote access gateways -- to
            gain persistent access to corporate and cloud-hosted
            infrastructure. Credential interception and replay enabled
            lateral movement across networks, harvesting operational
            and administrative data. This represented a deliberate
            shift away from reliance on software vulnerabilities toward
            exploiting infrastructure weaknesses directly tied to
            operational continuity.
        """,
        "expected": "Sandworm Team",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
    {
        "id": "T7",
        "description": """
            A threat group associated with a well-known Russian
            state-sponsored espionage actor targeted healthcare
            organisations by exploiting identity infrastructure rather
            than relying on traditional malware-heavy intrusions.
            Highly tailored phishing campaigns abused app-specific
            passwords and device-code authentication to compromise
            healthcare staff accounts -- particularly clinicians,
            researchers, and administrators with access to cloud email,
            collaboration platforms, and research data repositories.
            The tight integration of cloud identity services with EHRs,
            patient portals, and research platforms in healthcare
            environments enabled long-term, stealthy access to
            sensitive patient data and clinical communications without
            triggering conventional security alerts.
        """,
        "expected": "APT29",
        "source": "Thales Threat Landscape Report H2 2025, Countries section"
    },
]


def evaluate_thales(model, embeddings, semantic_profiles, groups,
                     malware_index=None, ioc_index=None):
    """
    Runs TRACE against the real, held-out Thales validation set.
    Same Top-1/Top-3/MRR methodology as the main evaluate() in
    evaluation.py, kept as a separate function/dataset so results
    here are clearly attributable to external, currently-dated
    reporting rather than the tuning-set test cases.
    """
    if ioc_index is None:
        ioc_index = load_ioc_index()

    top1_correct = 0
    top3_correct = 0
    reciprocal_ranks = []
    results_log = []

    print(f"\nRunning Thales external validation on "
          f"{len(THALES_TEST_CASES)} real, held-out cases...\n")
    print(f"{'ID':<4} {'Expected':<16} {'Got':<20} {'Top1':>5} "
          f"{'Top3':>5} {'RR':>6}")
    print("-" * 60)

    for case in THALES_TEST_CASES:
        results = hybrid_attribute(
            case["description"],
            model, embeddings, semantic_profiles, groups,
            malware_index=malware_index,
            ioc_index=ioc_index,
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

        top1_mark = "correct" if top1 else "wrong"

        print(f"{case['id']:<4} {expected:<16} "
              f"{predicted_names[0] if predicted_names else 'None':<20} "
              f"{top1_mark:>7} {'yes' if top3 else 'no':>5} {rr:>6.2f}")

        results_log.append({
            "id": case["id"],
            "expected": expected,
            "predicted_top1": predicted_names[0] if predicted_names else None,
            "predicted_top3": predicted_names[:3],
            "top1": top1,
            "top3": top3,
            "reciprocal_rank": rr,
            "source": case["source"]
        })

    n = len(THALES_TEST_CASES)
    top1_acc = top1_correct / n * 100
    top3_acc = top3_correct / n * 100
    mrr = sum(reciprocal_ranks) / n

    print("\n" + "=" * 60)
    print("THALES EXTERNAL VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Total cases:      {n}")
    print(f"Top-1 Accuracy:   {top1_acc:.1f}%  ({top1_correct}/{n})")
    print(f"Top-3 Accuracy:   {top3_acc:.1f}%  ({top3_correct}/{n})")
    print(f"MRR:              {mrr:.3f}")

    return results_log


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

    results = evaluate_thales(
        model, embeddings, semantic_profiles, groups,
        malware_index=malware_index, ioc_index=ioc_index
    )

    with open("data/thales_validation_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nSaved to data/thales_validation_results.json")