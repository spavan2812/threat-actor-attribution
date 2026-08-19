import json
import os
from hybrid_engine import hybrid_attribute, load_semantic_components, load_ioc_index
from attribution_engine import load_groups_with_idf

UNIT42_TEST_CASES = [
    {
        "id": "U1",
        "description": """
            A state-sponsored group has been active since at least
            2013 and is attributed to Iran, traditionally focusing on
            Middle Eastern targets and Nordic universities across the
            EU. Members are affiliated with an Iran-based academic
            institute linked to intrusions carried out on behalf of
            the Iranian government, specifically its Revolutionary
            Guard. Research and proprietary data at universities,
            government agencies, and private-sector companies
            worldwide have been targeted. A notable drop in activity
            was observed following the international COVID crisis
            in 2020.
        """,
        "expected": "Silent Librarian",
    },
    {
        "id": "U2",
        "description": """
            A suspected nation-state actor attributed to Iran has
            primarily disrupted Israeli organisations since 2020,
            with links to attacks across the wider Middle East. The
            group's approach involves exfiltrating sensitive data
            before deploying destructive ransomware and wiper malware
            to disrupt systems and cover its tracks. Education,
            technology, and financial-sector organisations have been
            targeted.
        """,
        "expected": "Agrius",
    },
    {
        "id": "U3",
        "description": """
            Active since at least 2012, a suspected nation-state
            group attributed to China runs long-term cyberespionage
            campaigns, primarily against telecommunications
            companies, government entities, and financial
            institutions across Southeast Asia, Europe, and Africa.
            Operations are characterised by multi-wave intrusions
            aimed at establishing persistent footholds, with initial
            access gained by exploiting vulnerabilities in
            internet-facing applications, followed by custom and
            modified malware across multiple operating systems to
            move laterally and evade detection.
        """,
        "expected": "GALLIUM",
    },
    {
        "id": "U4",
        "description": """
            Active since at least 2017, an Iranian state-sponsored
            cyberespionage group has been attributed by US Cyber
            Command to Iran's Ministry of Intelligence and Security.
            The group's objective is cyberespionage aligned with
            Iranian government interests, including intelligence
            gathering, operational disruption, and responses to
            regional conflicts -- particularly those involving Israel.
        """,
        "expected": "MuddyWater",
    },
    {
        "id": "U5",
        "description": """
            A state-sponsored cyberespionage group attributed to
            China has been active since 2021, with the goal of
            stealing intellectual property aligned with China's
            national interests. The group has demonstrated the
            capability to exploit undisclosed zero-day
            vulnerabilities.
        """,
        "expected": "Threat Group-3390",
    },
    {
        "id": "U6",
        "description": """
            A nation-state actor attributed to a major Western
            adversary's foreign intelligence service has been active
            since at least 2008, targeting government, diplomatic,
            and critical-infrastructure entities worldwide across
            North America, Europe, and countries opposing that
            nation's geopolitical objectives. The group's primary
            focus is intelligence gathering and data exfiltration to
            support foreign-policy goals, gain advantage in
            geopolitical conflicts, and monitor perceived adversaries.
        """,
        "expected": "APT29",
    },
    {
        "id": "U7",
        "description": """
            A financially motivated ransomware-as-a-service operation
            with suspected ties to a now-defunct major ransomware
            group shares similar tactics, techniques, and
            infrastructure with that predecessor. First observed in
            April 2022, the group uses double extortion -- encrypting
            data and threatening public disclosure of sensitive
            information to coerce payment -- targeting critical
            infrastructure and high-profile organisations globally.
        """,
        "expected": "Storm-1811",
    },
    {
        "id": "U8",
        "description": """
            An Iran-based threat actor is known for social
            engineering tactics and malware that communicates via
            IMAP for command and control, using specific email
            addresses. Watering-hole attacks and fake employment-offer
            sites designed to interest potential victims are part of
            the group's playbook.
        """,
        "expected": "CURIUM",
    },
    {
        "id": "U9",
        "description": """
            A suspected nation-state group attributed to China has
            been active since at least 2012, targeting organisations
            across Taiwan, Hong Kong, mainland China, India, and
            Africa in operations aligned with Chinese intelligence
            interests. Advanced malware frameworks have been deployed
            using varied initial-access vectors, including
            supply-chain compromise and DNS poisoning.
        """,
        "expected": "Daggerfly",
    },
    {
        "id": "U10",
        "description": """
            A sophisticated cybercriminal group emerged in June 2022,
            known for double-extortion tactics -- exfiltrating
            sensitive data before encrypting systems and threatening
            to leak it unless a ransom is paid. Tooling includes a mix
            of custom and publicly available utilities for
            command-and-control, lateral movement, credential
            dumping, and data exfiltration.
        """,
        "expected": "Play",
    },
    {
        "id": "U11",
        "description": """
            A nation-state group attributed to a Western adversary's
            military intelligence directorate is well known for
            targeting entities of strategic interest to that nation,
            especially those with military significance. The group is
            recognised as one of two state-linked actors that
            compromised major U.S. political party organisations
            during the 2016 election cycle.
        """,
        "expected": "APT28",
    },
    {
        "id": "U12",
        "description": """
            A financially motivated ransomware-as-a-service operation
            observed since early 2023 uses double-extortion tactics,
            exfiltrating sensitive data before typically encrypting
            systems. Targeting is global, with a focus on North
            America, the UK, Australia, and Europe, impacting
            manufacturing, professional services, education, critical
            infrastructure, and retail. Observed dwell times range
            from under 24 hours to roughly a month.
        """,
        "expected": "Akira",
    },
    {
        "id": "U13",
        "description": """
            A Chinese state-sponsored actor focused on espionage and
            information gathering has been active since 2021,
            evading detection through living-off-the-land techniques
            that rely on built-in system tools to blend in with
            normal network activity. The actor leverages compromised
            small office/home office network devices as intermediate
            infrastructure to further obscure its operations.
        """,
        "expected": "Volt Typhoon",
    },
    {
        "id": "U14",
        "description": """
            A state-sponsored cyberespionage group believed linked to
            the Chinese government has been active since at least
            2013, supporting national strategic objectives in
            sensitive research and geopolitically significant
            relationships. Initial access relies on phishing emails
            and exploitation of web-server vulnerabilities, with a
            particular interest in maritime-related targets connected
            to naval modernisation efforts.
        """,
        "expected": "Leviathan",
    },
    {
        "id": "U15",
        "description": """
            A Pakistan-based threat actor has been operating since at
            least 2019, mainly targeting South Asian countries,
            specifically India and Afghanistan. The malware's common
            name derives from an infection chain designed to mimic
            another well-known actor's tooling, and this group has
            reported similarities with a related Pakistan-linked
            actor, possibly representing a subdivision of it.
        """,
        "expected": "SideCopy",
    },
    {
        "id": "U16",
        "description": """
            A financially motivated cyberthreat group active since at
            least May 2022 is composed of English-speaking members,
            some reportedly as young as 16. Initial operations
            involved SIM swapping and credential harvesting targeting
            individuals for cryptocurrency theft, later evolving to
            include data theft and ransomware deployment aimed at
            extorting large organisations for financial gain.
        """,
        "expected": "Scattered Spider",
    },
    {
        "id": "U17",
        "description": """
            A suspected nation-state actor attributed to China has
            been active since at least 2017, conducting stealthy,
            long-term intrusions focused on espionage operations
            against high-technology companies.
        """,
        "expected": "Chimera",
    },
    {
        "id": "U18",
        "description": """
            A Pakistan-based threat group has been active since 2013,
            primarily targeting Indian governmental, military, and
            educational sectors.
        """,
        "expected": "Transparent Tribe",
    },
    {
        "id": "U19",
        "description": """
            A Russia-based threat group has been operating since at
            least 2004, linked to that nation's federal security
            service.
        """,
        "expected": "Turla",
    },
    {
        "id": "U20",
        "description": """
            A ransomware-as-a-service operation active since July
            2021 has exploited vulnerabilities such as ProxyShell in
            Microsoft Exchange Servers, using tools like Cobalt Strike
            alongside obfuscation and anti-debugging techniques to
            evade detection. The malware checks system language
            settings and exits if Russian or certain Eastern European
            languages are detected, apparently to avoid impacting
            systems in those regions.
        """,
        "expected": "BlackByte",
    },
    {
        "id": "U21",
        "description": """
            A nation-state group attributed to a subgroup of a major
            Western adversary's military intelligence directorate
            uses spear phishing and vulnerability exploitation to
            access systems, with objectives spanning espionage and
            destruction. Activities have included targeting
            industrial control systems and using distributed
            denial-of-service attacks to disrupt critical
            infrastructure.
        """,
        "expected": "Sandworm Team",
    },
    {
        "id": "U22",
        "description": """
            Active since at least 2012, a threat group assessed as
            Chinese state-sponsored conducts both espionage and
            financially-motivated operations across more than a
            dozen countries.
        """,
        "expected": "Winnti Group",
    },
    {
        "id": "U23",
        "description": """
            A nation-state actor attributed to China has been active
            since at least 2012, with campaigns designed to gather
            sensitive information and exert political influence
            aligned with Chinese state interests, including monitoring
            political developments in regions of strategic importance
            such as areas tied to global 5G rollout.
        """,
        "expected": "Mustang Panda",
    },
    {
        "id": "U24",
        "description": """
            A cybercriminal group that emerged in mid-2023 specialises
            in ransomware attacks focused on financial gain through
            double and triple extortion. Originally targeting a wide
            range of U.S. industries, the group has notably shifted
            focus toward healthcare institutions in the UK.
        """,
        "expected": "INC Ransom",
    },
    {
        "id": "U25",
        "description": """
            A nation-state threat group has been active since at
            least 2013, targeting individuals likely connected to a
            neighbouring government and military, and is believed
            responsible for a 2015 operation that delivered remote
            access tools. The group previously relied on commodity
            tools before shifting to custom-developed tooling in
            2016.
        """,
        "expected": "Gamaredon Group",
    },
]


def evaluate_unit42(model, embeddings, semantic_profiles, groups,
                     malware_index=None, ioc_index=None):
    """
    Runs TRACE against the real, held-out Unit 42 validation set.
    Same Top-1/Top-3/MRR methodology as evaluate() in evaluation.py
    and evaluate_thales() in thales_validation.py, kept as its own
    separate function/dataset for the same reason both of those are
    kept separate from each other and from TEST_CASES -- each
    result should be clearly attributable to its own independent
    source.
    """
    if ioc_index is None:
        ioc_index = load_ioc_index()

    top1_correct = 0
    top3_correct = 0
    reciprocal_ranks = []
    results_log = []

    print(f"\nRunning Unit 42 external validation on "
          f"{len(UNIT42_TEST_CASES)} real, held-out cases...\n")
    print(f"{'ID':<4} {'Expected':<20} {'Got':<20} {'Top1':>5} "
          f"{'Top3':>5} {'RR':>6}")
    print("-" * 65)

    for case in UNIT42_TEST_CASES:
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

        print(f"{case['id']:<4} {expected:<20} "
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
        })

    n = len(UNIT42_TEST_CASES)
    top1_acc = top1_correct / n * 100
    top3_acc = top3_correct / n * 100
    mrr = sum(reciprocal_ranks) / n

    print("\n" + "=" * 65)
    print("UNIT 42 EXTERNAL VALIDATION SUMMARY")
    print("=" * 65)
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

    results = evaluate_unit42(
        model, embeddings, semantic_profiles, groups,
        malware_index=malware_index, ioc_index=ioc_index
    )

    with open("data/unit42_validation_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\nSaved to data/unit42_validation_results.json")