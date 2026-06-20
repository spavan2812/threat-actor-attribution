from sentence_transformers import SentenceTransformer, util
import json
import os
import torch

#CySecBERT model 
MODEL_NAME = "all-MiniLM-L6-v2"
EMBEDDINGS_PATH = "data/unified/actor_embeddings.pt"
PROFILES_PATH = "data/unified/knowledge_base.json"

def load_model():
    print('Loading CySecBERT model...')
    model= SentenceTransformer(MODEL_NAME)
    print("Model Loaded.")
    return model

def build_actor_profile_text(actor):
    """Converts actor profile into a single text block
    for encoding. Combines description, TTPs, and tools"""
    parts=[]
    name=actor.get('name', "")
    aliases=actor.get("aliases", [])
    parts.append(f"Threat actor: {name}")
    if aliases:
        parts.append(f"Also known as: {', '.join(aliases[:5])}")

    #Description
    desc = actor.get("description", "")
    if desc:
        parts.append(desc[:500])

    country=actor.get("country", [])
    if country:
        parts.append(f"Motivation: {', '.join(country)}")

    motivation = actor.get("motivation", [])
    if motivation:
        parts.append(f"Motivation: {', '.join(motivation)}")

    sectors = actor.get("target_sectors", [])
    if sectors: 
        parts.append(f"Target Sectors: {', '.join(sectors[:5])}")

    ttps = actor.get("ttps", [])
    if ttps:
        ttp_names = [t["technique_name"] for t in ttps[:15]]
        parts.append(f"Known techniques: {', '.join(ttp_names)}")

    tools = actor.get("tools", [])
    if tools:
        if isinstance(tools[0], dict):
            tools_names = [t.get("name", "") for t in tools[:10]]
        else:
            tool_names = tools[:10]
        parts.append(f"Known tools: {', '.join(tool_names)}")

    return " | ".join(parts)

def build_actor_embeddings(model, profiles):
    """Encodes all actor profiles into vectors
    Saves to disk to save time on recomputation"""

    profile_texts=[]
    valid_profiles=[]

    for actor in profiles:
        text= build_actor_profile_text(actor)
        if text.strip():
            profile_texts.append(text)
            valid_profiles.append(actor)

    embeddings=model.encode(
        profile_texts,
        batch_size=32,
        show_progress_bar=True,
        convert_to_tensor=True
    )

    save_data = {
        "embeddings": embeddings,
        "actor_names": [a["name"] for a in valid_profiles]
    }

    torch.save(save_data, EMBEDDINGS_PATH)
    print(f"Saved embeddings to {EMBEDDINGS_PATH}")

    return embeddings, valid_profiles

def load_actor_embeddings(model, profiles):
    """Loads pre-computed embeddedings if they exist"""
    if os.path.exists(EMBEDDINGS_PATH):
        print("Loading pre-computed actor embeddings...")
        save_data = torch.load(EMBEDDINGS_PATH, weights_only=False)
        embeddings = save_data["embeddings"]
        actor_names = save_data["actor_names"]

        name_to_profile = {a["name"]: a for a in profiles}
        valid_profiles = [name_to_profile[n] for n in actor_names if
                          n in name_to_profile]
        print(f"Loaded {len(valid_profiles)} actor embeddings.")
        return embeddings, valid_profiles
    else:
        return build_actor_embeddings(model, profiles)
    
def semantic_attribute(query_text, model, embeddings, profiles, top_n=5):
    """Main semantic attribution function.
    Encodes query text and finds most similar actor profiles"""
    #Encode query
    query_embedding=model.encode(
        query_text, 
        convert_to_tensor=True
    )
    #Compute cosine similarity against all actor profiles
    similarities = util.cos_sim(query_embedding, embeddings)[0]

    #Get top N results
    top_indices = torch.topk(similarities, k=min(top_n, len(profiles)))

    results=[]
    for score, idx in zip(top_indices.values, top_indices.indices):
        actor=profiles[idx.item()]
        results.append({
            "name": actor["name"],
            "aliases": actor.get("aliases", [])[:3],
            "score": round(score.item()*100, 2),
            "country": actor.get("country", []),
            "motivation": actor.get("motivation", []),
            "ttp_count": actor.get("ttp_count", 0)
        })
    return results

if __name__ == "__main__":
    #Load Knowledge Base
    with open(PROFILES_PATH, "r") as f:
        profiles = json.load(f)

    model=load_model()
    embeddings, valid_profiles = load_actor_embeddings(model, profiles)

    # Test 1 - explicit description (same as baseline test)
    print("\n" + "="*60)
    print("TEST 1 - Explicit tool names (APT29 expected)")
    print("="*60)
    test1 = """
    Phishing emails targeted state organizations, delivering 
    malicious shortcut files that executed PowerShell commands. 
    The attack leveraged MASEPIE for file transfers, STEELHOOK 
    for browser data theft, and OCEANMAP as a backdoor. 
    Similar attacks observed in Poland.
    """
    results1 = semantic_attribute(test1, model, embeddings, valid_profiles)
    print(f"\nTop 5 results:")
    for i, r in enumerate(results1, 1):
        print(f"#{i} {r['name']} — {r['score']}% | {r['country']}")

    # Test 2 - paraphrased description (no explicit tool names)
    print("\n" + "="*60)
    print("TEST 2 - Paraphrased, no tool names (APT29 expected)")
    print("="*60)
    test2 = """
    A sophisticated nation-state actor sent targeted emails to 
    government ministry employees containing malicious attachments. 
    After execution credentials were harvested from memory and 
    the attacker moved laterally using stolen account details. 
    Data was collected from browsers and exfiltrated through 
    encrypted channels. The campaign focused on Eastern European 
    government organisations.
    """
    results2 = semantic_attribute(test2, model, embeddings, valid_profiles)
    print(f"\nTop 5 results:")
    for i, r in enumerate(results2, 1):
        print(f"#{i} {r['name']} — {r['score']}% | {r['country']}")

    # Test 3 - APT28 paraphrased
    print("\n" + "="*60)
    print("TEST 3 - Paraphrased APT28 description")
    print("="*60)
    test3 = """
    State sponsored actors sent targeted emails to defence 
    ministry officials containing weaponised documents. After 
    opening, a keylogger was installed and credentials stolen. 
    The group used these credentials to access additional systems 
    and collect sensitive documents. Infrastructure overlaps with 
    previous Russian military intelligence operations targeting 
    NATO member states.
    """
    results3 = semantic_attribute(test3, model, embeddings, valid_profiles)
    print(f"\nTop 5 results:")
    for i, r in enumerate(results3, 1):
        print(f"#{i} {r['name']} — {r['score']}% | {r['country']}")
