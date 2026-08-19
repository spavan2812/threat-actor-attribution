import json, torch
import torch.nn.functional as F

kb = json.load(open("data/unified/knowledge_base.json"))
data = torch.load("data/unified/actor_embeddings.pt")
emb = data["embeddings"]
names = data["actor_names"]
if not torch.is_tensor(emb):
    emb = torch.tensor(emb)

emb_norm = F.normalize(emb, dim=1)
sim_matrix = emb_norm @ emb_norm.T
n = len(names)
avg_sim = (sim_matrix.sum(dim=1) - 1.0) / (n - 1)

desc_by_name = {a["name"]: a.get("description", "") for a in kb}

targets = ["Earth Lusca", "FIN8", "TA505", "BlackTech", "Naikon"]
for t in targets:
    if t in names:
        idx = names.index(t)
        desc = desc_by_name.get(t, "")
        print(f"{t:<15} avg_sim={avg_sim[idx].item():.4f}  desc_len={len(desc)}")
        print(f"  first 200 chars: {desc[:200]}")
        print()

print("Overall mean avg_sim:", avg_sim.mean().item())
