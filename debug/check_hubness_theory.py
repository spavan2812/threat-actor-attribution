import json, torch
import torch.nn.functional as F
import statistics

data = torch.load("data/unified/actor_embeddings.pt")
emb = data["embeddings"]
names = data["actor_names"]
if not torch.is_tensor(emb):
    emb = torch.tensor(emb)

emb_norm = F.normalize(emb, dim=1)
sim_matrix = emb_norm @ emb_norm.T
n = len(names)
avg_sim = (sim_matrix.sum(dim=1) - 1.0) / (n - 1)

centroid = emb_norm.mean(dim=0)
centroid_norm = F.normalize(centroid, dim=0)
dist_to_centroid = emb_norm @ centroid_norm

sims = avg_sim.tolist()
dists = dist_to_centroid.tolist()
mean_s, mean_d = statistics.mean(sims), statistics.mean(dists)
cov = sum((s - mean_s) * (d - mean_d) for s, d in zip(sims, dists)) / len(sims)
std_s, std_d = statistics.pstdev(sims), statistics.pstdev(dists)
corr = cov / (std_s * std_d)

print("Correlation between hub-ness (avg_sim) and closeness to centroid:", corr)
print()
print("Overall mean avg_sim:", mean_s)
print("Overall std avg_sim:", std_s)
print()
pairs = list(zip(names, sims))
pairs.sort(key=lambda x: -x[1])
print("Top 10 highest average-similarity actors (potential hubs):")
for name, s in pairs[:10]:
    print(f"  {name:<20} avg_sim={s:.4f}")
