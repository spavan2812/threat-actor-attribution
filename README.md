# TRACE: Threat Actor Recognition and Attribution through Contextual Evidence

MSc Applied Cybersecurity dissertation project (QUB, ELE8095). Full methodology and results are described in the dissertation; this README documents the reproducibility details referenced throughout the report as "recorded in the project repository."

## Repository structure

- `src/` — core production system (13 files): knowledge base construction, hybrid fusion engine, entity extraction, kill-chain sequencing, evaluation harness, and data pipelines.
- `validation/` — final scripts producing the results reported in the dissertation (16 files).
- `debug/` — diagnostic scripts, each tied to a specific finding or bug fix discussed in the dissertation (33 files).
- `data/` — knowledge base, evaluation results, and small result files. Large/third-party files are excluded (see below).

## Setup (Python 3.14.6)
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt --break-system-packages


## Knowledge base and ATT&CK snapshot

The knowledge base (`data/unified/knowledge_base.json`) merges MITRE ATT&CK, MISP Galaxy, and the ETDA Threat Group Encyclopaedia into 186 reconciled actor profiles.

- ATT&CK version: v19 (April 2026 update, introducing the Stealth/Defense Impairment tactic split)
- Retrieval date: [Fill in: exact date the snapshot was downloaded]

## Fusion configuration

The seven engine weights and exclusive-match bonus, fixed on the development set and held constant across all external evaluations:

```python
ENGINE_WEIGHTS = {
    'semantic': 0.65, 'keyword': 0.35, 'ioc': 0.30,
    'tool': 0.20, 'country': 0.15, 'sector': 0.10, 'motivation': 0.10
}
DIRECT_SIGNAL_BOOST = 0.25
```

Cross-encoder reranking (development-set comparison only): `cross-encoder/ms-marco-MiniLM-L-6-v2`, top 10 candidates, blend weight 0.3.

## Excluded from this repository

- `data/otx/ioc_actor_index.json` (~2GB) — exceeds GitLab's file size limit. `load_ioc_index()` in `hybrid_engine.py` degrades gracefully and returns `{}` if this file is absent, so the system still runs without the IoC engine's contribution. Rebuild via `python src/otx_pipeline.py` (requires an AlienVault OTX API key).
- `guru_dataset/`, `cti_bench_repo/`, `dataset/` — third-party datasets, not redistributed. See dissertation Section IV for how to obtain each (Guru et al.'s public GitHub repository; CTIBench's official release).

## Reproducing key results

- Development set + partial-input ablation: `python src/evaluation.py`
- CTIBench external validation: `python validation/evaluate_ctitaa.py`
- Matched Guru et al. comparison: `python validation/guru_matched_benchmark.py`
- Kill-chain sequencing (held-out + cross-source): `python validation/check_kill_chain_discrimination.py`, `python validation/check_kill_chain_cross_source.py`
- Selective-prediction risk-coverage curve: `python validation/check_risk_coverage_curve.py`