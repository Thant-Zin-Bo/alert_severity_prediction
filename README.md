# alert_severity_prediction
Predicting the Severity of the alert from feature extracting from Alert description 
Table of Contents

Features

Repository Layout

Quick Start

Data Contracts

Pipelines

1) Extraction – extract_hybrid.py

2) Pseudonymization – pseudonymize.py

3) EDA – eda_alerts.py (example name)

4) Modeling – TF-IDF+LogReg and DistilBERT

Evaluation & Outputs

Configuration

CLI Examples

Troubleshooting

Roadmap

Contributing

License

Features

Hybrid entity extraction

Deterministic regex rules for high-precision patterns.

Lightweight no-label “NER” pass to catch variants regex misses.

A cue mechanism to bias/guide extraction in ambiguous text.

Pseudonymization with dictionaries

Consistent replacements for component type, name, and test.

Report + dictionaries saved to disk for auditing & reproducibility.

UTF-7 clean-up (optional)

Static UTF-7 decode map (e.g., +AF8- → _) to normalize noisy inputs.

Two modeling tracks

CPU-optimized TF-IDF + Logistic Regression (fast, interpretable).

DistilBERT classifier (optional; stronger with GPU/fine-tuning).

Balanced evaluation

Accuracy, micro-F1, micro-precision/recall, confusion matrix & curves.

Batteries-included artifacts

Clean CSVs, dictionaries, metrics JSON, confusion matrix PNG/CSV, curves, and label map.

Repository Layout (to be updated)


Quick Start
1) Environment
# Python 3.10–3.12 recommended
python -m venv .venv
source .venv/bin/activate        # (Windows) .venv\Scripts\activate

pip install -r requirements.txt


Core deps: pandas, numpy, scikit-learn, matplotlib, transformers (if using DistilBERT).

If you prefer notebooks, you can run a local Jupyter server. For Docker users, mount your project folder and expose port 8888.

2) Input data

Drop a CSV of raw alerts in data/raw/ (or use data/sample/samplealert.csv).
Minimum column expected: a free-text description (e.g., Description).

Data Contracts
Raw alerts (input)

Required

Description (str): the alert text blob.

Optional (used if available)

Start_Time, Duration, Priority (any case; parser is tolerant)

Other metadata columns are passed through.

Extracted alerts (intermediate: alerts_with_fields_hybrid.csv)

Adds normalized entity columns:

Component_Type, Component_Name, Test

Normalized/derived fields for:

Start_Time_norm, Duration_min, Priority_Level (if inferrable)

Pseudonymized alerts (final: alerts_pseudo.csv)

Same schema as extracted, but with sensitive entity values replaced by stable pseudonyms.

Dictionaries are saved for reproducibility.

Pipelines
1) Extraction – extract_hybrid.py

Goal: From raw Description, extract Component_Type, Component_Name, Test and normalize time/priority.

How it works

Regex rules: high-precision patterns for known formats.

Cue-guided logic: helper keywords/anchors that strengthen or weaken a match in ambiguous contexts.

No-label NER pass: when regex is uncertain or fails, a lightweight NER heuristic proposes entities (trained heuristics or rules; no external labels required).

Chooser: for each field, select regex if it’s strong; otherwise fall back to NER.

Preprocessing:

Parse Start_Time to a uniform Start_Time_norm

Convert durations to minutes Duration_min

Map/normalize priority into Priority_Level

Output: out/alerts_with_fields_hybrid.csv (no dedup; every alert kept).

2) Pseudonymization – pseudonymize.py

Goal: Replace sensitive entity values with consistent pseudonyms.

Why extract “again”?
It doesn’t. Pseudonymization uses the already-extracted columns. It:

Builds/updates three dictionaries:

Component type, Component name, Test

Applies replacements to create stable pseudonyms.

Writes:

out/alerts_pseudo.csv

out/pseudo_dictionaries.json

per-entity CSVs with counts (e.g., dict_component_type.csv)

Notes

Handles odd encodings (optional UTF-7 clean-up such as +AF8- → _).

“Brace” in your comments refers to literal {/} characters in text—not an entity. They’re cleaned/escaped during parsing.

3) EDA – eda_alerts.py (example name)

Fast sanity checks & visuals:

Class/priority distributions

Missingness overview

Basic text stats (lengths, tokenization)

Correlations & skew

Outputs go to out/ (PNGs/CSVs).

4) Modeling – TF-IDF+LogReg and DistilBERT
A) TF-IDF + Logistic Regression (CPU-friendly)

Reads out/alerts_pseudo.csv

70/15/15 stratified split (train/val/test)

Deterministic label encoding

class_weight='balanced' for imbalance

Hyperparam sweep on C (select by macro-F1 on val)

Saves to out/:

metrics.json, confusion_matrix.csv/.png, curves.png, label_map.json

Run:

python scripts/train_logreg_text.py

B) DistilBERT (optional; fine-tune recommended)

Uses transformers pipeline and similar data split

Expect warnings if you haven’t fine-tuned yet:

“Some weights … newly initialized… You should probably TRAIN this model…”

Run:

python scripts/train_distilbert.py

Evaluation & Outputs

Metrics: Accuracy, micro-F1, micro-precision, micro-recall (plus macro-F1 for model selection).

Artifacts:

out/metrics.json

out/confusion_matrix.png and .csv

out/curves.png (e.g., PR/ROC by class where applicable)

out/label_map.json (id ↔ label)

Why micro-F1? It aggregates contributions of all classes to compute the average F1—ideal when class sizes are imbalanced and you care about overall correctness across all alerts.

Configuration

Common flags (check each script’s argparse for full list):

--in_csv / --out_csv

--text_col (default: Description)

--seed (deterministic splits)

--val_size, --test_size

--max_features (TF-IDF)

--C / --C_grid (LogReg)

--model_name (DistilBERT variant)

Environment tips:

Windows + Matplotlib: ensure a compatible backend; our training script sets Agg for headless image export.

For Jupyter in Docker, pass env vars properly (avoid quoting issues like -e JUPYTER_PASSWORD="p"SSW0RD123").

CLI Examples

1) Extract hybrid fields

python scripts/extract_hybrid.py \
  --in_csv data/raw/alerts.csv \
  --out_csv out/alerts_with_fields_hybrid.csv


2) Pseudonymize

python scripts/pseudonymize.py \
  --in_csv out/alerts_with_fields_hybrid.csv \
  --out_csv out/alerts_pseudo.csv


3) EDA

python scripts/eda_alerts.py \
  --in_csv out/alerts_pseudo.csv \
  --out_dir out/


4) Train (TF-IDF + LogReg)

python scripts/train_logreg_text.py \
  --in_csv out/alerts_pseudo.csv \
  --val_size 0.15 --test_size 0.15 --seed 42


5) Train (DistilBERT)

python scripts/train_distilbert.py \
  --in_csv out/alerts_pseudo.csv \
  --model_name distilbert-base-uncased \
  --epochs 3 --batch_size 16

Troubleshooting

Matplotlib import errors on Windows
Use Python 3.10–3.11 if 3.12 gives issues with local binaries, or keep matplotlib pinned to a compatible version in requirements.txt. Our scripts set matplotlib.use("Agg") for PNG export without GUI.

“Weights … newly initialized” (Transformers)
This is expected before fine-tuning. Train for a few epochs on your labeled dataset before using in production.

Docker + Jupyter
Ensure the env file exists and quoting is correct:

docker run -d --name jupyter \
  -p 127.0.0.1:8888:8888 \
  -v /ABSOLUTE/PATH/Projects:/home/jovyan/work \
  --env-file .env \
  jupyter/datascience-notebook


If you don’t need auth during local testing, drop the security flags entirely.

Roadmap

 Add active learning loop for entity review (“entity review file” to confirm/curate extractions).

 Expand cue library and make it project-configurable.

 Export feature importance (LogReg) and error analysis notebooks.

 Add lightweight REST API for scoring new alerts.

 Structured benchmark harness with fixed seeds and data snapshots.

Contributing

Issues and PRs are welcome—especially for new regex patterns, cue sets, or small-footprint NER heuristics. Please include:

A failing example,

A minimal fix/test,

Notes on expected side-effects.
