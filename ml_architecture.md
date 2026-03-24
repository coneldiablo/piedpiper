# Pied Piper ML Architecture

## Overview

Pied Piper uses a hybrid ML architecture with two complementary layers:

1. `Supervised classification`
   - Implemented in `analyzer/ml_detector.py` and `scripts/train_model.py`
   - Builds a fixed-length feature vector (`100` features)
   - Trains a `LogisticRegression` classifier with `StandardScaler`
   - Produces `ml_probability`, which is injected into the risk scoring pipeline

2. `Unsupervised similarity analysis`
   - Implemented in `analyzer/clustering.py`
   - Uses `DBSCAN` for behaviour-based grouping
   - Projects each sample into a 2D behavioural plane
   - Assigns every sample to a behavioural quadrant
   - Uses `Manhattan distance` in scaled feature space to find nearest neighbours
   - Can persist indexed profiles into SQLite via `services/ml_profile_store.py`

## Supervised Layer

### Input

The classifier consumes features extracted from:

- static analysis
- dynamic analysis
- IoCs

### Feature groups

The vector includes:

- file size
- entropy indicators
- suspicious imports
- API-call categories
- IoC density

### Training

Training entrypoint:

```powershell
.\.venv\Scripts\python.exe scripts\train_model.py --samples 1000
```

Training behaviour:

- if a labelled dataset exists, it is used
- if labelled data is insufficient, synthetic top-up is added
- if no dataset exists, the model is trained on a synthetic dataset

### Output

Artifacts:

- `models/malware_model.pkl`
- `models/malware_model_metrics.json`

The resulting probability is fed into:

- `analyzer/scoring.py`
- GUI risk display
- report generation

## Unsupervised Layer

### Why it exists

This layer is used when we want to compare malware behaviour without requiring trusted labels.

That means:

- the algorithm does not need to know the malware family in advance
- it works on behavioural similarity
- it can be used for grouping, nearest-neighbour search and family approximation

### Behavioural plane

Each sample is projected into a 2D plane:

- `X-axis`: execution risk and maliciousness
  - suspicious API ratio
  - supervised ML probability
  - risk score
- `Y-axis`: propagation and external activity
  - network activity
  - IoC density
  - behavioural pattern count
  - API-call volume
  - entropy contribution

The dataset median becomes the origin of the plane.

### Quadrants

After centering around the median origin, each sample is assigned to one of four quadrants:

- `Q1`: Execution & Propagation
- `Q2`: Propagation-Dominant
- `Q3`: Dormant / Low-Activity
- `Q4`: Execution-Dominant

This gives an interpretable behavioural segmentation for presentation and analyst triage.

### Manhattan distance

Nearest-neighbour search uses `Manhattan distance` over the scaled behavioural feature vector.

Why Manhattan distance is useful here:

- robust for sparse behavioural vectors
- interpretable as total absolute deviation between malware profiles
- works well when features represent counts, presences and discrete behavioural indicators

In the project it is used for:

- nearest sample lookup
- family profile comparison
- similarity search in the SQLite profile store

## Profile Store

Persistent storage is implemented in:

- `services/ml_profile_store.py`

Storage backend:

- `SQLite`

Default path:

- `./data/ml_profiles.db`

Each stored profile contains:

- sample id
- family label if available
- cluster label
- quadrant
- 2D behavioural coordinates
- scaled feature vector
- risk and ML metadata

This allows the system to accumulate a local behavioural knowledge base.

## API Support

ML-specific API endpoints:

- `POST /api/ml/train`
- `POST /api/ml/similarity`

Swagger:

- `http://127.0.0.1:8080/api/docs`

## Presentation-ready statement

You can describe the ML subsystem like this:

> Pied Piper uses a hybrid ML architecture. The supervised layer estimates the probability of maliciousness from static, dynamic and IoC features. The unsupervised layer clusters behavioural profiles, projects them onto a 2D quadrant model and compares samples using Manhattan distance. This allows both probability-based scoring and label-independent malware similarity analysis.
