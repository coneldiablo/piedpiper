import os
import pytest

import api.server as server_module


class DummyClustering:
    def __init__(self, *args, **kwargs):
        pass

    def cluster_by_behavior(self, samples):
        return {"labels": [0 for _ in samples], "clusters": {0: {"size": len(samples), "sample_ids": [s.get("id", idx) for idx, s in enumerate(samples)]}}, "noise": 0}

    def identify_family(self, sample):
        return {
            "label": 0,
            "similarity": 0.99,
            "distance": 0.1,
            "manhattan_distance": 0.2,
            "quadrant": "Q1",
            "behavioral_plane": {"quadrant": "Q1", "quadrant_label": "Execution & Propagation", "x": 0.1, "y": 0.2},
        }

    def get_nearest_neighbors(self, sample, *, top_k=5):
        return [{"id": sample.get("id", "sample"), "manhattan_distance": 0.0, "quadrant": "Q1"}][:top_k]

    def describe_sample_projection(self, sample, *, use_family_origin=False):
        return {"quadrant": "Q1", "quadrant_label": "Execution & Propagation", "x": 0.1, "y": 0.2}

    def build_family_profiles(self, dataset, family_key="family"):
        return {"DemoFamily": {"size": len(dataset), "summary": {"avg_risk": 50.0}, "plane_centroid": {"x": 0.1, "y": 0.2}}}

    def identify_family_from_profiles(self, sample, profiles=None, *, top_k=3):
        return {
            "family": "DemoFamily",
            "similarity": 0.95,
            "distance": 0.15,
            "manhattan_distance": 0.25,
            "quadrant": "Q1",
            "behavioral_plane": {"quadrant": "Q1", "quadrant_label": "Execution & Propagation", "x": 0.1, "y": 0.2},
            "candidates": [{"family": "DemoFamily", "similarity": 0.95, "distance": 0.15, "manhattan_distance": 0.25, "size": 2}],
        }

    def persist_similarity_profiles(self, store_path=None):
        return 2

    def get_persistence_status(self):
        return {
            "profiles": 2,
            "sqlite": {"enabled": True, "stored": 2, "path": "./data/ml_profiles.db"},
            "qdrant": {"enabled": False, "configured": False, "stored": 0},
        }

    def get_scaled_feature_vector(self, sample):
        return [0.1, 0.2, 0.3]


class DummyYARAGenerator:
    def generate_rule_ml(self, analysis_data, rule_name):
        return f"rule {rule_name} {{\n    strings:\n        $a = \"dummy\"\n    condition:\n        $a\n}}"


class DummyMLProfileStore:
    def __init__(self, db_path=None):
        self.db_path = db_path

    def find_neighbors(self, feature_vector, *, top_k=5, family=None, quadrant=None):
        return [{"sample_id": "persisted-1", "manhattan_distance": 0.1, "quadrant": "Q1"}][:top_k]


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setattr(server_module, "MalwareClustering", DummyClustering)
    monkeypatch.setattr(server_module, "YARAGenerator", lambda: DummyYARAGenerator())
    monkeypatch.setattr(server_module, "MLProfileStore", DummyMLProfileStore)
    monkeypatch.setattr(
        server_module,
        "train_model",
        lambda sample_count=1000, dataset_path=None: {
            "sample_count": sample_count,
            "data_source": dataset_path or "synthetic_only",
            "auc": 0.99,
        },
    )
    return server_module.create_app()


@pytest.fixture
def secured_app(monkeypatch):
    monkeypatch.setattr(server_module, "MalwareClustering", DummyClustering)
    monkeypatch.setattr(server_module, "YARAGenerator", lambda: DummyYARAGenerator())
    monkeypatch.setattr(server_module, "_run_analysis_job", lambda job_id, payload: None)

    config_mgr = server_module.config_manager
    settings = config_mgr.settings
    sentinel = object()

    original_users = settings.get("API_AUTH_USERS", sentinel)
    original_secret = settings.get("API_JWT_SECRET", sentinel)
    original_rate = settings.get("API_RATE_LIMIT_ANALYZE", sentinel)

    config_mgr.set("API_AUTH_USERS", {"tester": "secret"})
    config_mgr.set("API_JWT_SECRET", "test-secret")
    config_mgr.set("API_RATE_LIMIT_ANALYZE", "3 per minute")

    app = server_module.create_app()
    app.config["TESTING"] = True

    yield app

    def _restore(key, original):
        if original is sentinel:
            settings.pop(key, None)
        else:
            config_mgr.set(key, original)

    _restore("API_AUTH_USERS", original_users)
    _restore("API_JWT_SECRET", original_secret)
    _restore("API_RATE_LIMIT_ANALYZE", original_rate)


def test_hunt_endpoint(app):
    client = app.test_client()
    payload = {
        "query": "SELECT * FROM api_calls WHERE api LIKE '%Write%'",
        "dataset": {"api_calls": [{"api": "WriteFile"}, {"api": "CreateRemoteThread"}]},
    }
    response = client.post("/api/hunt", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["results"][0]["api"] == "WriteFile"


def test_cluster_endpoint(app):
    client = app.test_client()
    payload = {"samples": [{"id": "sample1"}, {"id": "sample2"}]}
    response = client.post("/api/cluster", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["clusters"][0]["size"] == 2


def test_yara_endpoint(app):
    client = app.test_client()
    payload = {
        "analysis_data": {"static": {"strings": ["abc"]}, "dynamic": {}, "iocs": []},
        "rule_name": "test_rule",
    }
    response = client.post("/api/yara", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["rule_name"] == "test_rule"
    assert data["rule"].startswith("rule test_rule")


def test_ml_train_endpoint(app):
    client = app.test_client()
    response = client.post("/api/ml/train", json={"samples": 500})
    assert response.status_code == 200
    data = response.get_json()
    assert data["sample_count"] == 500
    assert data["auc"] == 0.99


def test_ml_similarity_endpoint(app):
    client = app.test_client()
    payload = {
        "dataset": [
            {"id": "sample1", "family": "DemoFamily"},
            {"id": "sample2", "family": "DemoFamily"},
        ],
        "sample": {"id": "query_sample"},
        "top_k": 3,
        "persist_store": True,
    }
    response = client.post("/api/ml/similarity", json=payload)
    assert response.status_code == 200
    data = response.get_json()
    assert data["sample_projection"]["quadrant"] == "Q1"
    assert data["cluster_match"]["manhattan_distance"] == 0.2
    assert data["family_match"]["family"] == "DemoFamily"
    assert data["persisted_profiles"] == 2
    assert data["store_neighbors"][0]["sample_id"] == "persisted-1"
    assert data["vector_store"]["backend"] == "sqlite"


def test_analyze_requires_auth_and_rate_limit(secured_app):
    client = secured_app.test_client()
    payload = {"file": os.path.abspath(__file__), "dynamic": False}

    unauthorized = client.post("/api/analyze", json=payload)
    assert unauthorized.status_code == 401

    login = client.post("/api/auth/login", json={"username": "tester", "password": "secret"})
    assert login.status_code == 200
    token = login.get_json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}

    first = client.post("/api/analyze", headers=headers, json=payload)
    second = client.post("/api/analyze", headers=headers, json=payload)
    third = client.post("/api/analyze", headers=headers, json=payload)

    assert first.status_code == 202
    assert second.status_code == 202
    assert third.status_code == 429
