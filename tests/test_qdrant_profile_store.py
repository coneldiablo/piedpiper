import pytest

from services.qdrant_profile_store import QdrantProfileStore


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = str(self._payload)
        self.content = b"{}" if payload is not None else b""

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers=None, json=None, timeout=None, verify=None):
        self.calls.append({"method": method, "url": url, "json": json})
        if method == "GET" and url.endswith("/collections/test_profiles"):
            return FakeResponse(404, {"status": {"error": "not found"}})
        if method == "PUT" and url.endswith("/collections/test_profiles"):
            return FakeResponse(200, {"result": True})
        if method == "PUT" and "/points?wait=true" in url:
            return FakeResponse(200, {"result": {"status": "acknowledged"}})
        if method == "POST" and url.endswith("/points/search"):
            return FakeResponse(
                200,
                {
                    "result": [
                        {
                            "id": "point-1",
                            "score": 0.98,
                            "payload": {
                                "sample_id": "s1",
                                "family": "Downloader",
                                "quadrant": "Q1",
                                "feature_vector": [0.0, 1.0, 2.0],
                                "metadata": {"name": "sample1"},
                            },
                        }
                    ]
                },
            )
        raise AssertionError(f"Unexpected request: {method} {url}")


def test_qdrant_profile_store_upsert_and_search():
    session = FakeSession()
    store = QdrantProfileStore(
        endpoint="http://qdrant.local:6333",
        collection="test_profiles",
        enabled=True,
        verify_ssl=False,
        session=session,
    )

    inserted = store.upsert_profiles(
        [
            {
                "sample_id": "s1",
                "family": "Downloader",
                "cluster_label": 0,
                "quadrant": "Q1",
                "axis_x": 0.2,
                "axis_y": 0.5,
                "risk_score": 50,
                "ml_probability": 0.7,
                "suspicious_ratio": 0.4,
                "network_count": 2,
                "feature_vector": [0.0, 1.0, 2.0],
                "metadata": {"name": "sample1"},
            }
        ]
    )

    assert inserted == 1

    neighbours = store.find_neighbors([0.2, 1.1, 2.2], top_k=1)
    assert len(neighbours) == 1
    assert neighbours[0]["sample_id"] == "s1"
    assert neighbours[0]["manhattan_distance"] == pytest.approx(0.5)
    assert any(call["url"].endswith("/points/search") for call in session.calls)
