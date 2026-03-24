import math

import pytest

from analyzer.clustering import MalwareClustering


@pytest.fixture
def sample_dataset():
    return [
        {
            "id": "s1",
            "dynamic": {
                "api_calls": [{"api": "CreateFileW"}, {"api": "WriteFile"}],
                "network": [{"remote_ip": "1.2.3.4", "remote_port": 80}],
                "behavioral_patterns": [{"pattern": "Downloader"}],
            },
            "iocs": [{"type": "domain", "value": "bad.com"}],
            "risk": {"score": 45, "ml_probability": 0.6},
            "family": "Downloader",
        },
        {
            "id": "s2",
            "dynamic": {
                "api_calls": [{"api": "CreateRemoteThread"}, {"api": "VirtualAllocEx"}],
                "network": [{"remote_ip": "5.6.7.8", "remote_port": 4444}],
                "behavioral_patterns": [{"pattern": "Injection"}],
            },
            "iocs": [{"type": "ip", "value": "5.6.7.8"}],
            "risk": {"score": 80, "ml_probability": 0.9},
            "family": "Injector",
        },
        {
            "id": "s3",
            "dynamic": {
                "api_calls": [{"api": "RegOpenKeyExW"}],
                "network": [],
                "behavioral_patterns": [],
            },
            "iocs": [],
            "risk": {"score": 15, "ml_probability": 0.1},
            "family": "Benign",
        },
    ]


def test_cluster_by_behavior_returns_enriched_summary(sample_dataset):
    clusterer = MalwareClustering(eps=0.9, min_samples=1)
    summary = clusterer.cluster_by_behavior(sample_dataset)

    assert "clusters" in summary
    assert len(summary["clusters"]) == 3
    first_cluster = summary["clusters"][0]
    assert "summary" in first_cluster
    assert first_cluster["summary"]["top_apis"]
    assert isinstance(first_cluster["centroid"], list)

    family_hint = clusterer.identify_family(sample_dataset[0])
    assert family_hint["label"] == 0
    assert math.isfinite(family_hint["similarity"])


def test_build_and_use_family_profiles(sample_dataset):
    clusterer = MalwareClustering()
    profiles = clusterer.build_family_profiles(sample_dataset, family_key="family")

    assert set(profiles.keys()) == {"Downloader", "Injector", "Benign"}
    assert profiles["Downloader"]["size"] == 1

    result = clusterer.identify_family_from_profiles(sample_dataset[0], profiles, top_k=3)
    assert result["family"] == "Downloader"
    assert result["candidates"][0]["family"] == "Downloader"


def test_similarity_projection_and_manhattan_neighbours(sample_dataset):
    clusterer = MalwareClustering(eps=0.9, min_samples=1)
    clusterer.cluster_by_behavior(sample_dataset)

    projection = clusterer.describe_sample_projection(sample_dataset[0])
    assert projection["quadrant"].startswith("Q")
    assert "quadrant_label" in projection

    neighbours = clusterer.get_nearest_neighbors(sample_dataset[0], top_k=2)
    assert len(neighbours) == 2
    assert neighbours[0]["id"] == "s1"
    assert neighbours[0]["manhattan_distance"] <= neighbours[1]["manhattan_distance"]
