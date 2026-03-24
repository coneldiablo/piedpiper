from services.ml_profile_store import MLProfileStore


def test_ml_profile_store_upsert_and_manhattan_lookup(tmp_path):
    db_path = tmp_path / "profiles.db"
    store = MLProfileStore(db_path=str(db_path))

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
            },
            {
                "sample_id": "s2",
                "family": "Injector",
                "cluster_label": 1,
                "quadrant": "Q4",
                "axis_x": 0.8,
                "axis_y": -0.2,
                "risk_score": 90,
                "ml_probability": 0.95,
                "suspicious_ratio": 0.9,
                "network_count": 1,
                "feature_vector": [5.0, 5.0, 5.0],
                "metadata": {"name": "sample2"},
            },
        ]
    )

    assert inserted == 2

    profiles = store.fetch_profiles(limit=10)
    assert len(profiles) == 2

    neighbours = store.find_neighbors([0.2, 1.1, 2.2], top_k=1)
    assert len(neighbours) == 1
    assert neighbours[0]["sample_id"] == "s1"
