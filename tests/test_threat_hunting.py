from analyzer.threat_hunting import ThreatHuntingEngine


def test_threat_hunting_simple_like_query():
    dataset = {
        "api_calls": [
            {"api": "CreateRemoteThread", "args": {"pid": 1234}},
            {"api": "WriteFile", "args": {"pid": 4321}},
        ]
    }

    engine = ThreatHuntingEngine(dataset, context={"pid": 4321})
    query = "SELECT * FROM api_calls WHERE api LIKE '%Thread%' AND args.pid != self.pid"
    results = engine.execute_query(query)

    assert len(results) == 1
    assert results[0]["api"] == "CreateRemoteThread"
