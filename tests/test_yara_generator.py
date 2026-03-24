from analyzer.yara_generator import YARAGenerator


def test_yara_generator_produces_rule():
    generator = YARAGenerator()
    analysis_data = {
        "static": {
            "file_size": 1024,
            "strings": ["http://malicious.example", "RunPowerShell"],
            "imports": ["kernel32!CreateRemoteThread"],
        },
        "dynamic": {
            "api_calls": [
                {"api": "CreateRemoteThread", "args": {}},
            ],
        },
        "iocs": [
            {"type": "domain", "value": "malicious.example"},
        ],
    }

    rule = generator.generate_rule_ml(analysis_data, "test_rule")

    assert rule.startswith("rule test_rule")
    assert "strings:" in rule
