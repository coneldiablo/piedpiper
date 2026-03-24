from analyzer.evasion_detector import EvasionDetector


def test_evasion_detector_flags_vm_checks_and_timing():
    detector = EvasionDetector()
    api_calls = [
        {
            "api": "GetAdaptersInfo",
            "args": {},
            "timestamp": 1,
        },
        {
            "api": "RegOpenKeyExA",
            "args": {"lpSubKey": r"SOFTWARE\\Oracle\\VirtualBox"},
            "timestamp": 2,
        },
        {
            "api": "Sleep",
            "args": {"dwMilliseconds": 15000},
            "timestamp": 3,
        },
    ]

    report = detector.analyse(api_calls)

    assert report["score"] > 0
    assert any(item["type"] == "vm_api_call" for item in report["vm_checks"])
    assert any(item["type"] == "vm_registry_probe" for item in report["vm_checks"])
    assert any(item["type"] == "long_sleep" for item in report["timing_attacks"])
