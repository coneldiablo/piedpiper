from analyzer.ioc_extractor import IocExtractor


def test_bitcoin_address_detection():
    extractor = IocExtractor()

    sample_strings = [
        "Ransom note: send BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh immediately."
    ]

    extractor._find_iocs_in_strings(sample_strings, "unit:test:note")

    btc_iocs = [ioc for ioc in extractor.found_iocs if ioc["type"] == "btc_address"]
    assert btc_iocs, "Expected at least one Bitcoin address IoC"
    assert btc_iocs[0]["value"].startswith("bc1q")
    assert btc_iocs[0]["source"] == "unit:test:note"


def test_mutex_detection_from_api_call():
    extractor = IocExtractor()
    mutex_value = "Global\\\\{12345678-1234-1234-1234-1234567890AB}"

    extractor._process_api_call(
        {
            "pid": 1337,
            "api": "CreateMutexW",
            "args": {
                "lpName": mutex_value,
            },
        }
    )

    mutex_iocs = [ioc for ioc in extractor.found_iocs if ioc["type"] == "mutex"]
    assert mutex_iocs, "Expected mutex IoC extracted from CreateMutexW call"
    assert any(mutex_value in entry["value"] for entry in mutex_iocs)
