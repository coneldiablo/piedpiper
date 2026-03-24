from analyzer.dynamic_analysis import FRIDA_HOOK_CATALOG, _dynamic_analysis_stub


def test_frida_hook_catalog_meets_declared_threshold():
    assert len(FRIDA_HOOK_CATALOG) >= 50


def test_dynamic_stub_exposes_runtime_contract(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"demo")

    result = _dynamic_analysis_stub(str(sample), reason="unit_test")

    assert result["hook_catalog_size"] == len(FRIDA_HOOK_CATALOG)
    assert result["runtime_capabilities"]["reason"] == "unit_test"
    assert set(result["system_snapshots"]) == {"pre", "post", "diff"}
    assert isinstance(result["file_operations"], list)
    assert isinstance(result["registry_operations"], list)
    assert isinstance(result["timeline"], list)
