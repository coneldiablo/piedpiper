rule OfficeOOXMLMacroArtifact
{
    meta:
        author = "Pied Piper"
        description = "Detects OOXML macro storage and suspicious template relations"
    strings:
        $macro = "vbaProject.bin" ascii nocase
        $tpl = "attachedTemplate" ascii nocase
        $ole = "oleObject" ascii nocase
    condition:
        any of them
}
