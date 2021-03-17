import "pe"

rule py2exe
{
  meta:
        author = "Didier Stevens"
        description = "Detect PE file produced by py2exe"
  condition:
        for any i in (0 .. pe.number_of_resources - 1):
          (pe.resources[i].type_string == "P\x00Y\x00T\x00H\x00O\x00N\x00S\x00C\x00R\x00I\x00P\x00T\x00")
}

rule pyinstaller
{
    meta:
        description = "Detect any binary file produced by pyinstaller"
    strings:
        $a = "pyi-windows-manifest-filename"
        $b = "pyi_carchive"
        $c = "pyi_bootstrap"
        $d = "spyiboot01_bootstrap"
    condition:
        any of them
}

rule cxfreeze
{
    meta:
        author = "ex0dus"
        description = "Detect any binary file produced by cxfreeze"
    strings:
        $a = "cx_Freeze" // TODO
    condition:
        $a
}
