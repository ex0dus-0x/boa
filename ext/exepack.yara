import "pe"

rule upx
{
    meta:
        description: "Detect UPX packing"

    strings:
        $a = "UPX0"
        $b = "UPX1"

    condition:
        $a or $b
}
