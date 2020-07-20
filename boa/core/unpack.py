"""
unpacker.py
"""
import yara
import pefile
import unpy2exe

def is_py2exe(binary, rule_path="rules/py2exe.yar"):
    """
    Uses a YARA-based check to determine if the file is compiled with Py2Exe
    """
    with open(rule_path, "r") as fd:
        content = fd.read()

    # compile the rule and check for a match
    rule = yara.compile(source=content)
    if len(rule.match(data=binary)) != 0:
        return True

    return False


def is_pyinstaller(binary, rule_path="rules/pyinstaller.yar"):
    """
    Uses a YARA-based check to determien if the fiel is compiled with PyInstaller
    """
    with open(rule_path, "r") as fd:
        content = fd.read()

    # compile the rule and check for a match
    rule = yara.compile(source=content)
    if len(rule.match(data=binary)) != 0:
        return True

    return False
