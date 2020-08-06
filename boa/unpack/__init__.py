"""
unpacker.py
"""
import typing as t
import yara

from . import pyinstaller, py2exe


def get_packer(filepath: str) -> t.Optional[t.Any]:
    """
    Helper utility to help return the correct Unpacker based on the YARA rule that
    matches it.
    """
    rules = yara.compile(filepath="ext/unpacker.yara")
    matches = rules.match(filepath=filepath)

    # if both are present, return None
    if len(matches) > 1:
        return None

    # determine which packer was used
    if matches[0].rule == "pyinstaller":
        return pyinstaller.PyInstaller(filepath)
    elif matches[0].rule == "py2exe":
        return py2exe.Py2exe(filepath)
    else:
        return None
