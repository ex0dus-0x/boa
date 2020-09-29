"""
unpacker.py

    Defines a base class used by all packers in order to keep consistent
    across the API definitions, and implements a helper function to parse out the
    unpacker using Yara. This is still a WIP.

"""
import typing as t
import yara

from boa.unpack import pyinstaller, py2exe


class BaseUnpacker:
    """
    Defines a base unpacker class to inherit from for all variants of
    packers used for the Python executable distribution ecosystem.
    """

    def __init__(self, path: str):
        self.filepath = path

        # defines how many pyz files recovered
        self.pyz_len = 0

        # includes path to all bytecode files
        self.bytecode_paths = []

    def __str__(self):
        """ Defined for displaying purposes """
        raise NotImplementedError()

    def get_py_version(self):
        """ Implements functionality to parse out the Python interpreter version """
        raise NotImplementedError()

    def unpack(self, unpack_dir: str):
        """ Implements the actual process of unpacking PYZ archive files and resources """
        raise NotImplementedError()


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
    packer = None
    if matches[0].rule == "pyinstaller":
        packer = pyinstaller.PyInstaller(filepath)
    elif matches[0].rule == "py2exe":
        packer = py2exe.Py2exe(filepath)

    return packer
