"""
__init__.py

    Defines a base class used by all unpackers in order to keep consistent
    across the API definitions, and implements a helper function to parse out the
    unpacker using Yara.
"""
import os
import traceback
import typing as t

import yara
import lief


class UnpackException(Exception):
    pass


class BaseUnpacker:
    """ Base class used for all variants of Python unpacker implementations. """

    def __init__(self, path: str):

        # get file pointer and size for later reading and seeking
        self.file: t.Any = open(path, "rb")
        self.size: int = os.stat(path).st_size

        # stores object with arbitrary binary format
        self.binary: t.Any = lief.parse(path)

        # Python version used to compile the binary
        self.pyver: t.Optional[float] = None

        # Installer-specific version
        self.packer_ver: t.Optional[float] = None

        # stores paths to all unpacked bytecode files
        self.bytecode_paths: t.List[str] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """ Destructor - handle exceptions and close file """
        if exc_type is not None:
            traceback.print_exception(exc_type, exc_value, tb)
        self.file.close()

    def __str__(self) -> str:
        """ Output for identifying packer used """
        raise NotImplementedError()

    def parse_pyver(self) -> t.Optional[float]:
        """ Setter used to parse out Python interpreter version """
        raise NotImplementedError()

    def parse_packer_ver(self) -> t.Optional[float]:
        """ Setter used to parse out installer version """
        raise NotImplementedError()

    def unpack(self, unpack_dir: str):
        """ Implements the actual process of unpacking resources """
        raise NotImplementedError()


def get_packer(filepath: str) -> t.Optional[BaseUnpacker]:
    """
    Helper utility to help return the correct Unpacker based on the YARA rule that matches it.
    """
    from . import pyinstaller, py2exe

    rules = yara.compile(filepath="rules/installer.yara")
    matches = rules.match(filepath=filepath)

    # if multiple are present, return None
    if len(matches) > 1:
        return None

    # parse response from rule, return now, if `detect_only` is set
    res: str = matches[0].rule

    # determine which packer was used
    packer: t.Optional[BaseUnpacker] = None
    if res == "pyinstaller":
        packer = pyinstaller.PyInstaller(filepath)
    elif res == "py2exe":
        packer = py2exe.Py2Exe(filepath)
    elif res == "cxfreeze":
        packer = cxfreeze.CxFreeze(filepath)

    return packer
