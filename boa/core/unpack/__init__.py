"""
__init__.py

    Defines a base class used by all unpackers in order to keep consistent
    across the API definitions, and implements a helper function to parse out the
    unpacker using Yara.
"""
import os
import typing as t

import pefile
import yara

from . import pyinstaller, py2exe


class BaseUnpacker:
    """ Base class used for all variants of Python unpacker implementations. """

    def __init__(self, path: str):

        # get file pointer and size for later reading and seeking
        self.file: t.Any = open(path, "rb")
        self.size: int = os.stat(path).st_size

        # Python version used to compile the binary
        self.pyver: str = self.parse_pyver()

        # Installer-specific version
        self.packer_ver: str = self.parse_packer_ver()

        # stores paths to all unpacked bytecode files
        self.bytecode_paths: t.List[str] = []

    def __enter__(self):
        return self

    def __exit__(self):
        """ Destructor - close file descriptor to executable """
        self.file.close()

    def __str__(self) -> str:
        """ Output for identifying packer used """
        raise NotImplementedError()

    def parse_pyver(self) -> str:
        """ Setter used to parse out Python interpreter version """
        raise NotImplementedError()
    
    def parse_packer_ver(self) -> str:
        """ Setter used to parse out installer version """
        raise NotImplementedError()

    def unpack(self, unpack_dir: str):
        """ Implements the actual process of unpacking resources """
        raise NotImplementedError()


class WindowsUnpacker(BaseUnpacker):
    """ Base class used for all Windows PE unpackers """

    def __init__(self, path):
        """ Initializes a PE file object for interaction """
        self.pe = pefile.PE(path)
        super().__init__()


    def parse_pyver(self) -> str:
        """ Parse .rsrc and detect PYTHON*.dll dependency, and parse out version """
        pyver = None
        for rsrc_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if rsrc_type.name is not None:
                data = rsrc_type.name.string

                # check if PYTHON*.dll exists as a dep and
                if data[0:6] == b"PYTHON" and data[8:] == b".DLL":
                    pyver = data[6] - 0x30 + (data[7] - 0x30) / 10.0
                    break

        return pyver


class MacosUnpacker(BaseUnpacker):
    pass


class LinuxUnpacker(BaseUnpacker):
    pass



def get_packer(filepath: str) -> t.Optional[t.Any]:
    """
    Helper utility to help return the correct Unpacker based on the YARA rule that matches it.
    If `detect_only` is set, return only the 
    """
    rules = yara.compile(filepath="ext/unpacker.yara")
    matches = rules.match(filepath=filepath)

    # if multiple are present, return None
    if len(matches) > 1:
        return None

    # parse response from rule
    res = matches[0].rule

    # determine which packer was used
    packer = None
    if res == "pyinstaller":
        packer = pyinstaller.PyInstaller(filepath)
    elif res == "py2exe":
        packer = py2exe.Py2exe(filepath)
    elif res == "cx_freeze":
        raise NotImplementedError()

    return packer
