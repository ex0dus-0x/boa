"""
__init__.py

    Defines a base class used by all unpackers in order to keep consistent
    across the API definitions, and implements a helper function to parse out the
    unpacker using Yara.
"""
import os
import mmap
import typing as t

import pefile
import yara

class UnpackException(Exception):
    pass


class BaseUnpacker:
    """ Base class used for all variants of Python unpacker implementations. """

    def __init__(self, path: str):

        # get file pointer and size for later reading and seeking
        self.file: t.Any = open(path, "rb")
        self.size: int = os.stat(path).st_size

        # stores object with binary format
        self.binary: t.Optional[t.Any] = None

        # Python version used to compile the binary
        self.pyver: t.Optional[str] = None

        # Installer-specific version
        self.packer_ver: t.Optional[str] = None

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

    def parse_pyver(self) -> t.Optional[str]:
        """ Setter used to parse out Python interpreter version """
        raise NotImplementedError()
    
    def parse_packer_ver(self) -> str:
        """ Setter used to parse out installer version """
        raise NotImplementedError()

    def unpack(self, unpack_dir: str):
        """ Implements the actual process of unpacking resources """

        # first, fingerprint the executable's Python and installer version
        self.pyver = self.parse_pyver()
        if self.pyver is None:
            raise UnpackerException("Cannot parse out Python version from executable.")

        self.packer_ver = self.parse_packer_ver()
        if self.packer_ver is None:
            raise UnpackerException("Cannot parse out packer version from executable.")


class WindowsUnpacker(BaseUnpacker):
    """ Base class used for all Python PE unpackers """

    def __init__(self, path):
        super().__init__(path)
        pe_data = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_READ)
        self.binary = pefile.PE(data=pe_data)

    def parse_pyver(self) -> str:
        """ Parse .rsrc and detect PYTHON*.dll dependency, and parse out version """

        # check if resource entries exist
        pyver = None
        if not hasattr(self.binary, "DIRECTORY_ENTRY_RESOURCE"):
            return pyver

        # enumerate and check for the PYTHON*.dll
        for rsrc_type in self.binary.DIRECTORY_ENTRY_RESOURCE.entries:
            if rsrc_type.name is not None:
                data = rsrc_type.name.string
                if data[0:6] == b"PYTHON" and data[8:] == b".DLL":
                    pyver = data[6] - 0x30 + (data[7] - 0x30) / 10.0
                    break

        return pyver


class LinuxUnpacker(BaseUnpacker):
    """ Base class used for all Python ELF unpackers """

    def __init__(self, path):
        super().__init__(path)



def get_packer(filepath: str) -> t.Optional[t.Any]:
    """
    Helper utility to help return the correct Unpacker based on the YARA rule that matches it.
    If `detect_only` is set, return only the 
    """
    from . import pyinstaller, py2exe

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
