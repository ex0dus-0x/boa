"""
__init__.py

    Defines a base class used by all unpackers in order to keep consistent
    across the API definitions, and implements a helper function to parse out the
    unpacker using Yara.
"""
import os
import mmap
import typing as t
import traceback

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

    def detect(self):
        """
        Runs routine to fingerprint Python-specific metadata about the target.
        Derived objects should implement any other metadata, ie archive type for PyInstaller,
        or number of packed files.
        """

        self.pyver = self.parse_pyver()
        if self.pyver is None:
            raise UnpackException("Cannot parse out Python version from executable.")

        self.packer_ver = self.parse_packer_ver()
        if self.packer_ver is None:
            raise UnpackException("Cannot parse out packer version from executable.")


    def unpack(self, unpack_dir: str):
        """ Implements the actual process of unpacking resources """
        raise NotImplementedError()


class WindowsUnpacker(BaseUnpacker):
    """ Base class used for all Python PE unpackers """

    def __init__(self, path):
        super().__init__(path)
        pe_data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        self.binary = pefile.PE(data=pe_data)

    def parse_pyver(self) -> t.Optional[float]:
        """ 
        Python*.dll is typically dynamically loaded, so check .data for instances of the string.
        """
        pyver: t.Optional[float] = None
        data: bytes = b""
        for section in self.binary.sections:
            name = section.Name.decode("utf-8").rstrip("\x00")
            if name == ".data":
                data = section.get_data()

        # search python*.dll pattern and parse out version
        search = b"python37.dll"
        if search in data:
            pyver = 3.7
        return 3.7


class LinuxUnpacker(BaseUnpacker):
    """ Base class used for all Python ELF unpackers """

    def __init__(self, path):
        super().__init__(path)



def get_packer(filepath: str) -> t.Optional[t.Any]:
    """
    Helper utility to help return the correct Unpacker based on the YARA rule that matches it.
    """
    from . import pyinstaller, py2exe

    rules = yara.compile(filepath="ext/unpacker.yara")
    matches = rules.match(filepath=filepath)

    # if multiple are present, return None
    if len(matches) > 1:
        return None

    # parse response from rule, return now, if `detect_only` is set
    res: str = matches[0].rule

    # determine which packer was used
    packer: t.Optional[t.Any] = None
    if res == "pyinstaller":
        packer = pyinstaller.PyInstaller(filepath)
    elif res == "py2exe":
        packer = py2exe.Py2exe(filepath)
    elif res == "cx_freeze":
        raise NotImplementedError()

    return packer
