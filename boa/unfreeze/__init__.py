"""
__init__.py

    Defines a base class used by all unfreezers in order to keep consistent
    across the API definitions, and implements a helper function to parse out the type
    of installer using Yara.
"""
import os
import abc
import traceback
import typing as t

import yara


class UnfreezeException(Exception):
    pass


class Unfreeze(abc.ABC):
    """ Abstract base class used for all variants of Python uninstaller implementations. """

    def __init__(self, path: str):
        self.path: str = path

        # get file pointer and size for later reading and seeking
        self.file: t.Any = open(path, "rb")
        self.size: int = os.stat(path).st_size

        # Installer-specific version
        self.version: t.Optional[float] = None

        # stores paths to all unpacked bytecode files
        self.bytecode_paths: t.List[str] = []

        super().__init__()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        """ Destructor - handle exceptions and close file """
        if exc_type is not None:
            traceback.print_exception(exc_type, exc_value, tb)
        self.file.close()

    @abc.abstractmethod
    def __str__(self) -> str:
        """ Output for identifying installer used """
        pass

    @abc.abstractmethod
    def parse_version(self) -> t.Optional[float]:
        """ Used to parse out and set installer version """
        pass

    @abc.abstractmethod
    def thaw(self, unpack_dir: str) -> t.List[str]:
        """ Implements the actual process of unpacking resources """
        pass


def get_installer(filepath: str) -> t.Optional[Unfreeze]:
    from . import pyinstaller, py2exe

    # get path to rule relative to package
    pkg_dir: str = os.path.dirname(os.path.abspath(__file__))
    rulepath: str = os.path.join(pkg_dir, "installer.yara")

    rules = yara.compile(filepath=rulepath)
    matches = rules.match(filepath=filepath)

    # if multiple are present, return None
    if len(matches) > 1 or len(matches) == 0:
        return None

    res: str = matches[0].rule
    installer: t.Optional[Unfreeze] = None
    if res == "pyinstaller":
        installer = pyinstaller.PyInstaller(filepath)
    elif res == "py2exe":
        installer = py2exe.Py2Exe(filepath)
    elif res == "cxfreeze":
        installer = cxfreeze.CxFreeze(filepath)

    return installer
