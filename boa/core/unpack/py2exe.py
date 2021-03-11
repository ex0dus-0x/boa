"""
py2exe.py

    Unpacker implementation for py2exe installers.
"""
from . import WindowsUnpacker

class Py2Exe(WindowsUnpacker):
    def __str__(self) -> str:
        return "Py2EXE"
               
    def unpack(self, unpack_dir: str):
        pass
