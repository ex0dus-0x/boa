"""
cxfreeze.py

    Unpacker for cxfreeze-compiled executable.
"""
import typing as t

from . import BaseUnfreezer, UnfreezeException


class CxFreeze(BaseUnfreezer):
    def __str__(self) -> str:
        return "CxFreeze"

    def parse_pyver(self) -> t.Optional[float]:
        pass

    def parse_version(self) -> t.Optional[str]:
        pass

    def thaw(self, unpack_dir: str):
        pass
