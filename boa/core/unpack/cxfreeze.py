"""
cxfreeze.py

    Unpacker for cxfreeze-compiled executable.
"""

from . import BaseUnpacker, UnpackException

class CxFreeze(BaseUnpacker):
    def __str__(self) -> str:
        return "CxFreeze"

    def parse_pyver(self) -> t.Optional[float]:
        pass

    def parse_packer_ver(self) -> t.Optional[str]:
        pass

    def unpack(self, unpack_dir: str):
        pass
