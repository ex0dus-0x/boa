import os
import abc
import typing as t

import yara


class UnpackException(Exception):
    pass


class BaseUnpacker(abc.ABC):
    """ Abstract base class used for supported unpackers """

    def __init__(self, path: str):
        self.path: str = path

    def __enter__(self):
        pass


def get_packer(filepath: str) -> t.Optional[BaseUnpacker]:
    from . import upx

    # get path to rule relative to package
    pkg_dir: str = os.path.dirname(os.path.abspath(__file__))
    rulepath: str = os.path.join(pkg_dir, "packer.yara")

    rules = yara.compile(filepath=rulepath)
    matches = rules.match(filepath=filepath)

    # if multiple are present, return None
    if len(matches) > 1 or len(matches) == 0:
        return None

    res: str = matches[0].rule
    installer: t.Optional[BaseUnpacker] = None
    if res == "upx":
        unpacker = upx.UpxUnpack(filepath)

    return installer
