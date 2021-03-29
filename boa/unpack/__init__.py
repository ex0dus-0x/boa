import abc
import typing as t

import yara


class UnpackException(Exception):
    pass


class BaseUnpacker(abc.ABC):
    """ Abstract base class used for supported unpackers """

    def __init__(self, path: str):
        self.path: str = path


def get_unpacker(filepath: str) -> t.Optional[BaseUnpacker]:
    from . import upx

    rules = yara.compile(filepath="rules/unpacker.yara")
    matches = rules.match(filepath=filepath)

    # if multiple are present, return None
    if len(matches) > 1:
        return None

    res: str = matches[0].rule
    installer: t.Optional[BaseUnpacker] = None
    if res == "upx":
        unpacker = upx.UpxUnpack(filepath)

    return installer
