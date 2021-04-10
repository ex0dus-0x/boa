"""
py2exe.py

    Platforms Supported: Windows PEs Only
"""
import os
import zipfile
import typing as t

from . import Unfreeze, UnfreezeException


class Py2Exe(Unfreeze):
    def __str__(self) -> str:
        return "Py2Exe"

    def parse_version(self) -> t.Optional[str]:
        """ Doesn't seem to be deviations in unpacking based on installer version """
        return None

    def thaw(self, unpack_dir: str):
        """ Most relevant technique for unpacking: simply unzipping the executable """

        # shouldn't happen, but error-check
        if not zipfile.is_zipfile(self.path):
            raise UnfreezeException("Executable cannot be decompressed")

        # open as a zipfile
        zf = zipfile.ZipFile(self.file, mode="r")
        paths: t.List[str] = zf.namelist()

        # read each path from zipfile and write to disk
        for path in paths:

            # check if we want to ignore
            #if path in 

            with zf.open(path) as fd:
                contents = fd.read()

            # check if we need to recursively create dirs
            writepath = os.path.join(unpack_dir, path)
            subpath = os.path.dirname(writepath)
            if not os.path.exists(subpath):
                os.makedirs(subpath, exist_ok=True)

            with open(writepath, "wb") as fd:
                fd.write(contents)

        zf.close()
        return None
