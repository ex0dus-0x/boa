"""
py2exe.py

    Unpacker implementation for py2exe installers. Implements the simple unpacking algorithm
    used similarly in `unpy2exe` and `decompile-py2exe` that parses out the PYTHONSCRIPT
    resource entry and enumerates over all code objects, reconstructing a bytecode files.

    Platforms Supported: Windows PEs Only

"""
import os
import re
import mmap
import marshal
import typing as t

import pefile

from . import BaseUnpacker, UnpackException


class Py2Exe(BaseUnpacker):
    def __init__(self, path: str):
        """ Initialize base, and also instantiate PE object for parsing """
        super().__init__(path)
        pedata = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        self.binary = pefile.PE(data=pedata)

    def __str__(self) -> str:
        return "Py2Exe"

    def parse_pyver(self) -> t.Optional[float]:
        """ Check for instances of Python*.dll in PE, since it is dynamically loaded """

        # more generic check - iterate over symbols in .data
        data: bytes = b""
        for section in self.binary.sections:
            name = section.Name.decode("utf-8").rstrip("\x00")
            if name == ".data":
                data = section.get_data()

        # search python*.dll pattern and parse out version
        expr: str = r"python(\d+)\.dll"
        matches = re.search(expr, str(data))
        if matches is None:
            raise UnpackException("Cannot find Python DLL to parse version.")

        # strip out name and file extension
        res: t.List[str] = list(matches.group(0).split("python")[1].strip(".dll"))
        res.insert(1, ".")

        # insert dot for floating point and type convert
        self.pyver = float("".join(res))
        return self.pyver

    def parse_packer_ver(self) -> t.Optional[str]:
        """ Doesn't seem to be deviations in unpacking based on installer version """
        return None

    def unpack(self, unpack_dir: str):
        """
        As per with other unpacker implementations, compressed bytecode all exists
        within the PYTHONSCRIPT resource in the `.rsrc` header.
        """

        # shouldn't happen, but error-check
        if not hasattr(self.binary, "DIRECTORY_ENTRY_RESOURCE"):
            raise UnpackException("Cannot find resources header in target PE.")

        # get PYTHONSCRIPT resource entry
        script_entry = None
        for entry in self.binary.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.name and entry.name.string == b"PYTHONSCRIPT":
                script_entry = entry.directory.entries[0].directory.entries[0]
                break

        # again, shouldn't happen, but error-check
        if script_entry is None:
            raise UnpackException(
                "Cannot find PYTHONSCRIPT resource entry in target PE."
            )

        # given offset for PYTHONSCRIPT entry, dump data
        rva: int = script_entry.data.struct.OffsetToData
        size: int = script_entry.data.struct.Size
        dump: bytes = self.binary.get_data(rva, size)

        # get offset where code objects are stored and unmarshal
        codebytes: bytes = dump[0x010:]

        try:
            code_objs: t.List[t.Any] = marshal.loads(codebytes)
        except ValueError:
            raise UnpackException("Unable to unmarshal Python code, possibly version incompatibility.")
        
        # for each code object entry, patch with Python version and timestamp,
        # and then write to output workspace
        for co in code_objs:

            # TODO: check if module is to be ignored
            filename = os.path.join(unpack_dir, co.co_filename + ".pyc")
            
            # generate header with version magic and timestamp, and write to disk
            header = self._generate_pyc_header()
            with open(filename, "wb") as fd:
                fd.write(header)
                fd.write(marshal.dumps(co))

        return None
