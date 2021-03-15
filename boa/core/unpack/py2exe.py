"""
py2exe.py

    Unpacker implementation for py2exe installers. Implements the simple unpacking algorithm
    used similarly in `unpy2exe` and `decompile-py2exe` that parses out the PYTHONSCRIPT
    resource entry and enumerates over all entries with bytecode entries.

"""
import typing as t

from . import WindowsUnpacker, UnpackException


class Py2Exe(WindowsUnpacker):
    def __str__(self) -> str:
        return "Py2Exe"

    def parse_packer_ver(self) -> t.Optional[str]:
        """ TODO: detect Py2Exe  """
        return 0.10

    def unpack(self, unpack_dir: str):
        """
        As per with other unpacker implementations, compressed bytecode all exists
        within the PYTHONSCRIPT resource in the `.rsrc` header.
        """
        super().unpack(unpack_dir)

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
        rva = script_entry.data.struct.OffsetToData
        size = res.data.struct.Size
        dump = pe.get_data(rva, size)

        # TODO
