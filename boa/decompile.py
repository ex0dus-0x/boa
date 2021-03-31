"""
decompiler.py

    Provides an interface object for decompilation, consuming a codebase of bytecode paths
    and recovering the source from only the ones that are relevant to the program execution.
"""
import os
import struct
import marshal
import typing as t

import uncompyle6

# Contains magic number for each Python version, which we'll use for a bytecode header
MAGIC_NUMBERS: t.Dict[float, t.List[int]] = {
    1.5: [20121],
    1.6: [50428],
    2.0: [50823],
    2.1: [60202],
    2.2: [60717],
    2.3: [62011],
    2.4: [62041],
    2.5: [62071, 62081, 62091, 62092, 62101, 62111, 62121, 62131],
    2.6: [62151, 62161],
    2.7: [62171, 62181, 62191, 62201, 62211],
    3.0: [3111, 3131],
    3.1: [3141, 3151],
    3.2: [3160, 3170],
    3.2: [3180],
    3.3: [3190, 3200, 3210, 3220, 3230],
    3.4: [3250, 3260, 3270, 3280, 3290, 3300, 3310],
    3.5: [3320, 3330, 3340, 3350, 3351],
    3.6: [3360, 3361, 3370, 3371, 3372, 3373, 3375, 3376, 3377, 3378, 3379],
    3.7: [3390, 3391, 3392, 3393, 3394],
    3.8: [3400, 3401, 3410, 3411, 3412, 3413],
    3.9: [3420, 3421, 3422, 3423, 3424, 3425],
}


class DecompileException(Exception):
    pass


class BoaDecompiler:
    def __init__(self, outdir: str, pyver: float = 3.7):
        self.pyver = pyver

        if not os.path.exists(outdir):
            os.mkdir(outdir)
        self.workspace: str = outdir

    def decompile(self, path: str):
        """
        Given a single path, run uncompyle6 to recover source. Handle bytecode patching
        if necessary to ensure proper header is appended to raw code objects.
        """

        basename: str = os.path.basename(path).strip(".pyc")
        targetpath: str = os.path.join(self.workspace, basename + ".py")
        try:
            with open(targetpath, "w") as decompiled:
                uncompyle6.main.decompile_file(path, decompiled)
        except ValueError:
            with open(path, "rb") as fd:
                data = marshal.load(fd)
                bytecode = BoaDecompiler._object_patch(data)

            # most likely doesn't end in pyc, so write to disk as one
            pycpath: str = path + ".pyc"
            with open(pycpath, "wb") as fd:
                fd.write(bytecode)

            # now try this again
            with open(targetpath, "w") as decompiled:
                uncompyle6.main.decompile_file(pycpath, decompiled)

    def _object_patch(self, data: bytes) -> bytes:
        """
        Serializes a dumped code object into a proper bytecode by prepending appropriate headers.
        """

        # start by getting current magic number
        from importlib.util import MAGIC_NUMBER

        header = bytearray(MAGIC_NUMBER)

        # second word introduced after 3.7 represents bitfield to denote hashing
        if self.pyver >= 3.7:
            header.extend(_pack_uint32(0))

        # third component is timestamp, can be neglible
        header.extend(_pack_uint32(0))

        # source size word is added after 3.2
        if self.pyver >= 3.2:
            header.extend(_pack_uint32(0))

        # append rest of code objects to form full bytecode
        header.extend(marshal.dumps(data))
        return header

    # TODO: bruteforce header

    @staticmethod
    def _pack_uint32(val):
        """ Integer to 32-bit little-end bytes """
        return struct.pack("<I", val)

    @staticmethod
    def _generate_magic(version) -> bytes:
        return struct.pack(b"Hcc", MAGIC_NUMBERS[version], b"\r", b"\n")
