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
import decompyle3  # TODO: integrate

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


def _pack_uint32(val):
    """ Integer to 32-bit little-end bytes """
    return struct.pack("<I", val)


def _generate_magic(version) -> bytes:
    return struct.pack(b"Hcc", version, b"\r", b"\n")


class DecompileException(Exception):
    pass


class BoaDecompiler:
    """
    A wrapper over known Python decompilers with support for bytecode patching,
    which will bruteforce out a header for the raw code object to makes it viable for decompilation.
    """

    def __init__(self, outdir: str, pyver: float):
        self.pyver: float = pyver
        self.magic: t.List[int] = MAGIC_NUMBERS[self.pyver]

        # set callback to decompiler based on version
        if self.pyver >= 3.7:
            self.decompiler = decompyle3.main.decompile_file
        else:
            self.decompiler = uncompyle6.main.decompile_file

        # create output workspace
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
                self.decompiler(path, decompiled)
        except ValueError:
            with open(path, "rb") as fd:
                code = fd.read()

            # given the version, bruteforce out an appropriate header
            for magic in self.magic:
                bytecode = self._object_patch(code, magic)

                # most likely doesn't end in pyc, so write to disk as one
                pycpath: str = path + ".pyc"
                with open(pycpath, "wb") as fd:
                    fd.write(bytecode)

                # now try this again, break if successful
                try:
                    with open(targetpath, "w") as decompiled:
                        self.decompiler(pycpath, decompiled)
                    break
                except ValueError:
                    continue

    def _object_patch(self, data: bytes, magic: int) -> bytearray:
        """ Attempt to generate a patched bytecode with a given magic number permutations """

        # start with magic num
        bytecode = bytearray(_generate_magic(magic))

        # second word introduced after 3.7 represents bitfield to denote hashing
        if self.pyver >= 3.7:
            bytecode.extend(_pack_uint32(0))

        # third component is timestamp, can be neglible
        bytecode.extend(_pack_uint32(0))

        # source size word is added after 3.2
        if self.pyver >= 3.2:
            bytecode.extend(_pack_uint32(0))

        # append rest of code objects to form full bytecode
        bytecode.extend(data)
        return bytecode
