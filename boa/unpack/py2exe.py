"""
py2exe.py

    Unpacker implementation for py2exe installers. Builds an abstraction around the unpy2exe
    module in order to be uniform with the API implementation.
"""

import pefile
import unpy2exe


class Py2Exe(object):
    """
    Cheating with unpy2exe >:)
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.pyz_len = 0
        self.bytecode_paths = []

    def __str__(self):
        return "Py2exe"

    def unpack(self, unpacked_dir):
        """
        TODO: make everything baked in and remove dep
        """
        pe = pefile.PE(self.filepath)
        code_objects = unpy2exe.extract_code_objects(pe)
        for co in code_objects:
            unpy2exe.dump_to_pyc(co, None, unpacked_dir)
