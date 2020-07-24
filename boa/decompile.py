"""
decompiler.py

    Aggregates a single decompilation interface over several decompilers, since many have varying bugs
    in different versions and implementations.

"""

import uncompyle6
import decompyle3


class Decompiler(object):
    def __init__(self, pyver):
        self.pyver = pyver


    def _check_if_decompile(self, name):
        pass

    def decompile_file(self, path):
        pass
