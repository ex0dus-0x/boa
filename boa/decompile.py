"""
decompiler.py

    Aggregates a single decompilation interface over several decompilers, since many have varying bugs
    in different versions and implementations.

"""

import requests
import uncompyle6
import decompyle3


class BoaDecompiler(object):
    def __init__(self, workspace, pyver, decomp_all=False):
        self.workspace = workspace
        self.pyver = pyver
        self.decomp_all = decomp_all

        # stores a list of external deps that are
        self.deps = set()


    def _check_if_decompile(self, name) -> bool:
        """
        To save time and space, ignore decompiling known dependencies and add them to a set.
        May produce false positives, but hope is to reduce overtime decompiling unnecessary
        dependencies that are open-sourced.
        """
        dep = name.strip(".pyc")

        # check if dependency exists as a built-in module

        # if multiple submodules, chances are the dep is widely used. Check to see if available
        # on PyPI, and skip if it is.
        if "." in dep:
            pass

        # for smaller deps that weren't originally in the codebase, return anyway
        return True


    def decompile_file(self, path):
        """
        Given a path to a .pyc bytecode file, check if decompilation is necessary, ...
        """
        pass
