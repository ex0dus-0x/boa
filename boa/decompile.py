"""
decompiler.py

    Aggregates a single decompilation interface over several decompilers, since many have varying bugs
    in different versions and implementations.

"""
import os
import sys
import ntpath
import pkgutil

import requests
import uncompyle6
import decompyle3


class BoaDecompiler(object):
    """
    Defines the decompiler interface used that aggregates different decompiler
    modules for source recovery when given bytecode. Implements rudimentary
    bytecode patching if decompilers are unable to parse the input further.
    """
    def __init__(self, workspace, pyver, decomp_all=False):
        self.workspace = workspace

        # used to identify the first decompiler to be used
        #   Python 3.0 - 3.8: decompyle3
        #   Python 2.7.x: py2
        self.pyver = pyver

        # if set, all bytecode files will be indiscriminantly decompiled
        self.decomp_all = decomp_all

        # stores a list of paths
        self.paths = set()

        # stores a list of external deps that are present in the executable
        self.deps = set()


    def _check_if_decompile(self, name) -> bool:
        """
        To save time and space, ignore decompiling known dependencies and add them to a set.
        May produce false positives, but hope is to reduce overtime decompiling unnecessary
        dependencies that are open-sourced.
        """

        # cleanup dep path: parse out filename, and strip extension
        dep = os.path.splitext(ntpath.basename(name))[0]

        # check if dependency exists as a built-in module
        if any([val in dep for val in list(sys.builtin_module_names)]):
            return False

        # check if dependency exists as a standard library module
        stdlib = [
            mod for _, mod, pkg in list(pkgutil.iter_modules())
            if pkg is False
        ]
        if any([val in dep for val in stdlib]):
            return False

        # if dependency has multiple submodules, chances are it is an existing PyPI package
        # parse out module name, and check to see if version exists upstream, and ignore if so
        if "." in dep:
            modname = dep.split(".")[0]

            # don't repeat again if already parsed once
            if not modname in self.deps:
                resp = requests.get("https://pypi.org/pypi/{}/json".format(modname))

                # if found, add to set and return
                if resp.status_code == 200:
                    self.deps.update(modname)
                    return False
            else:
                return False

        # last check: remove any other modules already parsed
        if any([val in dep for val in list(self.deps)]):
            return False

        # there may be smaller deps that end up as false positives, since we can't make a distinction
        # between those and the original source code of the application
        return True


    def decompile_file(self, path):
        """
        Given a list of paths to a .pyc bytecode file, check if decompilation is necessary, ...
        """
        if not self._check_if_decompile(path):
            return None

        return path
