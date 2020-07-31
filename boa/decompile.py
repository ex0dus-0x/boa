"""
decompiler.py

    Aggregates a single decompilation interface over several decompilers, since many have varying bugs
    in different versions and implementations.

"""
import os
import sys
import ntpath
import pkgutil
import subprocess

import requests
import stdlib_list
import uncompyle6
import decompyle3

# other modules that we don't care about
MOD_DONT_CARE = [
    "pkg_resources",

    # Windows-specific Python runtime libraries
    "commctr",
    "netbios",
    "pythoncom",
    "pywin",
    "pywintypes",
    "win32com",
    "win32con",
    "win32evtlogutil",
    "win32traceutil",
    "winerror",
]


class BoaDecompiler(object):
    """
    Defines the decompiler interface used that aggregates different decompiler
    modules for source recovery when given bytecode. Implements rudimentary
    bytecode patching if decompilers are unable to parse the input further.
    """
    def __init__(self, workspace, pyver, paths, decomp_all=False):

        # reuse workspace for writing source
        self.workspace = workspace

        # instantiate list of all standard library modules
        self.stdlib = stdlib_list.stdlib_list("3.8")

        # instantiate a local dataset of top PyPI packages
        self.packages = BoaDecompiler.iter_packages()

        # Main decompiler used: uncompyle
        # However, in case uncompyle6 fails decompilation, we fallback:
        #   Python 3.x: decompyle3
        #   Python 2.7.x: py2
        self.pyver = pyver
        self.decompiler = "uncompyle6"

        # used to cache deps already tested to ignore
        self.cached_ignore_deps = set()

        # stores a set of all external and internal dependencies
        self.total_deps = set([
            ntpath.basename(path).split(".")[0]
            for path in paths
        ])

        # create a mapping with all deps as keys with vals as empty list storing paths
        self.dep_mapping = {
            dep: list()
            for dep in self.total_deps
        }

        # reiterate paths and populate self.dep_mapping
        for path in paths:
            base = ntpath.basename(path).split(".")[0]

            # check if dep is found as key
            if base in self.dep_mapping.keys():

                # check before decompiling
                if not decomp_all:

                    # check if appropriate to decompile, otherwise delete
                    if self._check_if_decompile(base):
                        self.dep_mapping[base] += [path]
                    else:
                        del self.dep_mapping[base]

                # otherwise add all indiscriminantly
                else:
                    self.dep_mapping[base] += [path]


    @staticmethod
    def iter_packages():
        """
        Helper function to Get dataset of top PyPI packages to check deps against
        """
        res = requests.get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-365-days.json")
        if res.status_code != 200:
            raise Exception("Cannot get packages")

        # convert to dictionary and get all package names
        pkgs_dict = dict(res.json())
        return [pkg["project"] for pkg in pkgs_dict["rows"]]



    def _check_if_decompile(self, dep) -> bool:
        """
        To save time and space, ignore decompiling known dependencies and add them to a set.
        May produce false positives, but hope is to reduce overhead decompiling unnecessary
        dependencies that are open-sourced.
        """

        # check if this is has been cached, and return quickly
        if dep in list(self.cached_ignore_deps):
            return False

        # check if dependency exists as a built-in module
        if dep in list(sys.builtin_module_names):
            self.cached_ignore_deps.update(dep)
            return False

        # check if dependency exists as a standard library module
        if dep in self.stdlib:
            self.cached_ignore_deps.update(dep)
            return False

        # check if package is popular on PyPI
        if dep in self.packages:
            self.cached_ignore_deps.update(dep)
            return False

        # check if module is something we don't care about"
        if dep in MOD_DONT_CARE:
            self.cached_ignore_deps.update(dep)
            return False

        # there may be smaller deps that end up as false positives, since we can't make a distinction
        # between those and the original source code of the application
        return True


    def decompile_all(self):
        """
        Given all the stored paths of relevant bytecode files, decompile all of them into the workspace directory.
        """
        for _, paths in self.dep_mapping.items():
            for path in paths:

                # get abspath to bytecode path and call decompiler
                decomp_path = os.path.join(self.workspace, "unpacked", path)
                proc = subprocess.Popen([self.decompiler, decomp_path], stdout=subprocess.PIPE)
                output = proc.stdout.read()

                # write result to path
                filename = ntpath.basename(path).replace("pyc", "py")
                store_path = os.path.join(self.workspace, "recovered", filename)
                with open(store_path, "wb") as fd:
                    fd.write(output)

        print("Done")
