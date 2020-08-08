"""
decompiler.py

    Provides an interface object for decompilation, consuming a codebase of bytecode paths
    and recovering the source from only the ones that are relevant to the program execution.

    TODO: Aggregates fallback decompiler APIs besides `uncompyle6` in order to fix potential bugs that
    may arise from the decompiler.

"""
import os
import sys
import json
import ntpath
import shutil
import pkgutil
import subprocess

import requests
import stdlib_list
import uncompyle6
#import decompyle3

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

    TODO: check and deal with files that are encrypted
    """
    def __init__(self, pyver, paths, decomp_all=False):

        # instantiate list of all standard library modules
        # TODO: convert pyver to str for stdlib_list
        self.stdlib = stdlib_list.stdlib_list("3.8")

        # instantiate a local dataset of top PyPI packages
        self.packages = BoaDecompiler.iter_packages()

        # Main decompiler used: uncompyle6
        # However, in case uncompyle6 fails decompilation, we fallback:
        #   Python 3.x: decompyle3
        #   Python 2.7.x: uncompyle2
        self.fallback_decompiler = "uncompyle2" if 20 <= int(pyver) < 30 else "decompyle3"

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
        Helper function to obtain a dataset of top PyPI packages to check dependencies against. If present and known,
        we should NOT decompile it to save time.
        """
        with open(os.path.join("ext", "package-dataset.json"), "r") as fd:
            contents = fd.read()

        # convert to dictionary and get all package names
        pkgs_dict = dict(json.loads(contents))
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


    def decompile_all(self, workspace, no_fallback=False):
        """
        Given all the stored paths of relevant bytecode files, decompile all of them into the workspace directory.

        TODO: If a decompiler fails for some reason, swap over to the fallback one.
        """

        # create a flattened list of all relevant files to decompile
        unpack_dir = os.path.join(workspace, "unpacked")
        decomp_files = sorted({os.path.join(unpack_dir, x) for v in self.dep_mapping.values() for x in v})

        # set directories to read and write to after decompilation
        input_dir = os.path.join(unpack_dir, os.path.commonprefix(decomp_files))
        output_dir = os.path.join(workspace, "recovered")

        # run decompilation on all files given with appropriate paths in place
        try:
            uncompyle6.main.main(input_dir, output_dir, decomp_files, [])

        # TODO: at an exception, unless configured, call the fallback decompiler
        except Exception as e:
            raise e

        # FIXME: uncompyle6 is not writing to output_dir. Manually do it for now until we figure out why
        for filename in os.listdir(input_dir):
            if filename.endswith(".py"):
                inpath = os.path.join(input_dir, filename)
                outpath = os.path.join(output_dir, filename)
                shutil.copyfile(inpath, outpath)

        return len(decomp_files)
