"""
decompiler.py

    Provides an interface object for decompilation, consuming a codebase of bytecode paths
    and recovering the source from only the ones that are relevant to the program execution.

    TODO: Aggregates fallback decompiler APIs besides `uncompyle6` in order to fix
    potential bugs that may arise from the decompiler.

"""
import os
import sys
import json
import struct
import ntpath
import shutil
import platform

import stdlib_list

"""
try:
    import uncompyle6
except KeyError:
    print("uncompyle6 is internally outdated, doesn't support your Python version!")
"""

#     Python 1.5:   20121
#     Python 1.6:   50428
#     Python 2.0:   50823
#     Python 2.1:   60202
#     Python 2.2:   60717
#     Python 2.3:   62011
#     Python 2.4:   62041
#     Python 2.5a0: 62071
#     Python 2.5a0: 62081
#     Python 2.5a0: 62091
#     Python 2.5a0: 62092
#     Python 2.5b3: 62101
#     Python 2.5b3: 62111
#     Python 2.5c1: 62121
#     Python 2.5c2: 62131
#     Python 2.6a0: 62151
#     Python 2.6a1: 62161
#     Python 2.7a0: 62171
#     Python 2.7a0: 62181
#     Python 2.7a0  62191
#     Python 2.7a0  62201
#     Python 2.7a0  62211
#     Python 3.0a4: 3111
#     Python 3.0b1: 3131
#     Python 3.1a1: 3141
#     Python 3.1a1: 3151
#     Python 3.2a1: 3160
#     Python 3.2a2: 3170
#     Python 3.2a3  3180
#     Python 3.3a1  3190
#     Python 3.3a1  3200
#     Python 3.3a1  3210
#     Python 3.3a2  3220
#     Python 3.3a4  3230
#     Python 3.4a1  3250
#     Python 3.4a1  3260
#     Python 3.4a1  3270
#     Python 3.4a1  3280
#     Python 3.4a4  3290
#     Python 3.4a4  3300
#     Python 3.4rc2 3310
#     Python 3.5a1  3320
#     Python 3.5b1  3330
#     Python 3.5b2  3340
#     Python 3.5b3  3350
#     Python 3.5.2  3351
#     Python 3.6a0  3360
#     Python 3.6a1  3361
#     Python 3.6a2  3370
#     Python 3.6a2  3371
#     Python 3.6a2  3372
#     Python 3.6b1  3373
#     Python 3.6b1  3375
#     Python 3.6b1  3376
#     Python 3.6b1  3377
#     Python 3.6b2  3378
#     Python 3.6rc1 3379
#     Python 3.7a1  3390
#     Python 3.7a2  3391
#     Python 3.7a4  3392
#     Python 3.7b1  3393
#     Python 3.7b5  3394
#     Python 3.8a1  3400
#     Python 3.8a1  3401
#     Python 3.8a1  3410
#     Python 3.8b2  3411
#     Python 3.8b2  3412
#     Python 3.8b4  3413
#     Python 3.9a0  3420
#     Python 3.9a0  3421
#     Python 3.9a0  3422
#     Python 3.9a2  3423
#     Python 3.9a2  3424
#     Python 3.9a2  3425

def magic(magic):
    return struct.pack(b"Hcc", magic, b"\r", b"\n")


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


class BoaDecompiler:
    """
    Defines the decompiler interface used that aggregates different decompiler
    modules for source recovery when given bytecode. Implements rudimentary
    bytecode patching if decompilers are unable to parse the input further.

    TODO: check and deal with files that are encrypted
    """

    def __init__(self, pyver, paths, decomp_all=False, use_interp_ver=False):
        
        # set the version used to enumerate with
        if use_interp_ver:
            stdver = ".".join(platform.python_version().split(".")[2:])
        else:
            stdver = ".".join(list(pyver))

        # instantiate list of all standard library modules
        self.stdlib = stdlib_list.stdlib_list(stdver)

        # instantiate a local dataset of top PyPI packages
        self.packages = BoaDecompiler.iter_packages()

        # TODO: dynamically import decompilers, exit if current Python versions don't work
        # Main decompiler used: uncompyle6
        self.decompiler = "uncompyle6"

        # However, in case uncompyle6 fails decompilation, we fallback:
        #   Python 3.x: decompyle3
        #   Python 2.7.x: uncompyle2
        self.fallback_decompiler = (
            "uncompyle2" if 20 <= int(pyver) < 30 else "decompyle3"
        )

        # used to cache deps already tested to ignore
        self.cached_ignore_deps = set()

        # stores a set of all external and internal dependencies
        self.total_deps = set(ntpath.basename(path).split(".")[0] for path in paths)

        # create a mapping with all deps as keys with vals as empty list storing paths
        self.dep_mapping = {dep: list() for dep in self.total_deps}

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
        Helper function to obtain a dataset of top PyPI packages to check dependencies against.
        If present and known, we should NOT decompile it to save time.
        """
        with open(os.path.join("ext", "package-dataset.json"), "r") as dataset:
            contents = dataset.read()

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

        # there may be smaller deps that end up as false positives, since we can't make
        # a distinction between those and the original source code of the application
        return True

    def decompile_all(self, workspace: str):
        """
        Given all the stored paths of relevant bytecode files, decompile all of them into the
        workspace directory.

        TODO: If a decompiler fails for some reason, swap over to the fallback one.
        """

        # create a flattened list of all relevant files to decompile
        unpack_dir = os.path.join(workspace, "unpacked")
        decomp_files = sorted(
            {os.path.join(unpack_dir, x) for v in self.dep_mapping.values() for x in v}
        )

        # set directories to read and write to after decompilation
        input_dir = os.path.join(unpack_dir, os.path.commonprefix(decomp_files))
        output_dir = os.path.join(workspace, "recovered")

        # run decompilation on all files given with appropriate paths in place
        try:
            uncompyle6.main.main(input_dir, output_dir, decomp_files, [])

        # TODO: at an exception, unless configured, call the fallback decompiler
        except Exception as err:
            raise err

        # FIXME: uncompyle6 is not writing to output_dir. Manually do it for now
        recovered = []
        for filename in os.listdir(input_dir):
            if filename.endswith(".py"):
                inpath = os.path.join(input_dir, filename)
                outpath = os.path.join(output_dir, filename)
                shutil.copyfile(inpath, outpath)
                recovered += [os.path.join(workspace, "recovered", filename)]

        return recovered
