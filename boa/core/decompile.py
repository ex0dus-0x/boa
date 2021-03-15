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
import ntpath
import shutil
import importlib
import typing as t

import stdlib_list


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

# other modules that we don't care about
MOD_DONT_CARE: t.List[str] = [
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


class DecompileException(Exception):
    pass


class BoaDecompiler:
    def __init__(self, pyver: float, paths, decomp_all=False):

        # get list of magic numbers
        if not pyver in MAGIC_NUMBERS:
            raise DecompileException("Python version not supported for decompilation")
        self.magic: t.List[int] = MAGIC_NUMBERS[pyver]

        # instantiate list of all standard library modules
        self.stdlib = stdlib_list.stdlib_list(pyver)

        # instantiate a local dataset of top PyPI packages to note waste time decompiling
        # open-sourced projects
        self.packages = BoaDecompiler.iter_packages()

        # dynamically import decompilers based on version
        # 3.7+: decompyle3
        # other versions: uncompyle6
        decomp: str = "decompyle3" if self.version >= 3.7 else "uncompyle6"
        try:
            self.decompiler: t.Any = importlib.import_module(decomp)
        except KeyError:
            raise DecompileEXception("Decompiler doesn't support Python version yet.")

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
