#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import sys
import json
import logging
import typing as t

import coloredlogs

import boa.argparse as argparse
from boa.worker import BoaWorker
from boa.decompile import BoaDecompiler

logger = logging.getLogger(__name__)
coloredlogs.install(level="INFO")


@argparse.subcommand(
    [
        argparse.argument(
            "executable",
            help="Path to Python-compiled executable to gather information.",
        ),
        argparse.argument("-j", "--json", help="Output detection results in JSON."),
    ]
)
def detect(args):
    """ Run initial info-gathering and reconassiance on the given executable """
    app: str = args.executable
    if not os.path.exists(app):
        logger.error("Cannot find path to executable.")
        return 1

    with open(app, "rb") as fd:
        binary = fd.read()

    # get information and print tabulated or as json
    data = runner.run_detect(binary)
    if not args.json:
        for key, value in data.items():
            print(f"{key}\t\t\t:\t\t\t{value}")
    else:
        print(json.dump(data))

    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "BYTECODE",
            nargs="+",
            help="Path to bytecode file(s) or raw dumped code object(s) for decompilation.",
        ),
        argparse.argument(
            "-p",
            "--pyver",
            type=float,
            help="Specify the major and minor version (x.y) of Python to decompile as. If not set, boa will figure it out.",
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            type=str,
            default="decompiled",
            help="Workspace where decompiled source files are all stored (default is `decompiled`).",
        ),
    ]
)
def decompile(args):
    """
    Given bytecode files decompile them back into original Python source code using uncompyle6 or decompyle3.
    If given dumped code objects, boa will bruteforce out an appropriate bytecode header before decompilation.
    """

    logger.info("Starting boa for bytecode decompilation.")

    pyver: float = args.pyver
    if not pyver:
        logger.warn("No Python version specifed to decompile against. Setting as 3.7")
        pyver = 3.7

    outdir: str = args.out_dir
    decomp = BoaDecompiler(outdir, pyver)

    # iterate over each bytecode file and decompile
    bfiles: t.List[str] = args.BYTECODE
    logger.debug(f"Found {len(bfiles)} files for decompilation.")
    for bfile in bfiles:
        if not os.path.exists(bfile):
            logger.error(f"`{bfile}` does not exist")
            return 1

        logger.info(f"Decompiling {bfile}...")
        decomp.decompile(bfile)

    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to Python-compiled executable to reverse engineer."
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            help="Path to store fully reversed artifacts in (default is `{executable}_out`).",
        ),
    ]
)
def reverse(args):
    """
    Given a Python-compiled executable, will attempt to fully reverse engineering and
    extrapolate source code. If Boa can accurately detect the packing routine, it will statically
    recover the bytecode. Otherwise, the binary will be instrumented to dump bytecode dynamically.
    """

    logger.info("Starting boa for reverse engineering")

    app = args.executable
    if not os.path.exists(app):
        logger.error("Cannot find path to executable.")
        return 1

    # output path or set default
    base: str = os.path.basename(app)
    out_dir: str = f"{base}_out" if not args.out_dir else args.out_dir
    logger.debug(f"{out_dir} for generated resources")
    if not os.path.exists(out_dir):
        logger.info("Creating output workspace for storing unpacked resources...")
        os.mkdir(out_dir)

    # instantiate a cli worker to interface with when performing RE
    worker = BoaWorker(app, out_dir, cli=True)

    logger.info("Detecting and unpacking the executable...")
    worker.run_unpack()

    logger.info("Decompiling unpacked bytecode...")
    worker.run_decompile()

    logger.info("Running static analysis on the source code...")


def main():
    argparse.parse_args()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
