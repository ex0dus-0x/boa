#!/usr/bin/env python3
"""
__main__.py

    Command line entry point for launching the standalone CLI executable.
"""
import os
import sys
import typing as t

import beautifultable

import boa.argparse as argparse
import boa.runner as runner
from boa.core.unpack import get_packer
from boa.core.decompile import BoaDecompiler


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to Python-compiled executable to reverse engineer."
        ),
        argparse.argument("-j", "--json", help="Output detection results in JSON."),
    ]
)
def detect(args):
    """ Given a target executable, gather metadata about a sample without fully reverse engineering it. """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # basic information
    print(f"Name: {app}")
    print(f"Executable Format: ELF")
    print(f"Time Created: 12")

    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to packed executable to unpack and dissect apart."
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            help="Path to store unpacked resources in (default is `{executable}_out`).",
        ),
    ]
)
def unpack(args):
    """ Given a packed target executable, do both generic executable unpacking (if detected) and Python-specific unpacking. """
    app: str = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # output path or set default
    out_dir: str = f"{app}_out" if not args.out_dir else args.out_dir
    if not os.path.exists(out_dir):
        print("Creating output workspace for storing unpacked resources...")
        os.mkdir(out_dir)

    # detect executable packing

    # instantiate unpacker
    with get_packer(app) as unpacker:
        if unpacker is None:
            print("Unable to detect the installer used to pack the executable.")
            return 1

        # fingerprint packer and Python version
        pyver: t.Optional[float] = unpacker.parse_pyver()
        if pyver is None:
            raise Exception()

        print(f"Compiled with Python version: {pyver}")
        print(f"Detected packer: {unpacker}", end=" ")

        packer_ver: t.Optional[float] = unpacker.parse_packer_ver()
        if not packer_ver is None:
            print(f"{packer_ver}")

        # given the output dir, run the unpacking routine
        unpacker.unpack(out_dir)

    print(f"Done unpacking in `{out_dir}`")
    return 0


@argparse.subcommand(
    [
        argparse.argument(
            "--bytecode_files",
            nargs="+",
            help="Path to bytecode file(s) for decompilation.",
        ),
        argparse.argument(
            "--bytecode_dir",
            help="Path to workspace with bytecode files for decompilation.",
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            type=str,
            default="out",
            help="Workspace where multiple decompiled source files are all stored (default is `out`).",
        ),
    ]
)
def decompile(args):
    """ Given bytecode files, patch and decompile them back into original Python source code. """

    bfiles = args.bytecode_files
    bdir = args.bytecode_dir

    # either specific files or a directory, not both
    if bfiles and bdir:
        print("Specify either `--bytecode_files` or `--bytecode_dir` but not both.")
        return 1

    # bytecode files that are parsed out
    bytecode: t.List[str] = []
    if bfiles:
        bytecode = [
            bfile
            for bfile in bfiles
            if os.path.exists(bfile) and bfile.endswith(".pyc")
        ]

    elif args.bytecode_dir:
        if not os.path.exists(bdir):
            print("Workspace with bytecode files does not exist.")
            return 1

        bytecode = [
            os.path.join(bdir, bfile)
            for bfile in os.listdir(bdir)
            if bfile.endswith(".pyc")
        ]

    # instantiate aggregate decompiler
    decomp = BoaDecomiler(bytecode)


@argparse.subcommand(
    [
        argparse.argument(
            "executable", help="Path to Python-compiled executable to reverse engineer."
        ),
        argparse.argument(
            "-o",
            "--out_dir",
            help="Path to store fully reversed Python application in (default is `{executable}_out`).",
        ),
    ]
)
def reverse(args):
    """ Subcommand to attempt to fully reverse engineering a target executable """
    app = args.executable
    if not os.path.exists(app):
        print("Cannot find path to executable. Exiting...")
        return 1

    # output path or set default
    out_dir = f"{app}_out" if not args.out_dir else args.out_dir
    if not os.path.exists(out_dir):
        print("Creating output workspace for storing unpacked resources...")
        os.mkdir(out_dir)

    # first, unpack the executable
    print("Detecting and unpacking the executable...")
    run_unpacking_routine(out_dir)

    # second, decompile source code
    print("Decompiling unpacked bytecode...")


def main():
    argparse.parse_args()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
